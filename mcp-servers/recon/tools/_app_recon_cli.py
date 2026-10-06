#!/usr/bin/env python3
"""App reconnaissance worker — static attack-surface extraction from mobile and
desktop application packages.

This is the recon-phase analogue of ``_js_recon_cli.py``: where that worker
mines a web app's JavaScript, this one mines a *shipped application* — an
Android APK, an iOS IPA, an Electron desktop bundle (``.asar``), a Java
``.jar``, or a raw native binary — for the same high-value recon material:

  * endpoints / API paths (the backend the app talks to — frequently hosts and
    routes that DNS/subdomain enumeration never reveals)
  * hostnames of those backends (new recon seeds for the engagement)
  * hardcoded secrets (API keys, tokens, JWTs, private keys)
  * exposed cloud storage (S3 / GCS / Azure / DO buckets)
  * platform metadata that is itself attack surface: Android permissions and
    declared components, iOS URL schemes and App Transport Security posture,
    cleartext-traffic configuration, package / bundle identifiers.

Design (deliberately mirrors js_recon / domain_hunter):
  * **Standard-library only.** ``zipfile`` reads APK/IPA/JAR, ``plistlib`` reads
    iOS (binary and XML) plists, a tiny pure-Python reader handles Electron
    ``.asar``. Nothing here needs apktool/jadx/aapt to produce a result, so the
    tool is always available in the Kali container with zero extra deps — the
    exact robustness bar js_recon and domain_hunter hold.
  * **Best tool when present, never required.** If ``aapt``/``aapt2`` happens to
    be installed, Android package/version/permission facts are read from it
    (authoritative); otherwise they are recovered by string extraction from
    the binary manifest. Either way the run succeeds.
  * **Facts, not verdicts.** A hit is evidence that a pattern matched bytes in
    the package — never a claim that a secret is live or a permission is
    abused. The platform's confidence pipeline earns findings from these facts.

Input is either a local path already inside the container (``--app-path``, e.g.
an operator-provided or workspace file) or a URL to download first
(``--url``). Emits one JSON object on stdout for the platform parser.
"""

from __future__ import annotations

import argparse
import json
import os
import plistlib
import re
import ssl
import struct
import subprocess
import sys
import tempfile
import zipfile
from urllib.request import Request, urlopen

from _recon_extract import (
    dedupe_cloud,
    dedupe_secrets,
    extract_cloud,
    extract_endpoints,
    extract_secrets,
    extract_urls,
    host_of,
    is_interesting,
    sanitize_text,
)

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
# TLS verification stays ON: the whole point is to analyze the genuine package,
# and a MITM that can swap the download can feed a tampered one whose extracted
# "secrets"/endpoints are attacker-chosen. A download that fails verification is
# reported as a download failure, not silently trusted.
_CTX = ssl.create_default_context()

# Budgets — an app can be hundreds of MB; cap what we read so one call can't
# blow memory or the tool timeout. Mirrors js_recon's per-file byte cap.
_MAX_DOWNLOAD_BYTES = 400 * 1024 * 1024  # 400 MB app download ceiling
_MAX_ENTRY_BYTES = 8 * 1024 * 1024       # read at most 8 MB from any one file
_MAX_TOTAL_BYTES = 120 * 1024 * 1024     # stop mining after 120 MB scanned
_MAX_ENTRIES = 6000                      # and after this many package members

# Output bounds. The emitted JSON is parsed downstream and truncated by the
# platform at a fixed char budget — if it overflows, the truncated body is no
# longer valid JSON and every structured fact is lost. So cap the long lists
# and, as a hard backstop, trim the (lowest-value, most numerous) endpoint list
# until the serialized result fits well under that budget. Permissions, hosts,
# secrets and platform metadata are never dropped.
_MAX_EMIT_ENDPOINTS = 300
_MAX_EMIT_HOSTS = 300
_MAX_OUTPUT_CHARS = 14000

# Android permissions whose presence is worth surfacing on its own (the
# high-blast-radius subset). Still just "declared", never "abused".
_DANGEROUS_PERMS = {
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS", "RECEIVE_SMS",
    "READ_CALL_LOG", "WRITE_CALL_LOG", "PROCESS_OUTGOING_CALLS", "CALL_PHONE",
    "RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE", "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES", "QUERY_ALL_PACKAGES",
    "BIND_ACCESSIBILITY_SERVICE", "WRITE_SETTINGS", "GET_ACCOUNTS",
}

_HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_URL_HOST_RE = re.compile(r"^(?:[a-z][a-z0-9+.\-]*:)?//([^/:\s\"']+)", re.I)
_PERM_RE = re.compile(r"\b((?:[a-zA-Z][\w]*\.)+permission\.[A-Z0-9_]+)\b")
_SCHEME_RE = re.compile(r"\b([a-z][a-z0-9.+\-]{1,30})://", re.I)
_COMPONENT_RE = re.compile(r"\b((?:[a-z][a-z0-9_]*\.){2,}[A-Z][A-Za-z0-9_$]+)\b")

# Schemes that are not interesting as app deep links (standard transports).
_BORING_SCHEMES = {"http", "https", "file", "data", "content", "javascript",
                   "about", "blob", "ws", "wss", "ftp", "mailto", "tel"}


# ---------------------------------------------------------------------------
# Download / input
# ---------------------------------------------------------------------------
def _url_suffix(url: str) -> str:
    """Known app extension from a URL path, so the temp file keeps its type
    hint (mkstemp otherwise strips it and e.g. a .asar is misdetected as a raw
    binary). Only a short allow-list of real app extensions, never arbitrary."""
    from urllib.parse import urlparse
    name = os.path.basename(urlparse(url).path).lower()
    for ext in (".apk", ".aab", ".ipa", ".asar", ".jar", ".xapk", ".apks"):
        if name.endswith(ext):
            return ext
    return ""


def _download(url: str, timeout: int, notes: list[str]) -> tuple[str, str]:
    """Fetch an app to a temp file. Return (path, error). On success error is
    ''. Only http/https are allowed — file://, ftp://, data:, etc. are refused
    so a URL can never make the worker read an arbitrary local path (SSRF/LFR)."""
    from urllib.parse import urlparse
    scheme = urlparse(url).scheme.lower()
    if scheme not in ("http", "https"):
        return "", f"refusing non-http(s) url scheme {scheme!r}: only http/https are allowed"
    try:
        req = Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
        fd, path = tempfile.mkstemp(prefix="osprey_app_", suffix=_url_suffix(url))
        total = 0
        with urlopen(req, timeout=timeout, context=_CTX) as resp, os.fdopen(fd, "wb") as out:
            while True:
                chunk = resp.read(1024 * 256)
                if not chunk:
                    break
                total += len(chunk)
                if total > _MAX_DOWNLOAD_BYTES:
                    notes.append(f"download truncated at {_MAX_DOWNLOAD_BYTES} bytes")
                    break
                out.write(chunk)
        if total == 0:
            try:
                os.unlink(path)
            except OSError:
                pass
            return "", "download produced no data (empty response)"
        return path, ""
    except Exception as exc:  # noqa: BLE001
        return "", f"download failed: {type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# String extraction (ascii/utf-8 + utf-16le) — the robust fallback for any
# binary member: Android AXML manifests, .dex, resources.arsc, Mach-O/ELF/PE.
# ---------------------------------------------------------------------------
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _strings(data: bytes) -> str:
    """Return printable ascii + utf-16le runs joined by newlines."""
    parts: list[str] = [m.group().decode("ascii", "replace") for m in _ASCII_RUN.finditer(data)]
    parts += [m.group().decode("utf-16-le", "replace") for m in _UTF16_RUN.finditer(data)]
    return "\n".join(parts)


def _looks_binary(data: bytes) -> bool:
    """Decide text vs binary by CONTENT, not file extension. Compiled Android
    resources (AXML, resources.arsc) and .dex carry a .xml/.arsc name or none
    yet are binary; decoding them as utf-8 turns their string pools into
    control-char/replacement-char soup that inflates output with junk. A NUL
    byte or a high control-char ratio in the head is the reliable tell; UTF-8
    high bytes (accented/CJK real text) are deliberately not counted."""
    sample = data[:8192]
    if not sample:
        return False
    if b"\x00" in sample:
        return True
    ctrl = sum(1 for b in sample if b < 0x09 or 0x0e <= b < 0x20)
    return ctrl / len(sample) > 0.05


# ---------------------------------------------------------------------------
# Electron .asar reader (pure-Python; format = u32le header-size, then a pickled
# JSON directory, then concatenated file bodies).
# ---------------------------------------------------------------------------
def _asar_entries(path: str):
    """Yield (name, bytes) for files inside an asar archive. Best-effort."""
    with open(path, "rb") as fh:
        # Pickle framing: 4 bytes alignment size, 4 bytes header-obj size,
        # 4 bytes string size, 4 bytes json-length, then the JSON header.
        head = fh.read(16)
        if len(head) < 16:
            return
        json_len = struct.unpack("<I", head[12:16])[0]
        header_json = fh.read(json_len).split(b"\x00", 1)[0]
        base = 16 + json_len
        # Align base to the 4-byte boundary the asar writer padded to.
        pad = (4 - (base % 4)) % 4
        base += pad
        try:
            tree = json.loads(header_json.decode("utf-8", "replace"))
        except ValueError:
            return

        def walk(node, prefix):
            for name, meta in (node.get("files") or {}).items():
                full = f"{prefix}/{name}" if prefix else name
                if isinstance(meta, dict) and "files" in meta:
                    yield from walk(meta, full)
                elif isinstance(meta, dict) and "offset" in meta and "size" in meta:
                    try:
                        off = int(meta["offset"])
                        size = int(meta["size"])
                    except (TypeError, ValueError):
                        continue
                    if size <= 0 or size > _MAX_ENTRY_BYTES:
                        size = min(max(size, 0), _MAX_ENTRY_BYTES)
                    fh.seek(base + off)
                    yield full, fh.read(size)

        yield from walk(tree, "")


# ---------------------------------------------------------------------------
# Mining core — shared by every app type.
# ---------------------------------------------------------------------------
class _Miner:
    def __init__(self) -> None:
        self.endpoints: set[str] = set()
        self.secrets: list[dict] = []
        self.cloud: list[dict] = []
        self.hosts: set[str] = set()
        self.schemes: set[str] = set()
        self.files_analyzed = 0
        self._budget = _MAX_TOTAL_BYTES

    def feed(self, source: str, text: str) -> None:
        if not text or self._budget <= 0:
            return
        # Neutralize any binary framing before extraction so a token can never
        # span garbage (defense-in-depth; the extractors also reject junk).
        text = sanitize_text(text)
        if len(text) > self._budget:
            text = text[: self._budget]
        self._budget -= len(text)
        self.files_analyzed += 1
        for ep in extract_endpoints(text):
            self.endpoints.add(ep)
            host = _host_of_endpoint(ep)
            if host:
                self.hosts.add(host)
        # Bare (unquoted) absolute URLs — common in native binaries and config.
        for url in extract_urls(text):
            self.endpoints.add(url)
            host = host_of(url)
            if host:
                self.hosts.add(host)
        self.secrets.extend(extract_secrets(text, source))
        self.cloud.extend(extract_cloud(text, source))
        for m in _SCHEME_RE.finditer(text):
            s = m.group(1).lower()
            if s not in _BORING_SCHEMES:
                self.schemes.add(s)

    def feed_bytes(self, source: str, data: bytes) -> None:
        self.feed(source, _strings(data))

    def feed_auto(self, source: str, data: bytes) -> None:
        """Route by CONTENT: binary members (compiled resources, .dex, native
        code) go through string extraction; genuine text is decoded whole."""
        if _looks_binary(data):
            self.feed_bytes(source, data)
        else:
            self.feed(source, data.decode("utf-8", "replace"))


def _host_of_endpoint(ep: str) -> str:
    m = _URL_HOST_RE.match(ep)
    if not m:
        return ""
    host = m.group(1).split("@")[-1].split(":")[0].strip().lower()
    return host if _HOST_RE.match(host) else ""


def _read_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with zf.open(info) as fh:
        return fh.read(_MAX_ENTRY_BYTES)


def _mine_zip(zf: zipfile.ZipFile, miner: _Miner, skip: set[str] | None = None) -> None:
    skip = skip or set()
    count = 0
    for info in zf.infolist():
        if info.is_dir() or info.filename in skip:
            continue
        count += 1
        if count > _MAX_ENTRIES or miner._budget <= 0:
            break
        try:
            data = _read_entry(zf, info)
        except Exception:  # noqa: BLE001
            continue
        miner.feed_auto(info.filename, data)


# ---------------------------------------------------------------------------
# Android (.apk)
# ---------------------------------------------------------------------------
def _aapt_badging(path: str) -> dict:
    """Authoritative package/version/permission facts via aapt, if installed."""
    for tool in ("aapt", "aapt2"):
        exe = _which(tool)
        if not exe:
            continue
        try:
            args = [exe, "dump", "badging", path] if tool == "aapt" else [exe, "dump", "badging", path]
            proc = subprocess.run(args, capture_output=True, text=True, timeout=60)
        except Exception:  # noqa: BLE001
            continue
        out = proc.stdout or ""
        if "package:" not in out:
            continue
        pkg = _re1(r"package: name='([^']+)'", out)
        ver = _re1(r"versionName='([^']*)'", out)
        label = _re1(r"application-label:'([^']*)'", out)
        perms = re.findall(r"uses-permission: name='([^']+)'", out)
        return {"package": pkg, "version": ver, "app_label": label,
                "permissions": perms, "tool": tool}
    return {}


def _android_manifest_facts(text: str) -> tuple[set[str], set[str]]:
    """Permissions + declared component class names from a manifest's strings
    (works on binary-AXML string output or a decompiled text manifest alike)."""
    perms = {m.group(1) for m in _PERM_RE.finditer(text)}
    components = {
        m.group(1) for m in _COMPONENT_RE.finditer(text)
        if ".permission." not in m.group(1)
    }
    return perms, components


def _cleartext_permitted(xml: str) -> bool:
    return 'cleartexttrafficpermitted="true"' in xml.lower().replace(" ", "")


def analyze_apk(path: str, miner: _Miner, notes: list[str]) -> dict:
    meta: dict = {"platform": "android"}
    perms: set[str] = set()
    components: set[str] = set()
    cleartext = None

    badging = _aapt_badging(path)
    if badging:
        meta["package"] = badging.get("package") or ""
        meta["version"] = badging.get("version") or ""
        meta["app_label"] = badging.get("app_label") or ""
        perms.update(badging.get("permissions") or [])
        notes.append(f"android manifest read via {badging.get('tool')}")

    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        # Manifest: recover permissions / components / schemes by string
        # extraction (robust whether or not aapt ran).
        if "AndroidManifest.xml" in names:
            try:
                manifest = _strings(zf.read("AndroidManifest.xml"))
            except Exception:  # noqa: BLE001
                manifest = ""
            mp, mc = _android_manifest_facts(manifest)
            perms.update(mp)
            components.update(mc)
            miner.feed("AndroidManifest.xml", manifest)
        # network_security_config: an honest cleartext signal lives here as XML.
        for n in names:
            low = n.lower()
            if low.startswith("res/") and low.endswith(".xml") and (
                "network" in low or "security" in low
            ):
                try:
                    xml = zf.read(n).decode("utf-8", "replace")
                except Exception:  # noqa: BLE001
                    continue
                if _cleartext_permitted(xml):
                    cleartext = True
                miner.feed(n, xml)
        _mine_zip(zf, miner, skip={"AndroidManifest.xml"})

    meta["permissions"] = sorted(perms)
    meta["dangerous_permissions"] = sorted(
        p for p in perms if p.rsplit(".", 1)[-1] in _DANGEROUS_PERMS
    )
    meta["components"] = sorted(components)[:200]
    meta["cleartext_traffic"] = cleartext
    return meta


# ---------------------------------------------------------------------------
# iOS (.ipa)
# ---------------------------------------------------------------------------
def analyze_ipa(path: str, miner: _Miner, notes: list[str]) -> dict:
    meta: dict = {"platform": "ios"}
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        info_plist = next(
            (n for n in names if re.match(r"Payload/[^/]+\.app/Info\.plist$", n)), ""
        )
        if info_plist:
            raw = zf.read(info_plist)
            _apply_ios_plist(raw, meta, notes)
            # Plist string values themselves carry endpoints/domains sometimes.
            try:
                miner.feed(info_plist, json.dumps(_plist_text(plistlib.loads(raw))))
            except Exception:  # noqa: BLE001
                pass
        _mine_zip(zf, miner)
    return meta


def _plist_text(obj, depth: int = 0) -> list:
    """Flatten plist string values for endpoint/domain mining."""
    out: list = []
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_plist_text(v, depth + 1))
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            out.extend(_plist_text(v, depth + 1))
    elif isinstance(obj, str):
        out.append(obj)
    return out


# ---------------------------------------------------------------------------
# Electron (.asar) / Java (.jar) / native binary
# ---------------------------------------------------------------------------
def analyze_asar(path: str, miner: _Miner, notes: list[str]) -> dict:
    meta: dict = {"platform": "electron"}
    for name, data in _asar_entries(path):
        if miner._budget <= 0:
            break
        if name.endswith("package.json"):
            try:
                pkg = json.loads(data.decode("utf-8", "replace"))
                if isinstance(pkg, dict) and not meta.get("package"):
                    meta["package"] = pkg.get("name", "")
                    meta["version"] = pkg.get("version", "")
                    meta["app_label"] = pkg.get("productName", "") or pkg.get("name", "")
            except ValueError:
                pass
        miner.feed_auto(name, data)
    return meta


def analyze_jar(path: str, miner: _Miner, notes: list[str]) -> dict:
    with zipfile.ZipFile(path) as zf:
        _mine_zip(zf, miner)
    return {"platform": "java"}


def analyze_binary(path: str, miner: _Miner, notes: list[str]) -> dict:
    with open(path, "rb") as fh:
        data = fh.read(_MAX_TOTAL_BYTES)
    miner.feed_bytes(os.path.basename(path), data)
    return {"platform": "native"}


def analyze_directory(path: str, miner: _Miner, notes: list[str]) -> dict:
    """Analyze an UNPACKED app tree — an iOS ``.app`` bundle, an Electron
    resources dir, or an apktool/jadx-decompiled APK. Walks every file, mines
    it by content, and reads the same signature files (AndroidManifest.xml,
    Info.plist, package.json) the archive analyzers do."""
    meta: dict = {"platform": "directory"}
    perms: set[str] = set()
    components: set[str] = set()
    cleartext = None
    sig = {"android": False, "ios": False, "electron": False}
    count = 0
    for root, _dirs, files in os.walk(path):
        for fn in files:
            if miner._budget <= 0 or count > _MAX_ENTRIES:
                break
            count += 1
            fp = os.path.join(root, fn)
            try:
                with open(fp, "rb") as fh:
                    data = fh.read(_MAX_ENTRY_BYTES)
            except OSError:
                continue
            low = fn.lower()
            rel = os.path.relpath(fp, path)
            if low == "androidmanifest.xml":
                sig["android"] = True
                mp, mc = _android_manifest_facts(
                    data.decode("utf-8", "replace") if not _looks_binary(data) else _strings(data)
                )
                perms.update(mp)
                components.update(mc)
            elif low == "info.plist":
                sig["ios"] = True
                _apply_ios_plist(data, meta, notes)
            elif low == "package.json" and not meta.get("package"):
                sig["electron"] = True
                try:
                    pkg = json.loads(data.decode("utf-8", "replace"))
                    if isinstance(pkg, dict):
                        meta["package"] = pkg.get("name", "")
                        meta["version"] = pkg.get("version", "")
                        meta["app_label"] = pkg.get("productName", "") or pkg.get("name", "")
                except ValueError:
                    pass
            elif low.endswith(".xml") and ("network" in low or "security" in low):
                if _cleartext_permitted(data.decode("utf-8", "replace")):
                    cleartext = True
            miner.feed_auto(rel, data)
    if sig["android"]:
        meta["platform"] = "android"
        meta["permissions"] = sorted(perms)
        meta["dangerous_permissions"] = sorted(
            p for p in perms if p.rsplit(".", 1)[-1] in _DANGEROUS_PERMS
        )
        meta["components"] = sorted(components)[:200]
        meta["cleartext_traffic"] = cleartext
    elif sig["ios"]:
        meta["platform"] = "ios"
    elif sig["electron"]:
        meta["platform"] = "electron"
    return meta


def _apply_ios_plist(data: bytes, meta: dict, notes: list[str]) -> None:
    """Read Info.plist facts into meta (shared by IPA + directory analyzers)."""
    try:
        pl = plistlib.loads(data)
    except Exception as exc:  # noqa: BLE001
        notes.append(f"Info.plist parse failed: {type(exc).__name__}")
        return
    if not isinstance(pl, dict):
        return
    meta["bundle_id"] = pl.get("CFBundleIdentifier", "")
    meta["version"] = pl.get("CFBundleShortVersionString", "") or pl.get("CFBundleVersion", "")
    meta["app_label"] = pl.get("CFBundleDisplayName", "") or pl.get("CFBundleName", "")
    schemes: list[str] = []
    for entry in pl.get("CFBundleURLTypes", []) or []:
        if isinstance(entry, dict):
            schemes.extend(entry.get("CFBundleURLSchemes", []) or [])
    meta["url_schemes"] = sorted({str(s).lower() for s in schemes})
    ats = pl.get("NSAppTransportSecurity")
    if isinstance(ats, dict):
        meta["ats_arbitrary_loads"] = bool(ats.get("NSAllowsArbitraryLoads"))


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------
_MACHO_MAGICS = (
    b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
)


def _is_asar(path: str) -> bool:
    """True if the file parses as an asar archive (pickled JSON header with a
    'files' tree). Lets a URL-downloaded Electron bundle be detected even when
    the name carries no .asar extension."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
            if len(head) < 16:
                return False
            json_len = struct.unpack("<I", head[12:16])[0]
            if json_len <= 0 or json_len > 50_000_000:
                return False
            hdr = fh.read(min(json_len, 65536))
        return b'"files"' in hdr
    except Exception:  # noqa: BLE001
        return False


def _content_type(path: str) -> tuple[str, bool]:
    """Detect app type from CONTENT. Returns (type, confident). confident=False
    means nothing matched and we are defaulting to a raw-strings scan."""
    low = path.lower()
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        return "binary", False
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
        except Exception:  # noqa: BLE001
            names = []
        nameset = set(names)
        if "AndroidManifest.xml" in nameset or any(n.endswith(".dex") for n in names):
            return "apk", True
        if any(re.match(r"Payload/[^/]+\.app/", n) for n in names):
            return "ipa", True
        if low.endswith(".asar"):
            return "electron", True
        return "jar", True  # it genuinely is a zip (jar / aab / generic)
    if low.endswith(".asar") or _is_asar(path):
        return "electron", True
    if head[:4] == b"\x7fELF" or head[:2] == b"MZ" or head[:4] in _MACHO_MAGICS:
        return "binary", True
    # No container, no executable magic — extension is only a weak hint and the
    # file is likely corrupt/unknown; scan as raw strings but say so.
    return "binary", False


def detect_type(path: str, forced: str) -> str:
    if forced and forced != "auto":
        return forced
    return _content_type(path)[0]


_ANALYZERS = {
    "apk": analyze_apk,
    "ipa": analyze_ipa,
    "electron": analyze_asar,
    "jar": analyze_jar,
    "binary": analyze_binary,
}


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------
def _which(name: str) -> str:
    from shutil import which
    return which(name) or ""


def _re1(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def _bounded_json(result: dict) -> str:
    """Serialize result, trimming the endpoint list (lowest-value, highest-count)
    until it fits the output budget, so the JSON is always valid and the
    high-value facts (permissions/hosts/secrets/platform) always survive."""
    out = json.dumps(result, indent=None)
    if len(out) <= _MAX_OUTPUT_CHARS or not result.get("endpoints"):
        return out
    eps = list(result["endpoints"])
    while eps and len(out) > _MAX_OUTPUT_CHARS:
        drop = max(1, len(eps) // 4)
        eps = eps[: len(eps) - drop]
        trimmed = dict(result)
        trimmed["endpoints"] = eps
        trimmed["endpoints_truncated"] = True
        trimmed["notes"] = list(result.get("notes") or []) + [
            f"endpoint list trimmed to {len(eps)} of {result.get('endpoint_count', len(eps))} "
            "to keep output within the parse budget (full count preserved in endpoint_count)"
        ]
        out = json.dumps(trimmed, indent=None)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Static recon over a mobile/desktop app package.")
    ap.add_argument("--app-path", default="", help="Path to an app file/dir already in the container")
    ap.add_argument("--url", default="", help="URL to download the app from first")
    ap.add_argument("--type", default="auto",
                    choices=["auto", "apk", "ipa", "electron", "jar", "binary"])
    ap.add_argument("--timeout", type=int, default=120, help="Download timeout (s)")
    args = ap.parse_args()

    notes: list[str] = []
    cleanup = ""
    path = args.app_path.strip()
    if not path and args.url.strip():
        path, err = _download(args.url.strip(), args.timeout, notes)
        cleanup = path
        if err:
            print(json.dumps({"error": err, "target": args.url, "notes": notes}))
            return 1
    if not path:
        print(json.dumps({"error": "provide --app-path (file/dir in container) or --url", "notes": notes}))
        return 1
    is_dir = os.path.isdir(path)
    if not is_dir and not os.path.isfile(path):
        print(json.dumps({"error": f"path is not a readable file or directory: {path}", "notes": notes}))
        return 1

    try:
        miner = _Miner()
        if is_dir:
            app_type = "directory"
            meta = analyze_directory(path, miner, notes)
            size_bytes = 0
        else:
            content_type, confident = _content_type(path)
            app_type = args.type if args.type != "auto" else content_type
            # Honor a forced type (it is the escape hatch for e.g. an
            # extension-less download) but never silently mislabel: if content
            # confidently looks like something else, say so.
            if args.type != "auto" and confident and content_type != args.type \
                    and content_type in ("apk", "ipa", "electron", "jar"):
                notes.append(
                    f"forced type={args.type} but the file's content looks like "
                    f"{content_type} — reporting as {args.type} as requested"
                )
            if args.type == "auto" and not confident:
                notes.append(
                    "input matched no known app package (APK/IPA/Electron/JAR/executable); "
                    "scanned as raw strings — results may be noise if this is not an app"
                )
            analyzer = _ANALYZERS.get(app_type, analyze_binary)
            try:
                meta = analyzer(path, miner, notes)
            except zipfile.BadZipFile:
                notes.append(f"{app_type}: not a valid archive — falling back to binary string scan")
                app_type = "binary"
                meta = analyze_binary(path, miner, notes)
            size_bytes = os.path.getsize(path)

        ranked = sorted(
            miner.endpoints,
            key=lambda e: (0 if is_interesting(e) else 1, e.lower()),
        )
        schemes = sorted(set(meta.get("url_schemes", [])) | miner.schemes)
        result = {
            "target": args.url or args.app_path,
            "app_type": app_type,
            "size_bytes": size_bytes,
            "files_analyzed": miner.files_analyzed,
            "endpoints": ranked[:_MAX_EMIT_ENDPOINTS],
            "endpoint_count": len(ranked),
            "hosts": sorted(miner.hosts)[:_MAX_EMIT_HOSTS],
            "host_count": len(miner.hosts),
            "url_schemes": schemes,
            "secrets": dedupe_secrets(miner.secrets),
            "cloud_assets": dedupe_cloud(miner.cloud),
            "notes": notes,
        }
        result.update(meta)
        result["url_schemes"] = schemes  # meta may re-add ios-only schemes
        print(_bounded_json(result))
        return 0
    finally:
        if cleanup and os.path.isfile(cleanup):
            try:
                os.unlink(cleanup)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
