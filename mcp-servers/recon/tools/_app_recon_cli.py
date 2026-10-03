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
)

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

# Budgets — an app can be hundreds of MB; cap what we read so one call can't
# blow memory or the tool timeout. Mirrors js_recon's per-file byte cap.
_MAX_DOWNLOAD_BYTES = 400 * 1024 * 1024  # 400 MB app download ceiling
_MAX_ENTRY_BYTES = 8 * 1024 * 1024       # read at most 8 MB from any one file
_MAX_TOTAL_BYTES = 120 * 1024 * 1024     # stop mining after 120 MB scanned
_MAX_ENTRIES = 6000                      # and after this many package members

# Text-ish members worth decoding whole (vs. string-scraping as binary).
_TEXT_EXT = (
    ".js", ".json", ".xml", ".txt", ".html", ".htm", ".map", ".properties",
    ".yml", ".yaml", ".plist", ".mf", ".cfg", ".conf", ".ini", ".env",
    ".ts", ".jsx", ".tsx", ".vue", ".graphql", ".proto", ".md", ".csv",
)

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
def _download(url: str, timeout: int, notes: list[str]) -> str:
    """Fetch an app to a temp file. Return the path, or '' on failure."""
    try:
        req = Request(url, headers={"User-Agent": _UA, "Accept": "*/*"})
        fd, path = tempfile.mkstemp(prefix="osprey_app_")
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
        return path
    except Exception as exc:  # noqa: BLE001
        notes.append(f"download failed: {type(exc).__name__}: {exc}")
        return ""


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


def _host_of_endpoint(ep: str) -> str:
    m = _URL_HOST_RE.match(ep)
    if not m:
        return ""
    host = m.group(1).split("@")[-1].split(":")[0].strip().lower()
    return host if _HOST_RE.match(host) else ""


def _is_text(name: str) -> bool:
    return name.lower().endswith(_TEXT_EXT)


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
        if _is_text(info.filename):
            miner.feed(info.filename, data.decode("utf-8", "replace"))
        else:
            miner.feed_bytes(info.filename, data)


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
            for m in _PERM_RE.finditer(manifest):
                perms.add(m.group(1))
            for m in _COMPONENT_RE.finditer(manifest):
                cls = m.group(1)
                # A permission string (ending in .permission.FOO) also matches
                # the component shape — keep those out of the component list.
                if ".permission." not in cls and cls not in perms:
                    components.add(cls)
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
                if "cleartexttrafficpermitted=\"true\"" in xml.lower().replace(" ", ""):
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
            try:
                pl = plistlib.loads(zf.read(info_plist))
            except Exception as exc:  # noqa: BLE001
                pl = {}
                notes.append(f"Info.plist parse failed: {type(exc).__name__}")
            if isinstance(pl, dict):
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
                # Plist values themselves carry endpoints/domains sometimes.
                miner.feed(info_plist, json.dumps(_plist_text(pl)))
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
        if _is_text(name):
            miner.feed(name, data.decode("utf-8", "replace"))
        else:
            miner.feed_bytes(name, data)
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


# ---------------------------------------------------------------------------
# Type detection
# ---------------------------------------------------------------------------
def detect_type(path: str, forced: str) -> str:
    if forced and forced != "auto":
        return forced
    low = path.lower()
    try:
        with open(path, "rb") as fh:
            head = fh.read(8)
    except OSError:
        head = b""
    if low.endswith(".asar"):
        return "electron"
    if head[:4] == b"PK\x03\x04" or head[:4] == b"PK\x05\x06" or zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
        except Exception:  # noqa: BLE001
            names = []
        nameset = set(names)
        if "AndroidManifest.xml" in nameset or any(n.endswith(".dex") for n in names):
            return "apk"
        if any(re.match(r"Payload/[^/]+\.app/", n) for n in names):
            return "ipa"
        if low.endswith((".asar",)):
            return "electron"
        return "jar"  # generic zip / jar / aab-like → text+class mining
    if low.endswith(".apk"):
        return "apk"
    if low.endswith(".ipa"):
        return "ipa"
    if low.endswith(".jar"):
        return "jar"
    # Native executable magic.
    if head[:4] in (b"\x7fELF",) or head[:2] == b"MZ" or head[:4] in (
        b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"
    ):
        return "binary"
    return "binary"


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


def main() -> int:
    ap = argparse.ArgumentParser(description="Static recon over a mobile/desktop app package.")
    ap.add_argument("--app-path", default="", help="Path to an app file already in the container")
    ap.add_argument("--url", default="", help="URL to download the app from first")
    ap.add_argument("--type", default="auto",
                    choices=["auto", "apk", "ipa", "electron", "jar", "binary"])
    ap.add_argument("--timeout", type=int, default=120, help="Download timeout (s)")
    args = ap.parse_args()

    notes: list[str] = []
    cleanup = ""
    path = args.app_path.strip()
    if not path and args.url.strip():
        path = _download(args.url.strip(), args.timeout, notes)
        cleanup = path
    if not path:
        print(json.dumps({"error": "provide --app-path (file in container) or --url", "notes": notes}))
        return 1
    if not os.path.isfile(path):
        print(json.dumps({"error": f"file not found: {path}", "notes": notes}))
        return 1

    try:
        app_type = detect_type(path, args.type)
        miner = _Miner()
        analyzer = _ANALYZERS.get(app_type, analyze_binary)
        try:
            meta = analyzer(path, miner, notes)
        except zipfile.BadZipFile:
            notes.append(f"{app_type}: not a valid archive — falling back to binary string scan")
            app_type = "binary"
            meta = analyze_binary(path, miner, notes)

        ranked = sorted(
            miner.endpoints,
            key=lambda e: (0 if is_interesting(e) else 1, e.lower()),
        )
        schemes = sorted(set(meta.get("url_schemes", [])) | miner.schemes)
        result = {
            "target": args.url or args.app_path,
            "app_type": app_type,
            "size_bytes": os.path.getsize(path),
            "files_analyzed": miner.files_analyzed,
            "endpoints": ranked[:1000],
            "endpoint_count": len(ranked),
            "hosts": sorted(miner.hosts)[:500],
            "url_schemes": schemes,
            "secrets": dedupe_secrets(miner.secrets),
            "cloud_assets": dedupe_cloud(miner.cloud),
            "notes": notes,
        }
        result.update(meta)
        result["url_schemes"] = schemes  # meta may re-add ios-only schemes
        print(json.dumps(result, indent=None))
        return 0
    finally:
        if cleanup and os.path.isfile(cleanup):
            try:
                os.unlink(cleanup)
            except OSError:
                pass


if __name__ == "__main__":
    sys.exit(main())
