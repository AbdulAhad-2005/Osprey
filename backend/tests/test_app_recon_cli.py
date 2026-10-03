"""End-to-end test of the stdlib-only app-recon worker (_app_recon_cli.py).

Builds synthetic APK / IPA / Electron-asar / jar / native-binary fixtures,
runs the worker exactly as the backend does (``python3 _app_recon_cli.py
--app-path ...``), and asserts it recovers endpoints, backend hostnames,
secrets, cloud refs and platform metadata from each package type. Also guards
the shared ``_recon_extract`` module that js_recon now depends on, so a change
there that breaks extraction is caught here.
"""

from __future__ import annotations

import json
import plistlib
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

_TOOLS_DIR = (
    Path(__file__).resolve().parents[2] / "mcp-servers" / "recon" / "tools"
)
_CLI = _TOOLS_DIR / "_app_recon_cli.py"


def _run(app_path: str) -> dict:
    proc = subprocess.run(
        [sys.executable, str(_CLI), "--app-path", app_path],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"worker failed: {proc.stderr[:400]}"
    return json.loads(proc.stdout)


def _write_apk(path: str) -> None:
    manifest = (
        b"android.permission.INTERNET\x00android.permission.CAMERA\x00"
        b"android.permission.ACCESS_FINE_LOCATION\x00"
        b"com.example.app.MainActivity\x00"
    )
    dex = (b"dex\n035\x00" + b'GET https://api.example.com/v1/login '
           b'AKIA1234567890ABCDEF "/api/v2/users" mybucket.s3.amazonaws.com')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr(
            "res/xml/network_security_config.xml",
            '<network-security-config><base-config '
            'cleartextTrafficPermitted="true"/></network-security-config>',
        )
        z.writestr("assets/config.json", json.dumps(
            {"api": "https://backend.corp.example.com/graphql",
             "key": "sk_live_abcd1234efgh5678ijkl9012"}))


def _write_ipa(path: str) -> None:
    info = plistlib.dumps({
        "CFBundleIdentifier": "com.example.ios",
        "CFBundleShortVersionString": "2.3.1",
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "fbauth2"]}],
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "ServerURL": "https://ios-api.example.com/v1",
    })
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/Demo.app/Info.plist", info)
        z.writestr("Payload/Demo.app/Demo",
                   b"strings https://telemetry.example.net/collect "
                   b"glpat-ABCDEFGHIJ1234567890")


def _write_asar(path: str) -> None:
    files = {
        "main.js": b'const u="https://electron-api.example.com/rpc";'
                   b' const k="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";',
        "package.json": json.dumps(
            {"name": "demoapp", "version": "1.0.0", "productName": "DemoDesktop"}).encode(),
    }
    offset = 0
    tree = {}
    body = b""
    for name, data in files.items():
        tree[name] = {"offset": str(offset), "size": len(data)}
        body += data
        offset += len(data)
    header = json.dumps({"files": tree}).encode()
    json_len = len(header)
    header += b"\x00" * ((4 - (json_len % 4)) % 4)
    frame = (struct.pack("<I", 4) + struct.pack("<I", json_len + 8)
             + struct.pack("<I", json_len + 4) + struct.pack("<I", json_len))
    with open(path, "wb") as f:
        f.write(frame)
        f.write(header)
        f.write(body)


def test_apk(tmp_path):
    p = str(tmp_path / "app.apk")
    _write_apk(p)
    out = _run(p)
    assert out["app_type"] == "apk"
    assert out["platform"] == "android"
    assert "https://api.example.com/v1/login" in out["endpoints"]
    assert "api.example.com" in out["hosts"]
    assert "backend.corp.example.com" in out["hosts"]
    stypes = {s["secret"] for s in out["secrets"]}
    assert "AKIA1234567890ABCDEF" in stypes
    assert "sk_live_abcd1234efgh5678ijkl9012" in stypes
    assert any(c["bucket"] == "mybucket" for c in out["cloud_assets"])
    perms = set(out["permissions"])
    assert "android.permission.CAMERA" in perms
    assert "android.permission.CAMERA" in set(out["dangerous_permissions"])
    # permission strings must not leak into the component list
    assert all(".permission." not in c for c in out["components"])
    assert out["cleartext_traffic"] is True


def test_ipa(tmp_path):
    p = str(tmp_path / "app.ipa")
    _write_ipa(p)
    out = _run(p)
    assert out["app_type"] == "ipa"
    assert out["bundle_id"] == "com.example.ios"
    assert out["ats_arbitrary_loads"] is True
    assert set(out["url_schemes"]) >= {"myapp", "fbauth2"}
    assert "ios-api.example.com" in out["hosts"]
    assert "telemetry.example.net" in out["hosts"]  # from the Mach-O strings
    assert any(s["secret"].startswith("glpat-") for s in out["secrets"])


def test_electron_asar(tmp_path):
    p = str(tmp_path / "app.asar")
    _write_asar(p)
    out = _run(p)
    assert out["app_type"] == "electron"
    assert out["package"] == "demoapp"
    assert "electron-api.example.com" in out["hosts"]
    assert any(s["secret"].startswith("ghp_") for s in out["secrets"])


def test_jar_and_binary(tmp_path):
    jar = str(tmp_path / "x.jar")
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("config.properties",
                   "endpoint=https://java-api.example.com/service\n"
                   "password=\"supersecretvalue123\"")
    out = _run(jar)
    assert out["app_type"] == "jar"
    assert "java-api.example.com" in out["hosts"]

    binf = str(tmp_path / "app.bin")
    with open(binf, "wb") as f:
        f.write(b"\x7fELF" + b"\x00" * 32 + b"https://native-api.example.com/ping")
    out = _run(binf)
    assert out["app_type"] == "binary"
    assert "native-api.example.com" in out["hosts"]


def test_missing_input_is_graceful_error(tmp_path):
    proc = subprocess.run(
        [sys.executable, str(_CLI), "--app-path", str(tmp_path / "nope.apk")],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 1
    assert "error" in json.loads(proc.stdout)


def test_shared_extract_module_powers_js_recon():
    """Dedup guard: the shared module js_recon now imports must keep extracting."""
    sys.path.insert(0, str(_TOOLS_DIR))
    try:
        import _recon_extract as rx
    finally:
        sys.path.pop(0)
    assert rx.extract_endpoints('"/api/v1/x"') == ["/api/v1/x"]
    assert rx.extract_urls("see https://h.example.com/a for more") == ["https://h.example.com/a"]
    assert rx.host_of("https://h.example.com/a") == "h.example.com"
    secs = rx.extract_secrets('token="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"', "s")
    assert any(s["type"] == "github_token" for s in secs)
    # placeholder guard still filters obvious examples
    assert rx.extract_secrets('key="your_api_key_here"', "s") == []
