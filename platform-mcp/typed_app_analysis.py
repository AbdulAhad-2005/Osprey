"""Typed FastMCP tool for application analysis — static recon over mobile and
desktop app packages.

``app_recon`` is the recon-phase analogue of ``js_recon``: it mines a shipped
application (Android APK, iOS IPA, Electron ``.asar``, Java ``.jar``, or native
binary) for the backend it talks to — endpoints, hostnames, hardcoded secrets,
exposed cloud storage — plus platform metadata that is itself attack surface
(Android permissions/components + cleartext config, iOS URL schemes + App
Transport Security posture). Discovered backend hosts flow back into the
engagement as new recon seeds, the same way subdomain enumeration output does.

Calls the same backend execute path as platform_exec, with explicit parameters
so the Commander does not hand-build params_json.
"""

from __future__ import annotations

from typing import Any, Callable

TYPED_APP_ANALYSIS_TOOLS: tuple[str, ...] = ("app_recon",)

_TOOL_BLURBS: dict[str, str] = {
    "app_recon": (
        "Static app analysis (app_path= a file already in the Kali container, or url= to "
        "download first). Handles Android APK, iOS IPA, Electron .asar, Java .jar, and native "
        "binaries (type=auto detects; override with type=apk|ipa|electron|jar|binary). Extracts "
        "backend endpoints + hostnames (new recon seeds), hardcoded secrets (API keys/tokens/"
        "JWTs/private keys), exposed cloud storage, and platform posture: Android permissions/"
        "components + cleartext-traffic config, iOS URL schemes + App Transport Security. "
        "Stdlib-only (no device/emulator); aapt is used for richer Android facts when present. "
        "Large apps: run via platform_job_start so the download+scan can't time out the call. "
        "Get the app first if you don't have it — operator upload, or wget into the container "
        "via platform_shell, or pass a direct url=."
    ),
}

# App download + full static scan can run well past a flat 300s on a large APK/
# IPA; give it headroom. 0 from the caller uses this; an explicit value wins.
_DEFAULT_APP_TIMEOUT = 480


def _build_params(*, app_path: str = "", url: str = "", type: str = "", timeout: str = "") -> dict[str, Any]:
    params: dict[str, Any] = {}
    for key, val in (("app_path", app_path), ("url", url), ("type", type), ("timeout", timeout)):
        if str(val).strip():
            params[key] = str(val).strip()
    return params


def register_typed_app_analysis_tools(mcp: Any, *, execute: Callable[..., str]) -> int:
    """Register the app-analysis typed tool(s)."""
    count = 0
    for tool_name in TYPED_APP_ANALYSIS_TOOLS:
        blurb = _TOOL_BLURBS.get(tool_name, f"App-analysis tool {tool_name}.")

        def _make(name: str, doc: str) -> Callable[..., str]:
            def _tool(
                app_path: str = "",
                url: str = "",
                type: str = "auto",
                timeout: str = "",
                additional_args: str = "",
                timeout_seconds: int = 0,
                engagement_id: str = "",
            ) -> str:
                params = _build_params(app_path=app_path, url=url, type=type, timeout=timeout)
                effective_timeout = timeout_seconds or _DEFAULT_APP_TIMEOUT
                return execute(
                    name,
                    params,
                    additional_args=(additional_args or "").strip(),
                    timeout_seconds=effective_timeout,
                    engagement_id=engagement_id,
                )

            _tool.__name__ = name
            _tool.__doc__ = (
                f"{doc}\n\n"
                "RECON attack-surface mapping for applications. Typed tool; prefer over "
                "platform_exec JSON. app_path|url accepted (aliases file_path|path|target also "
                "remap). engagement_id= pins this call to a specific engagement (from "
                "platform_set_target). Escape hatch for raw apktool/jadx/strings: "
                "platform_shell / platform_script."
            )
            return _tool

        handler = _make(tool_name, blurb)
        mcp.tool(name=tool_name)(handler)
        count += 1
    return count
