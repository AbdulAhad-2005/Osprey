---
name: app-analysis
description: "Statically analyze an organization's shipped mobile and desktop apps (Android APK, iOS IPA, Electron, jar, native binary) with app_recon to recover the backend they call — API hosts/routes, hardcoded secrets, cloud buckets, permissions and transport posture — and feed those hosts back into recon."
phases: [recon]
tags: [recon, mobile, desktop, apk, ipa, electron, secrets]
---

# App Analysis — mobile & desktop packages as an attack-surface map

An organization's **apps are a map of its backend.** A mobile or desktop client hardcodes the
API hosts, routes, keys, and cloud buckets it talks to — frequently backends that never appear in
DNS, subdomain enumeration, or the public website. Pulling the app and mining it statically is a
first-class recon source, the same way `js_recon` is for web. `app_recon` is the tool.

It is **static and offline** — no device, emulator, or instrumentation. It is standard-library
only, so it always runs; if `aapt` happens to be installed it reads Android manifest facts from it
for accuracy, otherwise it recovers them itself. No new backend is required.

## What `app_recon` handles

| Input | `type=` | What it reads |
|-------|---------|---------------|
| Android APK | `apk` | AndroidManifest (permissions, components, deep-link schemes), `network_security_config` (cleartext), all DEX/resources/assets |
| iOS IPA | `ipa` | `Info.plist` (bundle id, `CFBundleURLSchemes`, `NSAppTransportSecurity`), the Mach-O binary, bundle resources |
| Electron desktop | `electron` | `app.asar` — every `.js`/`.json`/`.html` + `package.json` |
| Java desktop | `jar` | class strings + `.properties`/`.xml`/`.json` config, `MANIFEST.MF` |
| Native binary | `binary` | printable strings (ELF/PE/Mach-O) |

`type=auto` (default) detects from magic bytes + archive contents. A generic `.zip`/`.aab` is
mined like a jar (text + string extraction).

## What it extracts (the same recon currency, from a package)

1. **Backend endpoints + hostnames** — absolute and relative API routes, and the hostnames they
   point at. **The hostnames flow back into the engagement as new SUBDOMAIN seeds** (tagged
   `app-backend`) — resolve and probe them like any other discovered name. This is the highest-
   value output: app-only backends you would never have found otherwise.
2. **Hardcoded secrets** — AWS/Google/Firebase/Stripe/Slack/GitHub/GitLab keys, JWTs, private
   keys, generic `key=…` assignments. Obvious placeholders are filtered.
3. **Exposed cloud storage** — S3 / GCS / Azure / DigitalOcean bucket references.
4. **Platform posture** (facts, not verdicts) — Android permissions (dangerous subset flagged) and
   declared components; iOS URL schemes + whether App Transport Security is disabled
   (`NSAllowsArbitraryLoads`); Android `cleartextTrafficPermitted`; custom deep-link schemes.

## Getting the app first

`app_recon` needs the package in the container, one of two ways:
- **`url=`** — a direct **http/https** download link (vendor CDN, an APK mirror, a release
  artifact). `app_recon` downloads it (TLS verified, so a MITM can't swap in a tampered package),
  analyzes it, and cleans up. Only http/https are accepted — `file://`/`ftp://` are refused so a
  URL can't make the worker read a local path. URLs with `&` in them are blocked by the param
  guard — `wget` them via `platform_shell` first, then use `app_path=`.
- **`app_path=`** — a file **or a directory** already in the container. A directory is treated as
  an unpacked app: an iOS `.app` bundle, an Electron `resources/` tree, or an
  apktool/jadx-decompiled APK (its `AndroidManifest.xml`, `Info.plist`, `package.json` are read
  just like inside an archive). This is the natural follow-up after `apktool d` / `unzip`.
  The file itself can be one the operator uploaded or one you fetched with `platform_shell`
  (`wget -O /tmp/app.apk <url>`). Store/marketplace pulls (Play, App Store) need the operator to
  provide the artifact — Osprey does not scrape stores.

Large apps can exceed the foreground call budget — run `app_recon` via `platform_job_start` and
poll, exactly like a slow scan.

## Workflow

1. **Find the apps.** Check the target's site/footer links, `well_known_probe` output,
   `apple-app-site-association` / `assetlinks.json` (universal/app links name the package id),
   Play/App Store listings, and `js_recon`/`gau` hits for `.apk`/`.ipa`/download URLs.
2. **Analyze each package** with `app_recon` (`type=auto`).
3. **Promote backend hosts.** The `app-backend` SUBDOMAIN observations are new recon seeds —
   `dnsx_resolve` + `httpx_probe` them, then feed anything live into the normal recon→vuln flow.
   An app pointing at `internal-api.corp.example.com` just reopened recon.
4. **Turn endpoints into surface.** App endpoints land tagged `interesting_path` /
   `injection_point_candidate` — probe the interesting ones live and hand them to content/param
   discovery, same as `js_recon` endpoints.
5. **Triage secrets by validity, not presence** (see evidence discipline below).
6. **Note posture signals.** Cleartext-permitted, ATS-disabled, dangerous permissions, and custom
   schemes are `app-posture` leads for the vuln phase — not findings on their own.

## Going deeper than static (escape hatch)

`app_recon` is the broad static pass. For targeted deep work use `platform_shell` / `platform_script`
with the heavier toolchain when it is installed: `apktool d` (full manifest/smali), `jadx` (DEX →
Java), `apkleaks`, `strings`/`radare2` on the Mach-O/native binary, `asar extract` for Electron.
Dynamic/instrumented analysis (Frida/objection, emulator traffic through `proxy_*`) is a separate,
later activity and needs explicit operator authorization.

## Evidence discipline

- **Endpoints/hosts from an app are INFERRED until probed live** — a string in a binary is not a
  working route or a live host. Resolve + probe before recording an asset as real.
- **Secrets: exposure OBSERVED, validity UNVERIFIED.** A regex hit is not a working credential —
  it may be a publishable key (Firebase/Stripe publishable keys are designed to ship in clients) or
  rotated/dead. Cap at MEDIUM until a live check proves it; hand validation to the vuln phase.
- **Posture is "declared," never "exploited."** `usesCleartextTraffic`, a dangerous permission, or
  `NSAllowsArbitraryLoads` is a fact the manifest asserts — impact is a later test.
- **Cloud buckets:** the *reference* is observed; listability/writability is a separate test.

## Handoff (do NOT exploit here)

Leads land tagged `app-backend`, `app-endpoint`, `interesting_path`, `injection_point_candidate`,
`app-secret`, `cloud-asset`, and `app-posture`. Recon finds and records them honestly; validation
and exploitation belong to the vulnerability phase.
