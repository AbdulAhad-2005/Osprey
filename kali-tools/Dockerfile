# syntax=docker/dockerfile:1

# ─── Base image: pinned digest, not a floating tag ─────────────────────────────
# kalilinux/kali-rolling publishes NO versioned tags — only a moving "latest"
# pointer that re-resolves to whatever Kali ships today, on every build.
#
# Pinning by digest makes the base OS+toolchain snapshot reproducible: a build
# today and a build in six months resolve to the identical image. Upgrading
# becomes a deliberate, occasional action instead of something that happens
# silently underneath every `--build`.
#
# To take a new snapshot on purpose, run `scripts/pin-kali-base.sh` (prints the
# current amd64 digest) and paste the result below, or override at build time:
#   docker build --build-arg KALI_BASE_DIGEST=sha256:... kali-tools/
ARG KALI_BASE_DIGEST=sha256:d2560fdc054793be92236322113fa231e609f95403dd68c613ca864b0d872b1f
FROM kalilinux/kali-rolling@${KALI_BASE_DIGEST}

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/opt/go
# Keep /home/mcpuser/.local/bin on PATH so pipx shims and any runtime
# `pip install --user` OSINT tools resolve in non-login `docker exec` shells.
# Mirrors _KALI_EXEC_PATH in backend services/mcp_client.py.
ENV PATH="/home/mcpuser/.local/bin:${GOPATH}/bin:/usr/local/go/bin:${PATH}"

# GCC 15 in this snapshot defaults to -std=gnu23 (verified: __STDC_VERSION__ ==
# 202311L). C23 no longer auto-exposes older POSIX APIs the way earlier GNU-mode
# defaults did, which breaks legacy C sources that assume the old default.
# Forcing gnu17 is backward compatible — every C sdist this image
# builds still compiles fine under it — so this is a global, preventive fix for
# the whole class of "old C code assumed the old GCC default" breakage, not a
# unicorn-specific patch.
ENV CFLAGS="-std=gnu17 -D_DEFAULT_SOURCE"
ENV CXXFLAGS="-std=gnu++17 -D_DEFAULT_SOURCE"

# gh-latest-asset.py (defined below) resolves GitHub release assets for
# terrascan/ghidra/ysoserial/interactsh. Unauthenticated api.github.com calls
# are capped at 60/hour per source IP, which a shared NAT egress (Docker
# Desktop, CI runners) can exhaust across unrelated builds. Pass a token as a
# build secret (never baked into a layer, unlike --build-arg) to raise that to
# 5000/hour; every call site degrades to unauthenticated + a WARN skip when
# none is supplied, so this is optional:
#   docker build --secret id=github_token,env=GITHUB_TOKEN -t osprey-kali kali-tools/
# or, from a file: --secret id=github_token,src=./gh_token.txt

# This image makes several hundred external network calls over the course of a
# build (apt, go modules, pip/pipx, git clone, GitHub releases/API) across what
# can be an hour-plus wall clock — a single transient blip anywhere in that
# chain (a flaky mirror redirect, one dropped connection) otherwise throws away
# everything cached before it. apt gets a global retry count; wget/curl calls
# get native retry flags; git clone and pip/pipx `git+` installs (which have no
# built-in retry of their own) get wrapped in retry-cmd below.
COPY <<'EOF' /etc/apt/apt.conf.d/99retries
Acquire::Retries "5";
EOF

COPY <<'EOF' /usr/local/bin/retry-cmd
#!/bin/sh
# retry-cmd N CMD...  -- run CMD, retrying up to N times with backoff.
# For operations with no native retry flag of their own (git clone, pip/pipx
# installing from a git+ URL).
n=1
max="$1"; shift
until "$@"; do
    if [ "$n" -ge "$max" ]; then
        echo "retry-cmd: giving up after $n attempt(s): $*" >&2
        exit 1
    fi
    wait_s=$((n * 3))
    echo "retry-cmd: attempt $n failed, retrying in ${wait_s}s: $*" >&2
    sleep "$wait_s"
    n=$((n + 1))
done
EOF
# Strip any \r before chmod: this heredoc's content is copied byte-for-byte from
# the Dockerfile, so a contributor's editor/git config that checked the
# Dockerfile out with CRLF line endings bakes a `\r` into this script's shebang line,
# turning it into `#!/bin/sh\r` — the kernel can't resolve that interpreter
# path and every invocation fails with a bare "not found" (exit 127), which
# looks exactly like the file is missing even though it exists and is
# executable. Normalizing here makes the build immune to host line-ending
# state entirely, independent of any git config or .gitattributes on either
# the repo or the machine building it.
RUN sed -i 's/\r$//' /usr/local/bin/retry-cmd && chmod +x /usr/local/bin/retry-cmd

# apt-get gets its OWN retry wrapper, not just plain retry-cmd: Acquire::Retries
# above only retries within the SAME resolved connection, which doesn't help
# when http.kali.org's geo-redirect sticks a whole apt session to one specific
# mirror that has a structurally broken package pool.
# A fresh `apt-get update` process re-resolves DNS and
# has a real chance of landing on a different, healthy mirror; retrying inside
# the same apt invocation does not.
COPY <<'EOF' /usr/local/bin/apt-install-retry.sh
#!/bin/sh
# /usr/local/bin/apt-install-retry.sh N PKG...  -- apt-get update && install, retrying the
# WHOLE sequence (fresh process each attempt -> fresh DNS/mirror pick).
n=1
max="$1"; shift
until apt-get update && apt-get install -y --no-install-recommends "$@"; do
    if [ "$n" -ge "$max" ]; then
        echo "apt-install-retry: giving up after $n attempt(s): $*" >&2
        exit 1
    fi
    wait_s=$((n * 5))
    echo "apt-install-retry: attempt $n failed, retrying in ${wait_s}s: $*" >&2
    sleep "$wait_s"
    n=$((n + 1))
done
EOF
RUN sed -i 's/\r$//' /usr/local/bin/apt-install-retry.sh && chmod +x /usr/local/bin/apt-install-retry.sh

# ─── System base ───────────────────────────────────────────────────────────────
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-install-retry.sh 5 \
       wget curl git ca-certificates gnupg unzip \
       python3 python3-pip python3-venv python3-dev python3-setuptools python3-wheel \
       build-essential cmake pkg-config libssl-dev libffi-dev \
       libcap2-bin \
       ruby ruby-dev \
       golang-go \
       openjdk-21-jdk-headless
# openjdk-21-jdk-headless: Ghidra 11+ requires a real JDK 21 on PATH and bundles
# no JVM of its own — analyzeHeadless silently has no working java without this

# Small helper reused by the versioned GitHub-release installs below (terrascan,
# kube-bench, ghidra): prints the download URL of the release asset matching a
# glob pattern, defaulting to the latest release, or a specific tag when given
# one. Centralizes the "fetch latest, but let a build-arg pin a version"
# pattern instead of repeating GitHub API + JSON parsing three times.
COPY <<'EOF' /usr/local/bin/gh-latest-asset.py
#!/usr/bin/env python3
"""Print the browser_download_url of a GitHub release asset matching a glob.

Usage: gh-latest-asset.py OWNER/REPO 'PATTERN' [TAG]
TAG defaults to the latest release when omitted/empty; pass a release tag to
pin a specific version instead of tracking latest.
"""
import fnmatch
import json
import os
import sys
import time
import urllib.error
import urllib.request

repo, pattern = sys.argv[1], sys.argv[2]
tag = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else ""
url = f"https://api.github.com/repos/{repo}/releases/" + (f"tags/{tag}" if tag else "latest")

# Unauthenticated api.github.com calls are capped at 60/hour PER SOURCE IP —
# Docker Desktop's shared NAT egress IP means this quota is shared with every
# other build on the same network, and four call sites in this Dockerfile
# alone can exhaust it in one run. A token raises the cap to 5000/hour.
# Optional and backward compatible: falls back to unauthenticated when no
# token is supplied (see `docker build --secret id=github_token,...` below).
token = os.environ.get("GITHUB_TOKEN", "").strip()
req = urllib.request.Request(url)
if token:
    req.add_header("Authorization", f"Bearer {token}")

raw = None
for attempt in range(5):
    try:
        raw = urllib.request.urlopen(req, timeout=20).read()
        break
    except (urllib.error.URLError, TimeoutError) as exc:
        if attempt == 4:
            raise
        print(f"gh-latest-asset: attempt {attempt + 1} failed ({exc}), retrying...", file=sys.stderr)
        time.sleep((attempt + 1) * 3)
data = json.loads(raw)
for asset in data["assets"]:
    if fnmatch.fnmatch(asset["name"], pattern):
        print(asset["browser_download_url"])
        raise SystemExit(0)
raise SystemExit(f"no asset matching {pattern!r} in {repo} release {tag or 'latest'}")
EOF
RUN sed -i 's/\r$//' /usr/local/bin/gh-latest-asset.py && chmod +x /usr/local/bin/gh-latest-asset.py

# ─── 1. Kali apt packages ──────────────────────────────────────────────────────
# Covers the majority of the 90 tools in one layer.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    /usr/local/bin/apt-install-retry.sh 5 \
    # ── Recon ──
    amass dnsenum fierce whois \
    # ── OSINT (passive) — real Kali packages, not the pip dummies ──
    metagoofil theharvester dnstwist sherlock pipx \
    # ── Network ──
    nmap masscan naabu enum4linux enum4linux-ng smbmap \
    netexec nbtscan arp-scan responder samba-common-bin \
    net-tools iputils-ping dnsutils \
    # ── Web ──
    nikto whatweb sqlmap wafw00f wfuzz ffuf dirb dirsearch \
    wpscan xsser feroxbuster gobuster \
    dotdotpwn zaproxy \
    # ── Vulnerability ──
    nuclei \
    # ── Exploit lookup (offline Exploit-DB mirror + searchsploit; NOT Metasploit) ──
    exploitdb \
    # ── Credentials ──
    hydra john hashcat \
    # ── Binary — ropper here (apt), not pip: Kali packages its own
    #   python3-filebytes dependency, sidestepping the upstream PyPI filebytes
    #   sdist whose setup.py uses `ast.Str` (removed in Python 3.12+) ──
    gdb checksec binwalk radare2 ropper \
    # ── Forensics ──
    exiftool foremost steghide \
    # ── Reverse shells / netcat variants ──
    ncat socat \
    # ── Session persistence for shell-management skill (detached listeners,
    #    send-keys/capture-pane across separate platform_shell calls) ──
    tmux \
    # ── Utilities ──
    binutils

# ─── 2. Kali metasploit (~1 GB) ────────────────────────────────────────────────
# metasploit_run (mcp-servers/exploit/metasploit_run.py) is registered GATED
# in tool_registry.py — this makes that registration real instead of dead code.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    /usr/local/bin/apt-install-retry.sh 5 metasploit-framework

# ─── 3. Go tools (install individually for build resilience) ─────────────────
RUN mkdir -p /opt/go
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# The pip package `httpx` (a plain backend HTTP-client dependency, not this tool)
# installs its own same-named CLI into /home/mcpuser/.local/bin, which sits ahead
# of $GOPATH/bin on PATH (see ENV PATH below) so it always shadows this real
# ProjectDiscovery tool. Kali's own apt package sidesteps the exact same
# collision by naming its binary `httpx-toolkit` — mirror that convention here
# at build time so no wrapper ever has to guess an install path at runtime.
RUN ln -sf "$GOPATH/bin/httpx" "$GOPATH/bin/httpx-toolkit"
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/lc/gau/v2/cmd/gau@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/tomnomnom/waybackurls@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/tomnomnom/anew@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/hakluke/hakrawler@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/hahwul/dalfox/v2@latest
# jaeles — signature-based web vuln scanner (jaeles_vulnerability_scan). Was
# registered in the platform but missing from the image ("jaeles: command not found").
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/jaeles-project/jaeles@latest
# x8 — hidden-parameter brute-forcer (Rust). Built via cargo; guarded so a slow
# or failing build doesn't break the image (the tool degrades to "not found",
# which the platform's recovery handles).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    /usr/local/bin/apt-install-retry.sh 5 cargo pkg-config \
    && cargo install --root /usr/local x8 \
    || true
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/tomnomnom/qsreplace@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
# naabu is installed via apt above (the Go build needs libpcap headers and was
# unreliable); apt ships a working 2.6.x binary on the system PATH.
# PhoneInfoga (passive phone-number OSINT) — installed from the prebuilt release.
# `go install` fails: phoneinfoga v2 embeds its web UI via go:embed (client/dist/*),
# which is not present in the Go module, so the build errors out. Asset filename
# has no version in it, so the "latest" release redirect works without an API call;
# ARG below lets a build pin an exact tag if a future "latest" ever regresses.
ARG PHONEINFOGA_VERSION=""
RUN set -eux; \
    if [ -n "$PHONEINFOGA_VERSION" ]; then \
      PIF_URL="https://github.com/sundowndev/phoneinfoga/releases/download/${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz"; \
    else \
      PIF_URL="https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz"; \
    fi; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$PIF_URL" -O /tmp/phoneinfoga.tar.gz; \
    tar -xzf /tmp/phoneinfoga.tar.gz -C /tmp phoneinfoga; \
    install -m 0755 /tmp/phoneinfoga /usr/local/bin/phoneinfoga; \
    rm -f /tmp/phoneinfoga.tar.gz /tmp/phoneinfoga; \
    phoneinfoga version

# ─── 4. Python pip tools ──────────────────────────────────────────────────────
# ropper -> apt (section 1, above): the PyPI build was broken on modern Python.
# terrascan / autorecon -> dedicated installs below: the PyPI packages of those
# names are unrelated, abandoned projects — NOT the real tools (see notes there).
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages --ignore-installed \
       pwntools \
       angr \
       checkov \
       kube-hunter \
       arjun \
       volatility3

# ─── 4b. domain-hunter deps (mcp-servers/recon/tools/domain-hunter) ──────────
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages \
       requests pyyaml openpyxl dnspython tldextract beautifulsoup4

# ─── 4b2. Passive-OSINT python tools NOT packaged in Kali apt ─────────────────
# theHarvester/dnstwist/sherlock/metagoofil come from apt above (the PyPI
# "theHarvester" is a 0.0.1 placeholder — do NOT pip it). Only maigret, holehe
# and social-analyzer are unpackaged; install each in its OWN pipx venv so their
# heavy/pinned deps cannot conflict with netexec/pacu/awscli/checkov/etc. pipx
# symlinks the CLI into /usr/local/bin (on PATH for every exec path).
# web_contact_harvest / email_permute are bundled scripts using the 4b deps.
#
# autorecon lands here too: the PyPI package named "autorecon" (0.1.3) is an unrelated, 
# abandoned project — Tib3rius's actual AutoRecon (currently 2.x) is poetry-packaged and was never published
# to PyPI, so it has to come straight from the source repo like maigret/holehe.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install maigret \
    && pipx install holehe \
    && pipx install social-analyzer \
    && retry-cmd 5 pipx install git+https://github.com/Tib3rius/AutoRecon.git

# ─── 4b3. Wappalyzer python lib ───────────────────────────────────────────────
# wappalyzer_scan.py and tech_stack_analyze.py run `python3 -c "from Wappalyzer
# import Wappalyzer, WebPage"`, so the lib must be importable by the SYSTEM
# python3 (NOT a pipx venv). Without it both tools raise ModuleNotFoundError.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages python-Wappalyzer

# ─── 4b4. Web-pentest additions (TLS deep + GraphQL) ─────────────────────────
# sslyze (WSTG-CRYP: protocols/ciphers/cert/TLS-CVEs) in its own pipx venv; the
# CLI lands on /usr/local/bin (on PATH for every exec path).
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install sslyze
# graphql-cop is a standalone script — its PyPI package declares no console
# entry point, so pipx can't install it ("No apps associated"). Clone the repo,
# install its deps for the system python3, and drop a wrapper on PATH so the
# tool's expected `graphql-cop -t URL -o json` invocation works.
RUN --mount=type=cache,target=/root/.cache/pip \
    retry-cmd 5 sh -c 'rm -rf /opt/graphql-cop && git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop' \
    && pip3 install --break-system-packages requests \
    && (pip3 install --break-system-packages -r /opt/graphql-cop/requirements.txt || true) \
    && printf '#!/bin/sh\nexec python3 /opt/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
    && chmod +x /usr/local/bin/graphql-cop

# ─── 4b5. Playwright browser automation (browser_scrape / browser_flow) ───────
# Installed for the SYSTEM python3 (the browser CLIs `import playwright` directly,
# so a pipx venv would be invisible to them). Chromium + its OS deps land in a
# world-readable shared path so the non-root mcpuser can drive it at runtime.
#
# Kali's apt already ships python3-playwright (Debian-packaged, no bundled Node
# driver — it shells out to a SYSTEM /usr/bin/node) AND some of its deps
# (pyee) the same way. A plain `pip3 install playwright` sees that as "already
# satisfied" and skips installing the pip-packaged version (which bundles its
# own driver), so `playwright install` fails with "No such file or directory:
# '/usr/bin/node'". Installing nodejs fixes that, but pip still needs to lay
# down its own playwright/pyee. `--ignore-installed` installs pip's copies straight into
# site-packages (shadowing the apt ones on sys.path) without touching them.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    /usr/local/bin/apt-install-retry.sh 5 nodejs
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages --ignore-installed playwright \
    && python3 -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/pw-browsers

# ─── 4b2. mitmproxy — full-session passive traffic capture for proxy_start/
# proxy_flows/proxy_replay (browser_flow/browser_scrape opt into routing
# through it via proxy_port=). Own layer: heavier dependency set (h2, wsproto,
# kaitaistruct) than the rest of the pip block above, isolated so it doesn't
# invalidate that layer's cache when bumped independently. ──
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages mitmproxy

# ─── 4c. Ruby gem tools ──────────────────────────────────────────────────────
RUN gem install one_gadget

# ─── 5. GitHub / binary installs ──────────────────────────────────────────────

# whois is also in the apt recon layer above; this late install is a safety net
# for cached builds that predate that package.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    command -v whois >/dev/null 2>&1 || /usr/local/bin/apt-install-retry.sh 5 whois

# ── rustscan (prebuilt release — cargo is slow/flaky; fail the build if missing) ──
# Asset filename carries no version, so the "latest" redirect works without an
# API call; ARG below lets a build pin an exact tag if latest ever regresses.
ARG RUSTSCAN_VERSION=""
RUN set -eux; \
    mkdir -p /tmp/rustscan; \
    if [ -n "$RUSTSCAN_VERSION" ]; then \
      RS_URL="https://github.com/bee-san/RustScan/releases/download/${RUSTSCAN_VERSION}/rustscan.deb.zip"; \
    else \
      RS_URL="https://github.com/bee-san/RustScan/releases/latest/download/rustscan.deb.zip"; \
    fi; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$RS_URL" -O /tmp/rustscan/rustscan.deb.zip; \
    unzip -q /tmp/rustscan/rustscan.deb.zip -d /tmp/rustscan; \
    DEB="$(find /tmp/rustscan -name 'rustscan_*.deb' | head -n1)"; \
    test -n "$DEB"; \
    apt-get install -y --no-install-recommends "$DEB"; \
    command -v rustscan; \
    rm -rf /tmp/rustscan

# ── pacu (AWS exploitation) ──
RUN --mount=type=cache,target=/root/.cache/pip \
    retry-cmd 5 sh -c 'rm -rf /opt/pacu && git clone --depth 1 https://github.com/RhinoSecurityLabs/pacu.git /opt/pacu' \
    && cd /opt/pacu \
    && pip3 install --break-system-packages . \
    && ln -s /opt/pacu/cli.py /usr/local/bin/pacu \
    || true

# ── terrascan (IaC scanner) — the "terrascan" PyPI package (0.2.3) is an
# unrelated, abandoned project; the real tool from tenable/terrascan ships only
# as a Go binary via GitHub releases. Pass TERRASCAN_VERSION (a release tag,
# e.g. v1.19.9) to pin instead of tracking latest. ──
ARG TERRASCAN_VERSION=""
RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    TS_URL="$(python3 /usr/local/bin/gh-latest-asset.py tenable/terrascan '*_Linux_x86_64.tar.gz' "$TERRASCAN_VERSION")"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$TS_URL" -O /tmp/terrascan.tar.gz; \
    tar -xzf /tmp/terrascan.tar.gz -C /tmp terrascan; \
    install -m 0755 /tmp/terrascan /usr/local/bin/terrascan; \
    rm -f /tmp/terrascan.tar.gz /tmp/terrascan; \
    terrascan version) \
    || echo "WARN: terrascan install failed (rate limit or network), skipping"

# ── ghidra (headless) — requires the JDK 21 installed in the system-base layer
# above; Ghidra bundles no JVM of its own. Pass GHIDRA_VERSION (the release TAG,
# e.g. Ghidra_12.1.2_build — not a bare version number) to pin instead of
# tracking latest. ──
ARG GHIDRA_VERSION=""
RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    GH_URL="$(python3 /usr/local/bin/gh-latest-asset.py NationalSecurityAgency/ghidra '*.zip' "$GHIDRA_VERSION")"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$GH_URL" -O /tmp/ghidra.zip; \
    unzip -q /tmp/ghidra.zip -d /opt/; \
    ln -s /opt/ghidra_*/ghidraRun /usr/local/bin/ghidra; \
    ln -s /opt/ghidra_*/support/analyzeHeadless /usr/local/bin/analyzeHeadless; \
    rm /tmp/ghidra.zip) \
    || echo "WARN: ghidra install failed (rate limit or network), skipping"

# ── hashpump (hash length extension) ──
RUN retry-cmd 5 sh -c 'rm -rf /opt/hashpump && git clone --depth 1 https://github.com/leapsecurity/HashPump.git /opt/hashpump' \
    && cd /opt/hashpump \
    && make \
    && cp hashpump /usr/local/bin/ \
    || true

# ── ysoserial (Java deserialization gadget chains) ──
RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    mkdir -p /opt/ysoserial; \
    YSOSERIAL_URL="$(python3 /usr/local/bin/gh-latest-asset.py frohoff/ysoserial 'ysoserial-all.jar' '')"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$YSOSERIAL_URL" -O /opt/ysoserial/ysoserial.jar; \
    printf '#!/bin/sh\nexec java -jar /opt/ysoserial/ysoserial.jar "$@"\n' > /usr/local/bin/ysoserial; \
    chmod +x /usr/local/bin/ysoserial; \
    java -jar /opt/ysoserial/ysoserial.jar 2>&1 | head -1) \
    || echo "WARN: ysoserial install failed (rate limit or network), skipping"

# ── interactsh (OAST callback server) ──
# Asset name is "interactsh-client_<version>_linux_amd64.zip" — includes both
# the "-client" suffix and the version segment (ProjectDiscovery's standard
# toolname_version_os_arch convention across their whole suite), not the bare
# "interactsh-linux_amd64.zip" this used to glob for. Guarded with || true like
# the other nice-to-have (non-core) tools in this file (x8, prowler, falco) —
# a future asset-naming change on their end shouldn't block the whole image.
RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    INTERACTSH_URL="$(python3 /usr/local/bin/gh-latest-asset.py projectdiscovery/interactsh 'interactsh-client_*_linux_amd64.zip' '')"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$INTERACTSH_URL" -O /tmp/interactsh.zip; \
    unzip -q /tmp/interactsh.zip -d /tmp/interactsh; \
    install -m 0755 /tmp/interactsh/interactsh-client /usr/local/bin/interactsh-client; \
    rm -rf /tmp/interactsh /tmp/interactsh.zip; \
    interactsh-client -h 2>&1 | head -1) \
    || echo "WARN: interactsh-client install failed (rate limit or network), skipping"

# ── PHPGGC (PHP deserialization gadget chains) — needs a php CLI to run the
# generator itself; not installed anywhere else in this image, and the
# `|| true` on the verification line below would have silently hidden that
# gap (build succeeds, tool is dead at runtime) if left unadded. Its own
# small layer, not folded into the big categorized apt block above, so
# adding it doesn't invalidate that block's cache. ──
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    /usr/local/bin/apt-install-retry.sh 5 php-cli
RUN retry-cmd 5 sh -c 'rm -rf /opt/phpggc && git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc' \
    && printf '#!/bin/sh\nexec php /opt/phpggc/phpggc "$@"\n' > /usr/local/bin/phpggc \
    && chmod +x /usr/local/bin/phpggc \
    && php /opt/phpggc/phpggc --help 2>&1 | head -1 || true

# ── docker-bench-security ──
RUN retry-cmd 5 sh -c 'rm -rf /opt/docker-bench-security && git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security' \
    && ln -s /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

# ── kube-bench (CIS) — asset filename carries the version, so this uses the
# same latest/pin helper as terrascan/ghidra above. ──
ARG KUBE_BENCH_VERSION=""
RUN (set -eux; \
    KB_URL="$(python3 /usr/local/bin/gh-latest-asset.py aquasecurity/kube-bench '*_linux_amd64.tar.gz' "$KUBE_BENCH_VERSION")"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$KB_URL" -O /tmp/kube-bench.tar.gz; \
    tar xzf /tmp/kube-bench.tar.gz -C /usr/local/bin kube-bench; \
    rm /tmp/kube-bench.tar.gz) \
    || echo "WARN: kube-bench install failed (rate limit or network), skipping"

# ── clairctl (Clair) ──
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/quay/clair/cmd/clairctl@latest 2>/dev/null || true

# ── prowler (cloud — optional) — pipx-isolated like maigret/holehe/sslyze
# above: a system-wide `pip3 install prowler` was pulling down its own pins of
# aiohttp/beautifulsoup4/certifi/playwright/shodan/etc. into the SAME shared
# site-packages theHarvester's apt package depends on, silently downgrading/
# upgrading them out from under it. A standalone CLI never imported
# by other scripts, same as prowler — pipx's own venv is the right boundary. ──
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install prowler || true

# ── falco ──
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    /usr/local/bin/apt-install-retry.sh 5 falco || true

# ── scout-suite ──
RUN --mount=type=cache,target=/root/.cache/pip \
    retry-cmd 5 pip3 install --break-system-packages --no-build-isolation \
       git+https://github.com/nccgroup/ScoutSuite.git \
    || true

# ── libc-database — registered as libc_database_lookup in tool_registry.py /
# mcp-servers/binary/tools/libc_database_lookup.py, so this stays hard-required
# (no || true): if it's genuinely unreachable the build should fail loudly
# rather than silently ship a registered tool that doesn't work. ──
RUN retry-cmd 5 sh -c 'rm -rf /opt/libc-database && git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database' \
    && ln -s /opt/libc-database/libc-database.sh /usr/local/bin/libc-database

# ── python3 (already present from base) ──
RUN ln -sf /usr/bin/python3 /usr/bin/python

# ─── 6. Copy MCP servers ──────────────────────────────────────────────────────
# The mcp-servers/ directory is mounted as a volume in docker-compose. This
# step ensures the base Python environment can import mcp — needed for real:
# mcp_client.py's _start_in_docker() launches mcp-servers/<category>/server.py
# INSIDE this container via `docker exec -i ... python3 server.py` and speaks
# MCP JSON-RPC to it over stdio, so this isn't vestigial even though the
# faster run_argv() bash-command path bypasses it for most tool calls.
# Exact-pinned — this package previously drifted across 5 independent
# constraints in this repo (backend/requirements.txt, mcp-servers/
# requirements.txt, platform-mcp/requirements.txt, cli/pyproject.toml, and
# this line — two had no ceiling at all and could silently pull a breaking
# mcp 2.0 on a fresh build while the others stayed on 1.x). Bump ALL FIVE
# together, never just one.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip3 install --break-system-packages "mcp==1.28.1"

# ─── 6b. Make Go tools + PATH permanent for all shells / healthchecks ──────────
# Symlink into /usr/local/bin so login shells (`bash -lc`) still find tools when
# they reset PATH and drop Dockerfile ENV /opt/go/bin.
RUN find /opt/go/bin -type f -executable -exec bash -c \
      'for f; do ln -sfn "$f" "/usr/local/bin/$(basename "$f")"; done' _ {} + \
    && printf '%s\n' \
      'export GOPATH=/opt/go' \
      'export PATH="/opt/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH"' \
      > /etc/profile.d/99-pentest-tools.sh \
    && chmod 644 /etc/profile.d/99-pentest-tools.sh \
    && printf '%s\n' \
      'PATH="/opt/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
      > /etc/environment \
    && command -v subfinder \
    && command -v whois \
    && command -v rustscan \
    && command -v nmap \
    && command -v naabu \
    && command -v httpx \
    && command -v dnsx \
    && command -v tlsx \
    && command -v searchsploit

# ─── 6b. Raw-socket capabilities (unprivileged SYN / OS detection) ────────────
# The container runs as non-root mcpuser, so nmap -sS/-O and masscan/naabu
# otherwise fall back to slow connect scans (or fail -O entirely). File
# capabilities grant just the raw-socket rights they need without root. Docker's
# default capability bounding set keeps CAP_NET_RAW, so these take effect at
# runtime. `|| true` keeps the build resilient on filesystems without xattrs.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || true \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)" 2>/dev/null || true \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)" 2>/dev/null || true

# ─── 7. User setup ────────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash mcpuser \
    && chown -R mcpuser:mcpuser /opt/go/bin
USER mcpuser
WORKDIR /home/mcpuser

# Pre-fetch nuclei templates at build so the first scan doesn't block on a
# multi-minute download. Runs as mcpuser so templates land in its HOME.
RUN nuclei -update-templates || true

# MCP servers are mounted at /home/mcpuser/mcp-servers via docker-compose volume.
# The container stays alive; backend runs tools via:
#   docker exec -i osprey-kali python3 /home/mcpuser/mcp-servers/<cat>/server.py
CMD ["sleep", "infinity"]
