# syntax=docker/dockerfile:1

################################################################################
# Osprey Kali toolbox image — multi-stage, parallel build.
#
# Stages (all build in parallel — each only depends on runtime-base):
#   runtime-base   OS + every apt package needed at runtime.
#   go-tools       Go-based tools            -> /opt/go/bin
#   cargo-tools    x8 (Rust)                 -> /opt/release-bin
#   python-venv    shared importable venv    -> /opt/osprey-python
#   pipx-tools     standalone CLI scanners, one pipx venv each -> /opt/pipx
#   release-tools  prebuilt GitHub release binaries
#   misc-git-tools remaining small source-built tools + one_gadget
#   final          assembles all of the above, sets up the user/caps/CMD
#
# Test a single stage without running the whole build:
#   docker build --target go-tools -t test-go ./kali-tools
#
# Don't use --no-cache for routine rebuilds — it throws away layer caching
# and re-does every apt/go/pip/cargo/git step from scratch.
################################################################################

ARG KALI_BASE_DIGEST=sha256:d2560fdc054793be92236322113fa231e609f95403dd68c613ca864b0d872b1f
# kali-rolling has no versioned tags, only a moving "latest" — pin by digest
# for reproducible builds; bump deliberately via --build-arg when needed.

################################################################################
# ─── Stage: runtime-base — everything that ships in the final image ─────────
################################################################################
FROM kalilinux/kali-rolling@${KALI_BASE_DIGEST} AS runtime-base

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/opt/go
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_NO_CACHE_DIR=0
ENV OSPREY_PYTHON=/opt/osprey-python
ENV PIPX_HOME=/opt/pipx
ENV PIPX_BIN_DIR=/opt/pipx/bin
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
ENV GEM_HOME=/opt/gems
# venv python first, then the backend's runtime pip-install-user dir (keep in
# sync with _KALI_EXEC_PATH in services/mcp_client.py), then pipx, then go.
ENV PATH="/opt/osprey-python/bin:/home/mcpuser/.local/bin:/opt/pipx/bin:${GOPATH}/bin:/usr/local/go/bin:/usr/local/bin:${PATH}"

# GCC here defaults to C23 (gnu23), which drops some legacy POSIX exposure;
# gnu17 keeps older C sources building without per-package patches.
ENV CFLAGS="-std=gnu17 -D_DEFAULT_SOURCE"
ENV CXXFLAGS="-std=gnu++17 -D_DEFAULT_SOURCE"

COPY <<'EOF' /etc/apt/apt.conf.d/99retries
Acquire::Retries "5";
EOF

COPY <<'EOF' /usr/local/bin/retry-cmd
#!/bin/sh
# retry-cmd N CMD...  -- run CMD, retrying up to N times with backoff.
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
RUN sed -i 's/\r$//' /usr/local/bin/retry-cmd && chmod +x /usr/local/bin/retry-cmd

COPY <<'EOF' /usr/local/bin/apt-install-retry.sh
#!/bin/sh
# apt-install-retry.sh N PKG...  -- apt-get update && install, retrying the
# whole sequence (fresh process => fresh DNS/mirror pick).
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

# GitHub release lookup used by release-tools. Unauthenticated calls are
# capped at 60/hour/IP; pass a token to raise that:
#   docker build --secret id=github_token,env=GITHUB_TOKEN ...
COPY <<'EOF' /usr/local/bin/gh-latest-asset.py
#!/usr/bin/env python3
"""Print the browser_download_url of a GitHub release asset matching a glob.
Usage: gh-latest-asset.py OWNER/REPO 'PATTERN' [TAG]  (TAG defaults to latest)
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

# Created early so downstream stages can COPY --chown=mcpuser:mcpuser
# straight into place instead of a slow `chown -R` at the end of the build.
RUN useradd -m -s /bin/bash mcpuser

# Base utilities. java/ruby/php are runtime deps of Ghidra, ysoserial, and
# one_gadget/phpggc respectively, not just build tools.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-install-retry.sh 5 \
       wget curl git ca-certificates gnupg unzip \
       python3 python3-pip python3-setuptools python3-wheel \
       libcap2-bin \
       ruby ruby-dev \
       openjdk-21-jdk-headless \
       php-cli

# The pentest toolset — most of the ~90 tools in one apt layer.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-install-retry.sh 5 \
    # Recon
    amass dnsenum fierce whois \
    # OSINT (passive)
    metagoofil theharvester dnstwist sherlock pipx \
    # Network
    nmap masscan naabu enum4linux enum4linux-ng smbmap \
    netexec nbtscan arp-scan responder samba-common-bin \
    net-tools iputils-ping dnsutils \
    # Web
    nikto whatweb sqlmap wafw00f wfuzz ffuf dirb dirsearch \
    wpscan xsser feroxbuster gobuster \
    dotdotpwn zaproxy \
    # Vulnerability
    nuclei \
    # Exploit lookup (offline Exploit-DB mirror + searchsploit, not Metasploit)
    exploitdb \
    # Credentials
    hydra john hashcat \
    # Binary
    gdb checksec binwalk radare2 ropper \
    # Forensics
    exiftool foremost steghide \
    # Reverse shells / netcat variants
    ncat socat \
    # Shell session persistence
    tmux \
    # Utilities
    binutils

# Own layer: ~1GB, the slowest single apt install. Not tolerant of failure —
# metasploit_run is a gated, expected-present tool.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-install-retry.sh 5 metasploit-framework

# falco is allowed to fail — some Kali snapshots don't carry it.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    apt-install-retry.sh 5 falco || true

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
    command -v whois >/dev/null 2>&1 || apt-install-retry.sh 5 whois

# Insurance for any script with a #!/usr/bin/python shebang.
RUN ln -sf /usr/bin/python3 /usr/bin/python

################################################################################
# ─── Stage: go-tools ──────────────────────────────────────────────────────────
################################################################################
FROM runtime-base AS go-tools
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked,id=apt-cache-go \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked,id=apt-lists-go \
    apt-install-retry.sh 5 golang-go

RUN mkdir -p /opt/go
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# The pip package `httpx` shadows this binary on PATH; alias it like Kali's
# own apt package does to avoid the collision.
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
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    retry-cmd 3 go install github.com/jaeles-project/jaeles@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/tomnomnom/qsreplace@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
# naabu comes from apt in runtime-base (its Go build needs libpcap headers
# and was unreliable). clairctl is best-effort.
RUN --mount=type=cache,target=/opt/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install github.com/quay/clair/cmd/clairctl@latest 2>/dev/null || true

RUN command -v subfinder && command -v httpx && command -v katana \
    && command -v gau && command -v waybackurls && command -v anew \
    && command -v hakrawler && command -v dalfox && command -v jaeles \
    && command -v qsreplace && command -v dnsx && command -v tlsx

################################################################################
# ─── Stage: cargo-tools ───────────────────────────────────────────────────────
################################################################################
FROM runtime-base AS cargo-tools
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked,id=apt-cache-cargo \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked,id=apt-lists-cargo \
    apt-install-retry.sh 5 build-essential cargo pkg-config

RUN mkdir -p /opt/release-bin
# x8 (hidden-parameter brute-forcer). Best-effort — degrades to "not found".
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    sh -c 'cargo install --root /tmp/cargo-out x8 && cp /tmp/cargo-out/bin/x8 /opt/release-bin/x8' \
    || echo "WARN: x8 build failed (tolerated)"

################################################################################
# ─── Stage: python-venv — the one venv shared project code IMPORTS from ─────
# Standalone CLIs nothing imports (checkov, kube-hunter, mitmproxy, ...) live
# in pipx-tools instead, so their pinned deps can't collide with these.
################################################################################
FROM runtime-base AS python-venv
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked,id=apt-cache-venv \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked,id=apt-lists-venv \
    apt-install-retry.sh 5 \
       build-essential cmake pkg-config libssl-dev libffi-dev \
       python3-dev python3-venv git

# Isolated from Kali's apt-managed Python — do NOT add --system-site-packages,
# --break-system-packages, or --ignore-installed to anything in this stage.
RUN rm -rf "$OSPREY_PYTHON" \
    && python3 -m venv "$OSPREY_PYTHON" \
    && "$OSPREY_PYTHON/bin/python" --version \
    && "$OSPREY_PYTHON/bin/python" -m pip --version \
    && "$OSPREY_PYTHON/bin/python" -m pip install --upgrade \
       "pip>=25.3" \
       "setuptools>=78,<81" \
       wheel

RUN --mount=type=cache,target=/root/.cache/pip \
    "$OSPREY_PYTHON/bin/python" -m pip install \
       pwntools \
       angr \
       volatility3

# domain-hunter deps (mcp-servers/recon/tools/domain-hunter)
RUN --mount=type=cache,target=/root/.cache/pip \
    "$OSPREY_PYTHON/bin/python" -m pip install \
       requests pyyaml openpyxl dnspython tldextract beautifulsoup4

# wappalyzer_scan.py / tech_stack_analyze.py import this via a bare
# `python3 -c "from Wappalyzer import ..."` subprocess call. Since
# /opt/osprey-python/bin is first on PATH, that resolves into this venv
# automatically — verify with: docker exec <container> which python3
RUN --mount=type=cache,target=/root/.cache/pip \
    "$OSPREY_PYTHON/bin/python" -m pip install python-Wappalyzer

RUN mkdir -p /opt/release-bin

# pacu (AWS exploitation). Tolerant — best-effort tool.
RUN --mount=type=cache,target=/root/.cache/pip \
    retry-cmd 5 sh -c 'rm -rf /opt/pacu && git clone --depth 1 https://github.com/RhinoSecurityLabs/pacu.git /opt/pacu' \
    && cd /opt/pacu \
    && "$OSPREY_PYTHON/bin/python" -m pip install . \
    && rm -rf /opt/pacu/.git \
    && printf '#!/bin/sh\nexec /opt/osprey-python/bin/python /opt/pacu/cli.py "$@"\n' > /opt/release-bin/pacu \
    && chmod +x /opt/release-bin/pacu \
    || true

# graphql-cop has no console entry point for pipx to use; clone + wrapper.
RUN --mount=type=cache,target=/root/.cache/pip \
    retry-cmd 5 sh -c 'rm -rf /opt/graphql-cop && git clone --depth 1 https://github.com/dolevf/graphql-cop.git /opt/graphql-cop' \
    && rm -rf /opt/graphql-cop/.git \
    && "$OSPREY_PYTHON/bin/python" -m pip install requests \
    && ( "$OSPREY_PYTHON/bin/python" -m pip install -r /opt/graphql-cop/requirements.txt || true ) \
    && printf '#!/bin/sh\nexec /opt/osprey-python/bin/python /opt/graphql-cop/graphql-cop.py "$@"\n' > /opt/release-bin/graphql-cop \
    && chmod +x /opt/release-bin/graphql-cop

# Playwright + Chromium. No system nodejs needed: pip's playwright package
# bundles its own driver. If `--with-deps` ever errors on a missing
# /usr/bin/node, add `apt-install-retry.sh 5 nodejs` above this.
RUN --mount=type=cache,target=/root/.cache/pip \
    "$OSPREY_PYTHON/bin/python" -m pip install playwright \
    && "$OSPREY_PYTHON/bin/python" -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/pw-browsers

# ScoutSuite (cloud). Tolerant — heavier/pinned deps, own layer for caching.
RUN --mount=type=cache,target=/root/.cache/pip \
    retry-cmd 5 "$OSPREY_PYTHON/bin/python" -m pip install --no-build-isolation \
       git+https://github.com/nccgroup/ScoutSuite.git \
    || true

# MCP servers must run under /opt/osprey-python/bin/python — this package
# isn't on system python3 anymore. Version pin is duplicated in
# backend/requirements.txt, mcp-servers/requirements.txt,
# platform-mcp/requirements.txt, cli/pyproject.toml — bump together.
RUN --mount=type=cache,target=/root/.cache/pip \
    "$OSPREY_PYTHON/bin/python" -m pip install "mcp==1.28.1" \
    && "$OSPREY_PYTHON/bin/python" -c "import mcp; print('MCP import: OK')" \
    && "$OSPREY_PYTHON/bin/python" -m pip show mcp

################################################################################
# ─── Stage: pipx-tools — one pipx venv per standalone scanner CLI ───────────
################################################################################
FROM runtime-base AS pipx-tools
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked,id=apt-cache-pipx \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked,id=apt-lists-pipx \
    apt-install-retry.sh 5 python3-venv python3-dev build-essential git
# python3-dev/build-essential: most of these are pure Python, but
# kube-hunter's `netifaces` dep has no prebuilt wheel for this Kali
# snapshot's Python and needs to compile from source.

# theHarvester/dnstwist/sherlock/metagoofil are real apt packages already
# (runtime-base) — these four aren't packaged, or the PyPI package is a
# dummy/placeholder.
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install maigret \
    && pipx install holehe \
    && pipx install social-analyzer \
    && retry-cmd 5 pipx install git+https://github.com/Tib3rius/AutoRecon.git

RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install sslyze

RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install mitmproxy

RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install prowler || true

# checkov/kube-hunter/arjun: invoked as subprocess CLIs elsewhere in this
# project, not imported as libraries, so pipx isolation is safe here (same
# as mitmproxy/sslyze/prowler above). Kept as separate RUNs so one failing
# doesn't block or hide the others.
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install checkov
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install kube-hunter
RUN --mount=type=cache,target=/root/.cache/pip \
    pipx install arjun

################################################################################
# ─── Stage: release-tools — prebuilt GitHub release binaries ────────────────
################################################################################
FROM runtime-base AS release-tools
ARG PHONEINFOGA_VERSION=""
ARG TERRASCAN_VERSION=""
ARG GHIDRA_VERSION=""
ARG KUBE_BENCH_VERSION=""

RUN mkdir -p /opt/release-bin

# PhoneInfoga — `go install` fails (v2's web UI needs go:embed assets not in
# the module), so use the prebuilt release instead.
RUN set -eux; \
    if [ -n "$PHONEINFOGA_VERSION" ]; then \
      PIF_URL="https://github.com/sundowndev/phoneinfoga/releases/download/${PHONEINFOGA_VERSION}/phoneinfoga_Linux_x86_64.tar.gz"; \
    else \
      PIF_URL="https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_x86_64.tar.gz"; \
    fi; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$PIF_URL" -O /tmp/phoneinfoga.tar.gz; \
    tar -xzf /tmp/phoneinfoga.tar.gz -C /tmp phoneinfoga; \
    install -m 0755 /tmp/phoneinfoga /opt/release-bin/phoneinfoga; \
    rm -f /tmp/phoneinfoga.tar.gz /tmp/phoneinfoga; \
    /opt/release-bin/phoneinfoga version

# terrascan — real tool ships only as a Go binary; the PyPI package of the
# same name is an unrelated, abandoned project.
RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    TS_URL="$(python3 /usr/local/bin/gh-latest-asset.py tenable/terrascan '*_Linux_x86_64.tar.gz' "$TERRASCAN_VERSION")"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$TS_URL" -O /tmp/terrascan.tar.gz; \
    tar -xzf /tmp/terrascan.tar.gz -C /tmp terrascan; \
    install -m 0755 /tmp/terrascan /opt/release-bin/terrascan; \
    rm -f /tmp/terrascan.tar.gz /tmp/terrascan; \
    /opt/release-bin/terrascan version) \
    || echo "WARN: terrascan install failed, skipping"

# Ghidra headless — needs the JDK from runtime-base; bundles none of its own.
RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    GH_URL="$(python3 /usr/local/bin/gh-latest-asset.py NationalSecurityAgency/ghidra '*.zip' "$GHIDRA_VERSION")"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$GH_URL" -O /tmp/ghidra.zip; \
    unzip -q /tmp/ghidra.zip -d /opt/; \
    mv /opt/ghidra_* /opt/ghidra; \
    rm /tmp/ghidra.zip) \
    || echo "WARN: ghidra install failed, skipping"

RUN (set -eux; \
    KB_URL="$(python3 /usr/local/bin/gh-latest-asset.py aquasecurity/kube-bench '*_linux_amd64.tar.gz' "$KUBE_BENCH_VERSION")"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$KB_URL" -O /tmp/kube-bench.tar.gz; \
    tar xzf /tmp/kube-bench.tar.gz -C /opt/release-bin kube-bench; \
    rm /tmp/kube-bench.tar.gz) \
    || echo "WARN: kube-bench install failed, skipping"

RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    INTERACTSH_URL="$(python3 /usr/local/bin/gh-latest-asset.py projectdiscovery/interactsh 'interactsh-client_*_linux_amd64.zip' '')"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$INTERACTSH_URL" -O /tmp/interactsh.zip; \
    unzip -q /tmp/interactsh.zip -d /tmp/interactsh; \
    install -m 0755 /tmp/interactsh/interactsh-client /opt/release-bin/interactsh-client; \
    rm -rf /tmp/interactsh /tmp/interactsh.zip; \
    /opt/release-bin/interactsh-client -h 2>&1 | head -1) \
    || echo "WARN: interactsh-client install failed, skipping"

RUN --mount=type=secret,id=github_token,required=false \
    (set -eux; \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)"; \
    mkdir -p /opt/ysoserial; \
    YSOSERIAL_URL="$(python3 /usr/local/bin/gh-latest-asset.py frohoff/ysoserial 'ysoserial-all.jar' '')"; \
    wget -q --tries=5 --waitretry=5 --timeout=30 "$YSOSERIAL_URL" -O /opt/ysoserial/ysoserial.jar; \
    printf '#!/bin/sh\nexec java -jar /opt/ysoserial/ysoserial.jar "$@"\n' > /opt/release-bin/ysoserial; \
    chmod +x /opt/release-bin/ysoserial; \
    java -jar /opt/ysoserial/ysoserial.jar 2>&1 | head -1) \
    || echo "WARN: ysoserial install failed, skipping"

################################################################################
# ─── Stage: misc-git-tools ────────────────────────────────────────────────────
################################################################################
FROM runtime-base AS misc-git-tools
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked,id=apt-cache-misc \
    --mount=type=cache,target=/var/lib/apt/lists,sharing=locked,id=apt-lists-misc \
    apt-install-retry.sh 5 build-essential

RUN mkdir -p /opt/release-bin /opt/gems

# hashpump: only the compiled binary is kept; source tree is discarded.
RUN retry-cmd 5 sh -c 'rm -rf /opt/hashpump && git clone --depth 1 https://github.com/leapsecurity/HashPump.git /opt/hashpump' \
    && cd /opt/hashpump \
    && make \
    && cp hashpump /opt/release-bin/hashpump \
    && rm -rf /opt/hashpump \
    || true

# phpggc: the cloned repo IS the tool, so it has to stay (minus .git).
RUN retry-cmd 5 sh -c 'rm -rf /opt/phpggc && git clone --depth 1 https://github.com/ambionics/phpggc.git /opt/phpggc' \
    && rm -rf /opt/phpggc/.git \
    && printf '#!/bin/sh\nexec php /opt/phpggc/phpggc "$@"\n' > /opt/release-bin/phpggc \
    && chmod +x /opt/release-bin/phpggc \
    && php /opt/phpggc/phpggc --help 2>&1 | head -1 || true

RUN retry-cmd 5 sh -c 'rm -rf /opt/docker-bench-security && git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security' \
    && rm -rf /opt/docker-bench-security/.git

RUN retry-cmd 5 sh -c 'rm -rf /opt/libc-database && git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database' \
    && rm -rf /opt/libc-database/.git

# The repo has no single "libc-database.sh" entrypoint — separate scripts
# (get/add/find/dump/identify/download). Dispatcher so `libc-database find
# ...` works as one command on PATH.
COPY <<'EOF' /opt/release-bin/libc-database
#!/bin/sh
# Usage: libc-database <get|add|find|dump|identify|download> [args...]
sub="$1"; shift
cd /opt/libc-database && exec ./"$sub" "$@"
EOF
RUN chmod +x /opt/release-bin/libc-database

# one_gadget — clean install paths so this stage's output is just a COPY.
RUN gem install one_gadget --install-dir /opt/gems --bindir /opt/release-bin --no-document

################################################################################
# ─── Stage: final — assembles every stage above ──────────────────────────────
################################################################################
FROM runtime-base AS final
ARG RUSTSCAN_VERSION=""

# rustscan ships as a .deb that scatters files via dpkg, so it's simplest to
# just apt-install it here rather than extract it from a side stage.
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

# Pull in every parallel stage's output, pre-owned by mcpuser.
COPY --from=go-tools      --chown=mcpuser:mcpuser /opt/go/bin        /opt/go/bin
COPY --from=cargo-tools   --chown=mcpuser:mcpuser /opt/release-bin/. /usr/local/bin/
COPY --from=python-venv   --chown=mcpuser:mcpuser /opt/osprey-python /opt/osprey-python
COPY --from=python-venv   --chown=mcpuser:mcpuser /opt/pw-browsers   /opt/pw-browsers
COPY --from=python-venv   --chown=mcpuser:mcpuser /opt/pacu          /opt/pacu
COPY --from=python-venv   --chown=mcpuser:mcpuser /opt/graphql-cop   /opt/graphql-cop
COPY --from=python-venv   --chown=mcpuser:mcpuser /opt/release-bin/. /usr/local/bin/
COPY --from=pipx-tools    --chown=mcpuser:mcpuser /opt/pipx          /opt/pipx
COPY --from=release-tools --chown=mcpuser:mcpuser /opt/release-bin/. /usr/local/bin/
COPY --from=release-tools --chown=mcpuser:mcpuser /opt/ghidra        /opt/ghidra
COPY --from=release-tools --chown=mcpuser:mcpuser /opt/ysoserial     /opt/ysoserial
COPY --from=misc-git-tools --chown=mcpuser:mcpuser /opt/release-bin/. /usr/local/bin/
COPY --from=misc-git-tools --chown=mcpuser:mcpuser /opt/phpggc                /opt/phpggc
COPY --from=misc-git-tools --chown=mcpuser:mcpuser /opt/docker-bench-security /opt/docker-bench-security
COPY --from=misc-git-tools --chown=mcpuser:mcpuser /opt/libc-database         /opt/libc-database
COPY --from=misc-git-tools --chown=mcpuser:mcpuser /opt/gems                  /opt/gems

RUN ln -s /opt/ghidra/ghidraRun /usr/local/bin/ghidra \
    && ln -s /opt/ghidra/support/analyzeHeadless /usr/local/bin/analyzeHeadless \
    && ln -s /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

# Belt-and-suspenders symlinks into /usr/local/bin so a login shell that
# resets PATH still finds go/pipx tools.
RUN set -eux; \
    for f in /opt/go/bin/*; do \
        [ -x "$f" ] && [ -f "$f" ] && ln -sfn "$f" "/usr/local/bin/$(basename "$f")"; \
    done; \
    for f in /opt/pipx/bin/*; do \
        [ -x "$f" ] && [ -f "$f" ] && ln -sfn "$f" "/usr/local/bin/$(basename "$f")"; \
    done; \
    printf '%s\n' \
      'export GOPATH=/opt/go' \
      'export PATH="/opt/osprey-python/bin:/opt/pipx/bin:/opt/go/bin:/usr/local/go/bin:/usr/local/bin:$PATH"' \
      > /etc/profile.d/99-pentest-tools.sh; \
    chmod 644 /etc/profile.d/99-pentest-tools.sh; \
    printf '%s\n' \
      'PATH="/opt/osprey-python/bin:/opt/pipx/bin:/opt/go/bin:/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' \
      > /etc/environment

# Raw-socket caps for unprivileged nmap -sS/-O and masscan/naabu. Runs here
# (not copied from elsewhere) since capability xattrs aren't guaranteed to
# survive a cross-stage COPY.
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)" || true \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v masscan)" 2>/dev/null || true \
    && setcap cap_net_raw,cap_net_admin+eip "$(command -v naabu)" 2>/dev/null || true

# Fail the build if a REQUIRED tool is missing; only warn for tools whose own
# install step already tolerates failure (x8, prowler, pacu, hashpump,
# ysoserial, ghidra, terrascan, kube-bench, interactsh-client, clairctl).
RUN set -eu; \
    "$OSPREY_PYTHON/bin/python" -c "import mcp" && echo "OK mcp" || { echo "MISSING mcp"; exit 1; }; \
    "$OSPREY_PYTHON/bin/python" -c "from Wappalyzer import Wappalyzer" && echo "OK Wappalyzer" || { echo "MISSING Wappalyzer"; exit 1; }; \
    for t in subfinder httpx httpx-toolkit katana gau waybackurls anew hakrawler dalfox jaeles qsreplace dnsx tlsx \
             whois rustscan nmap naabu searchsploit maigret holehe sslyze mitmdump checkov kube-hunter arjun \
             graphql-cop phpggc docker-bench-security libc-database one_gadget; do \
        command -v "$t" >/dev/null || { echo "MISSING required tool: $t"; exit 1; }; \
    done; \
    for t in x8 prowler pacu hashpump ysoserial ghidra analyzeHeadless terrascan kube-bench interactsh-client clairctl; do \
        command -v "$t" >/dev/null && echo "OK (optional) $t" || echo "WARN: optional tool missing: $t"; \
    done

USER mcpuser
WORKDIR /home/mcpuser

RUN nuclei -update-templates || true

# MCP servers are mounted at /home/mcpuser/mcp-servers and run via:
#   docker exec -i osprey-kali /opt/osprey-python/bin/python /home/mcpuser/mcp-servers/<cat>/server.py
CMD ["sleep", "infinity"]