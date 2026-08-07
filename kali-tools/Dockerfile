FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/opt/go
# Keep /home/mcpuser/.local/bin on PATH so pipx shims and any runtime
# `pip install --user` OSINT tools resolve in non-login `docker exec` shells.
# Mirrors _KALI_EXEC_PATH in backend services/mcp_client.py.
ENV PATH="/home/mcpuser/.local/bin:${GOPATH}/bin:/usr/local/go/bin:${PATH}"

# ─── System base ───────────────────────────────────────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       wget curl git ca-certificates gnupg unzip \
       python3 python3-pip python3-venv python3-dev python3-setuptools python3-wheel \
       build-essential libssl-dev libffi-dev \
       libcap2-bin \
       ruby ruby-dev \
       golang-go \
    && rm -rf /var/lib/apt/lists/*

# ─── 1. Kali apt packages ──────────────────────────────────────────────────────
# Covers the majority of the 90 tools in one layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
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
    # ── Binary ──
    gdb checksec binwalk radare2 \
    # ── Forensics ──
    exiftool foremost steghide \
    # ── Utilities ──
    binutils \
    && rm -rf /var/lib/apt/lists/*

# ─── 2. Kali metasploit (~1 GB) ────────────────────────────────────────────────
# metasploit_run (mcp-servers/exploit/metasploit_run.py) is registered GATED
# in tool_registry.py — this makes that registration real instead of dead code.
RUN apt-get update \
    && apt-get install -y --no-install-recommends metasploit-framework \
    && rm -rf /var/lib/apt/lists/*

# ─── 3. Go tools (install individually for build resilience) ─────────────────
RUN mkdir -p /opt/go
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/hakluke/hakrawler@latest
RUN go install github.com/hahwul/dalfox/v2@latest
# jaeles — signature-based web vuln scanner (jaeles_vulnerability_scan). Was
# registered in the platform but missing from the image ("jaeles: command not found").
RUN go install github.com/jaeles-project/jaeles@latest
# x8 — hidden-parameter brute-forcer (Rust). Built via cargo; guarded so a slow
# or failing build doesn't break the image (the tool degrades to "not found",
# which the platform's recovery handles).
RUN apt-get update \
    && apt-get install -y --no-install-recommends cargo \
    && (cargo install --root /usr/local x8 || true) \
    && rm -rf /var/lib/apt/lists/*
RUN go install github.com/tomnomnom/qsreplace@latest
RUN go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest
# naabu is installed via apt above (the Go build needs libpcap headers and was
# unreliable); apt ships a working 2.6.x binary on the system PATH.
# PhoneInfoga (passive phone-number OSINT) — installed from the prebuilt release.
# `go install` fails: phoneinfoga v2 embeds its web UI via go:embed (client/dist/*),
# which is not present in the Go module, so the build errors out.
RUN set -eux; \
    PIF_VER="2.11.0"; \
    wget -q "https://github.com/sundowndev/phoneinfoga/releases/download/v${PIF_VER}/phoneinfoga_Linux_x86_64.tar.gz" -O /tmp/phoneinfoga.tar.gz; \
    tar -xzf /tmp/phoneinfoga.tar.gz -C /tmp phoneinfoga; \
    install -m 0755 /tmp/phoneinfoga /usr/local/bin/phoneinfoga; \
    rm -f /tmp/phoneinfoga.tar.gz /tmp/phoneinfoga; \
    phoneinfoga version

# ─── 4. Python pip tools ──────────────────────────────────────────────────────
RUN pip3 install --break-system-packages --no-cache-dir --ignore-installed \
       pwntools \
       angr \
       ropper \
       checkov \
       terrascan \
       kube-hunter \
       autorecon \
       arjun \
       volatility3

# ─── 4b. domain-hunter deps (mcp-servers/recon/tools/domain-hunter) ──────────
RUN pip3 install --break-system-packages --no-cache-dir \
       requests pyyaml openpyxl dnspython tldextract beautifulsoup4

# ─── 4b2. Passive-OSINT python tools NOT packaged in Kali apt ─────────────────
# theHarvester/dnstwist/sherlock/metagoofil come from apt above (the PyPI
# "theHarvester" is a 0.0.1 placeholder — do NOT pip it). Only maigret, holehe
# and social-analyzer are unpackaged; install each in its OWN pipx venv so their
# heavy/pinned deps cannot conflict with netexec/pacu/awscli/checkov/etc. pipx
# symlinks the CLI into /usr/local/bin (on PATH for every exec path).
# web_contact_harvest / email_permute are bundled scripts using the 4b deps.
ENV PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin
RUN pipx install maigret \
    && pipx install holehe \
    && pipx install social-analyzer

# ─── 4b3. Wappalyzer python lib ───────────────────────────────────────────────
# wappalyzer_scan.py and tech_stack_analyze.py run `python3 -c "from Wappalyzer
# import Wappalyzer, WebPage"`, so the lib must be importable by the SYSTEM
# python3 (NOT a pipx venv). Without it both tools raise ModuleNotFoundError.
RUN pip3 install --break-system-packages --no-cache-dir python-Wappalyzer

# ─── 4b4. Web-pentest additions (TLS deep + GraphQL) ─────────────────────────
# sslyze (WSTG-CRYP: protocols/ciphers/cert/TLS-CVEs) and graphql-cop (GraphQL
# security checks) — each in its own pipx venv to isolate pinned deps; the CLI
# lands on /usr/local/bin (on PATH for every exec path).
RUN pipx install sslyze \
    && pipx install graphql-cop

# ─── 4b5. Playwright browser automation (browser_scrape / browser_flow) ───────
# Installed for the SYSTEM python3 (the browser CLIs `import playwright` directly,
# so a pipx venv would be invisible to them). Chromium + its OS deps land in a
# world-readable shared path so the non-root mcpuser can drive it at runtime.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers
RUN pip3 install --break-system-packages --no-cache-dir playwright \
    && python3 -m playwright install --with-deps chromium \
    && chmod -R a+rX /opt/pw-browsers

# ─── 4c. Ruby gem tools ──────────────────────────────────────────────────────
RUN gem install one_gadget

# ─── 5. GitHub / binary installs ──────────────────────────────────────────────

# whois is also in the apt recon layer above; this late install is a safety net
# for cached builds that predate that package.
RUN command -v whois >/dev/null 2>&1 || (apt-get update \
    && apt-get install -y --no-install-recommends whois \
    && rm -rf /var/lib/apt/lists/*)

# ── rustscan (prebuilt release — cargo is slow/flaky; fail the build if missing) ──
RUN set -eux; \
    mkdir -p /tmp/rustscan; \
    wget -q "https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip" \
      -O /tmp/rustscan/rustscan.deb.zip; \
    unzip -q /tmp/rustscan/rustscan.deb.zip -d /tmp/rustscan; \
    apt-get update; \
    DEB="$(find /tmp/rustscan -name 'rustscan_*.deb' | head -n1)"; \
    test -n "$DEB"; \
    apt-get install -y --no-install-recommends "$DEB"; \
    command -v rustscan; \
    rm -rf /tmp/rustscan /var/lib/apt/lists/*

# ── pacu (AWS exploitation) ──
RUN git clone --depth 1 https://github.com/RhinoSecurityLabs/pacu.git /opt/pacu \
    && cd /opt/pacu \
    && pip3 install --break-system-packages --no-cache-dir . \
    && ln -s /opt/pacu/cli.py /usr/local/bin/pacu \
    || true

# ── ghidra (headless) ──
RUN GHIDRA_TAG="Ghidra_12.1.2_build" \
    && GHIDRA_FILE="ghidra_12.1.2_PUBLIC_20260605.zip" \
    && wget -q "https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_TAG}/${GHIDRA_FILE}" \
       -O /tmp/ghidra.zip \
    && unzip -q /tmp/ghidra.zip -d /opt/ \
    && ln -s /opt/ghidra_*/ghidraRun /usr/local/bin/ghidra \
    && ln -s /opt/ghidra_*/support/analyzeHeadless /usr/local/bin/analyzeHeadless \
    && rm /tmp/ghidra.zip \
    || true

# ── hashpump (hash length extension) ──
RUN git clone --depth 1 https://github.com/leapsecurity/HashPump.git /opt/hashpump \
    && cd /opt/hashpump \
    && make \
    && cp hashpump /usr/local/bin/ \
    || true

# ── docker-bench-security ──
RUN git clone --depth 1 https://github.com/docker/docker-bench-security.git /opt/docker-bench-security \
    && ln -s /opt/docker-bench-security/docker-bench-security.sh /usr/local/bin/docker-bench-security

# ── kube-bench (CIS) ──
RUN wget -q https://github.com/aquasecurity/kube-bench/releases/download/v0.9.3/kube-bench_0.9.3_linux_amd64.tar.gz -O /tmp/kube-bench.tar.gz \
    && tar xzf /tmp/kube-bench.tar.gz -C /usr/local/bin kube-bench \
    && rm /tmp/kube-bench.tar.gz

# ── clairctl (Clair) ──
RUN go install github.com/quay/clair/cmd/clairctl@latest 2>/dev/null || true

# ── prowler (cloud — optional; pip/debian pytz conflict on Kali) ──
RUN pip3 install --break-system-packages --no-cache-dir prowler || true

# ── falco ──
RUN apt-get update \
    && apt-get install -y --no-install-recommends falco || true \
    && rm -rf /var/lib/apt/lists/*

# ── scout-suite ──
RUN pip3 install --break-system-packages --no-cache-dir --no-build-isolation \
       git+https://github.com/nccgroup/ScoutSuite.git \
    || true

# ── libc-database ──
RUN git clone --depth 1 https://github.com/niklasb/libc-database.git /opt/libc-database \
    && ln -s /opt/libc-database/libc-database.sh /usr/local/bin/libc-database

# ── python3 (already present from base) ──
RUN ln -sf /usr/bin/python3 /usr/bin/python

# ─── 6. Copy MCP servers ──────────────────────────────────────────────────────
# The mcp-servers/ directory is mounted as a volume in docker-compose.
# This step ensures the base Python environment can import mcp.
RUN pip3 install --break-system-packages --no-cache-dir mcp>=1.2.0

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
# multi-minute download (and severity filters aren't silently empty until the
# template set exists). Runs as mcpuser so templates land in its HOME.
RUN nuclei -update-templates || true

# MCP servers are mounted at /home/mcpuser/mcp-servers via docker-compose volume.
# The container stays alive; backend runs tools via:
#   docker exec -i ai-pentest-kali python3 /home/mcpuser/mcp-servers/<cat>/server.py
CMD ["sleep", "infinity"]
