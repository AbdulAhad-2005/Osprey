FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive
ENV GOPATH=/opt/go
ENV PATH="${GOPATH}/bin:/usr/local/go/bin:${PATH}"

# ─── System base ───────────────────────────────────────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       wget curl git ca-certificates gnupg unzip \
       python3 python3-pip python3-venv python3-dev python3-setuptools python3-wheel \
       build-essential libssl-dev libffi-dev \
       ruby ruby-dev \
       golang-go \
    && rm -rf /var/lib/apt/lists/*

# ─── 1. Kali apt packages ──────────────────────────────────────────────────────
# Covers the majority of the 90 tools in one layer.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    # ── Recon ──
    amass dnsenum fierce \
    # ── Network ──
    nmap masscan enum4linux smbmap \
    nbtscan arp-scan responder samba-common-bin \
    net-tools iputils-ping dnsutils \
    # ── Web ──
    nikto sqlmap wafw00f wfuzz ffuf dirb dirsearch \
    wpscan xsser feroxbuster gobuster \
    dotdotpwn zaproxy \
    # ── Vulnerability ──
    nuclei \
    # ── Credentials ──
    hydra john hashcat \
    # ── Binary ──
    gdb checksec binwalk radare2 \
    # ── Forensics ──
    exiftool foremost steghide \
    # ── Utilities ──
    binutils \
    && rm -rf /var/lib/apt/lists/*

# ─── 2. Kali metasploit (optional, skip in small image) ───────────────────────
# Uncomment if you want the full metasploit framework (~1 GB).
# RUN apt-get update \
#     && apt-get install -y --no-install-recommends metasploit-framework \
#     && rm -rf /var/lib/apt/lists/*

# ─── 3. Go tools (install individually for build resilience) ─────────────────
RUN mkdir -p /opt/go
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN go install github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
RUN go install github.com/lc/gau/v2/cmd/gau@latest
RUN go install github.com/tomnomnom/waybackurls@latest
RUN go install github.com/tomnomnom/anew@latest
RUN go install github.com/hakluke/hakrawler@latest
RUN go install github.com/hahwul/dalfox/v2@latest
RUN go install github.com/tomnomnom/qsreplace@latest

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

# ─── 4b. Ruby gem tools ──────────────────────────────────────────────────────
RUN gem install one_gadget

# ─── 5. GitHub / binary installs ──────────────────────────────────────────────

# ── rustscan ──
RUN cargo install rustscan 2>/dev/null || \
    (apt-get update && apt-get install -y --no-install-recommends cargo \
     && cargo install rustscan && rm -rf /var/lib/apt/lists/*) || true

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

# ── prowler ──
RUN pip3 install --break-system-packages --no-cache-dir prowler

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

# ─── 7. User setup ────────────────────────────────────────────────────────────
RUN useradd -m -s /bin/bash mcpuser \
    && chown -R mcpuser:mcpuser /opt/go
USER mcpuser
WORKDIR /home/mcpuser

# MCP servers are mounted at /home/mcpuser/mcp-servers via docker-compose volume.
# The container stays alive; backend runs tools via:
#   docker exec -i ai-pentest-kali python3 /home/mcpuser/mcp-servers/<cat>/server.py
CMD ["sleep", "infinity"]
