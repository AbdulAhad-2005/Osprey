FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps + Docker CLI for kali-tools communication
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       gcc libpq-dev curl \
       apt-transport-https ca-certificates gnupg lsb-release \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
       https://download.docker.com/linux/debian $(lsb_release -cs) stable" \
       > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce-cli docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

COPY backend/pyproject.toml backend/requirements.txt /app/
COPY backend/src /app/src

# The CLI's own agent loop (cli/agent/) and its embedded platform-mcp gateway
# (platform-mcp/) — services/agent_runner.py runs a headless instance of that
# SAME loop for every backend-spawned scoped agent, rather than a second,
# independently-coded backend loop. Build context is the repo root (see
# docker-compose.yml) specifically so these two sibling directories are
# reachable here; backend/requirements.txt already pins litellm/mcp/httpx/
# prompt_toolkit identically to cli/requirements.txt for exactly this reason.
COPY cli /app/cli
COPY platform-mcp /app/platform-mcp

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e . \
    && pip install --no-cache-dir -e /app/cli

# Keyless Python-tool runtime deps (the light set from mcp-servers/requirements.txt).
# Installing them here means the custom Python tools (domain_hunter, js_recon, subdomain_takeover,
# web_contact_harvest, email_permute, dnstwist, tech/wappalyzer helpers, ...) run in
# native fallback out of the box. Compiled scanners (nmap/subfinder/httpx/nuclei) still
# come from the Kali profile or your host (locally) — /tools shows what's present.
# google-generativeai: the default LLM_MODEL is gemini/*, which LiteLLM cannot call
# without it — so the stock config works out of the box instead of erroring.
RUN pip install --no-cache-dir \
       requests dnspython "tldextract>=5.0,<6.0" beautifulsoup4 pyyaml openpyxl \
       google-generativeai

EXPOSE 9000

CMD ["uvicorn", "osprey.main:app", "--host", "0.0.0.0", "--port", "9000", "--reload"]
