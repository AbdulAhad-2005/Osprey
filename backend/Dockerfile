FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system deps + the `docker` CLI for kali-tools communication (the
# backend shells out to `docker exec`/`docker container inspect` — see
# services/mcp_client.py — it never runs `docker compose` itself, so no
# compose plugin is needed here). Debian's own repo ships a `docker-cli`
# package, so this skips Docker's external apt repo entirely. The
# client being a version or two behind the daemon is fine: `docker exec`/
# `docker container inspect` are long-stable across the Engine API.
#
# python:3.12-slim's default sources (/etc/apt/sources.list.d/debian.sources)
# point at plain http://deb.debian.org — many corporate/ISP networks allow
# HTTPS but block or mangle unencrypted HTTP egress, which fails every apt-get
# here with no useful error (the retry loop below just exhausts and exits 1).
# Switching to https:// (apt >=1.5 / this image's apt 3.x supports it natively,
# no apt-transport-https package needed) costs nothing on a network where plain
# HTTP already worked and fixes it on one where it didn't.
RUN sed -i 's|http://deb\.debian\.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources
# Retries the whole update+install sequence on a transient mirror/network
# blip (a fresh `apt-get update` re-picks mirrors) instead of failing the
# build outright — same pattern as kali-tools/Dockerfile's apt-install-retry.
RUN n=0; \
    until apt-get update \
       && apt-get install -y --no-install-recommends \
          gcc libpq-dev curl ca-certificates docker-cli; do \
      n=$((n + 1)); \
      [ "$n" -ge 3 ] && exit 1; \
      echo "apt-get failed, retry $n/3 in $((n * 5))s..." >&2; \
      sleep $((n * 5)); \
    done \
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
# The shared ReAct loop lives in the top-level agent_core package (extracted
# from cli/agent); both the backend and the CLI import it, so it must be present
# and installed here — otherwise foreground_chat/agent_runner fail at import.
COPY agent_core /app/agent_core

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e . \
    && pip install --no-cache-dir -e /app/agent_core \
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
