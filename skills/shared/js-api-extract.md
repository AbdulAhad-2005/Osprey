# JS / API route extract (script convention)

When catalog tools only give titles/ports, **invent** a probe with `platform_script`.
Do not wait for a dedicated agent. Print structured lines so memory + graph update.

## Pattern

1. Fetch the HTML shell or `main.*.js` / `app.*.js` for a crown-jewel host.
2. Extract path-like strings (`/api`, `/rest`, `/v1`, `/graphql`, `/backend`).
3. Optionally probe a shortlist and print status + body grade.

## Stdout markers (land in graph)

```text
FINDING|inferred|info|url|/api/v1/users|seen in main.js
FINDING|observed|medium|url|https://host/api/health|200 application/json {...}
PATH /api/v1/users
REL|inferred|host:erp.example|likely_same_app|host:ess.example|shared JS bundle hash
HYPOTHESIS|SPA shell on /api — need JSON Content-Type before HIGH
```

Ingest rules also pick up conservative `js_route_hint` patterns automatically.
SPA HTML on `/api` stays demoted (`spa_catchall_suspect`) until JSON proof.

## Smoke sketch (adapt — do not treat as a fixed playbook)

```python
import re, urllib.request
url = "https://TARGET/"  # set by you
html = urllib.request.urlopen(url, timeout=20).read().decode("utf-8", "replace")
for m in re.findall(r'["\'](/(?:api|rest|v\d+|graphql|backend)[^"\']{2,80})["\']', html):
    print(f"FINDING|inferred|info|url|{m}|from HTML/JS string")
    print(f"PATH {m}")
```

Use `packages='beautifulsoup4'` only if stdlib is not enough.
Confirm interesting links with `platform_graph_link` when you believe them.
