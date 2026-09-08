---
name: chunked-scans
description: "Keep the session moving: push long probes into background jobs and split large host lists into shortlists/batches, inventing chunk size from evidence and scope."
phases: [shared]
tags: [methodology, parallelism, jobs]
---

# Chunked / parallel scans (skill — not a stage script)

Elite operators keep the chat moving. Long probes belong in **jobs**; large host
lists get **shortlists + batches**. You invent the chunk size from evidence and
scope — the platform does not auto-start work.

## When to branch

- Tool will take minutes (amass, rustscan, nmap service, bulk httpx, heavy scripts)
- You have other assets to touch while waiting
- Soft **Parallel note** on an exec card → optional `platform_job_start`

Never treat the note as an order. Max concurrent jobs = `config/parallelism.yaml`
(`max_running_jobs`, default 4). Poll before starting more.

## Chunked port / host sketch

Wide `1-65535` / `-p-` ranges auto-chunk into background jobs (no gate); a full sweep runs directly. Prefer narrow ranges for speed.

```python
# platform_script — adapt IPs and port sets yourself
ips = """10.0.0.1
10.0.0.2
""".strip().splitlines()
chunk = 5
ports = "80,443,8080,8443"  # narrow from evidence / user scope
for i in range(0, len(ips), chunk):
    batch = ",".join(ips[i : i + chunk])
    print(f"FINDING|inferred|info|observation|chunk {i//chunk+1}|hosts={batch} ports={ports}")
    # Prefer platform_job_start(nmap_*) per chunk from chat — or shell one binary here
```

Or: `platform_fanout_assets` on a **chosen** shortlist (dry-run first).

## Loop

1. `platform_context` → read `jobs: n/max running […]` and current phase readiness
2. Start ≤ max jobs; keep working other assets in parallel
3. `platform_job_poll` / `platform_job_result` when a branch finishes
4. Narrate — never silent-wait on one linear scan when the surface is wide
