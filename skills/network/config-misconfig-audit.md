---
name: config-misconfig-audit
description: Locate and read common service configuration files on a host (SSH, Samba, web servers, databases, FTP, NFS, Redis, Docker, sudoers, cron, systemd units) and flag misconfigurations against known-insecure patterns. Use this whenever you have local file read access to a target (post-exploitation, a provided host, or a local/internal engagement) and need a systematic config-hardening review rather than a network-only scan.
phase: vuln
tags: [vuln, config-review, misconfig, local-audit, hardening, ssh, samba, web, database]
---

# Config Misconfiguration Audit

## When to use this skill
Trigger this once you have **local read access** to a filesystem — via an
authenticated session, a provided box for a config-review engagement, an
agent shell, or a container you're allowed to inspect. This is a read-only
review skill: it never edits, exploits, or restarts a service. It produces
a findings list an operator can hand to a client or feed into the exploit
phase as leads (e.g. "SSH allows password root login" -> credential attack
surface).

## Method
1. **Discover what's actually running first.** Don't blindly check every
   path below — cross-reference with `ss -tulpn` / `netstat -tulpn`,
   `systemctl list-units --type=service --state=running`, or the process
   list, so findings are tied to services that matter on this host.
2. **Locate config files.** For each running service, resolve its real
   config path (services are often started with `-c <path>` or a
   non-default `/etc/<service>/` layout) rather than assuming the default.
3. **Read, don't parse blindly.** Grep for the specific directives below;
   note the file path and line number for each finding so it's reproducible.
4. **Check file/dir permissions**, not just content — a correctly configured
   file that's world-writable or world-readable (secrets) is itself a finding.
5. **Rate severity** (Critical/High/Medium/Low/Info) based on exploitability
   from the current access level, not just "deviates from best practice."
6. **Record every finding** with: file path, directive/line, current value,
   why it's risky, and the safe/expected value — this is what turns a config
   read into an actionable finding rather than a raw file dump.

## SSH — `/etc/ssh/sshd_config` (and `sshd_config.d/*.conf`)
| Directive | Flag if | Risk |
|---|---|---|
| `PermitRootLogin` | `yes` (not `prohibit-password`/`no`) | Direct root login target |
| `PasswordAuthentication` | `yes` on an internet-facing host | Brute-force / credential-stuffing surface |
| `PermitEmptyPasswords` | `yes` | Trivial auth bypass |
| `Protocol` | `1` or missing (very old) | Broken cipher/legacy protocol |
| `X11Forwarding` | `yes` unnecessarily | Local privilege/pivot vector |
| `AllowTcpForwarding` / `GatewayPorts` | `yes` broadly | Tunneling/pivoting abuse |
| `MaxAuthTries` | high or unset | Weak brute-force friction |
| `LogLevel` | `QUIET`/`ERROR` | Impaired auth-attempt visibility |
| `AllowUsers`/`AllowGroups` | absent | No allow-list, wider attack surface |
| Host key perms | world-readable private key | Key theft |
| `Banner` | none required by policy, note only | Info only |

Also check `~/.ssh/authorized_keys` for keys with no `from=`/`command=`
restriction where policy expects one, and for `sshd` running an outdated
version (`ssh -V` / package version) with known CVEs.

## Samba — `/etc/samba/smb.conf`
| Directive | Flag if | Risk |
|---|---|---|
| `security` | `= share` | No per-user auth, legacy null-session model |
| `map to guest` | `= bad user` or `= bad password` | Unknown users silently mapped to guest |
| `guest ok` / `guest account` | `= yes` on any `[share]` | Anonymous access to that share |
| `browseable` | `= yes` on sensitive shares | Share enumeration without creds |
| `writable`/`read only = no` | on a guest-accessible share | Anonymous write / ransomware staging |
| `server min protocol` | allows `NT1`/SMBv1 | EternalBlue-class exposure |
| `null passwords` | `= yes` | Blank-password accounts accepted |
| No `valid users =` restriction on a share | — | Over-broad access |

Cross-check with `smbclient -L //host -N` (null session) results if you also
have network access — a config finding is strongest when paired with a live
confirmation.

## Web servers
**Nginx** (`/etc/nginx/nginx.conf`, `sites-enabled/*`):
- `server_tokens` not `off` → version disclosure in error/headers
- `autoindex on` on a content dir → directory listing
- Missing `add_header X-Frame-Options` / CSP / HSTS on TLS vhosts
- Weak `ssl_protocols` (TLSv1/TLSv1.1) or weak `ssl_ciphers`
- A `location ~` regex that unintentionally exposes `.git`, `.env`, backup
  files (`*.bak`, `*~`)

**Apache** (`/etc/apache2/apache2.conf`, `httpd.conf`, vhost files):
- `Options +Indexes` → directory listing
- `AllowOverride All` where not needed → `.htaccess` privilege creep
- `TraceEnable on` → HTTP TRACE / XST
- `ServerSignature On` / `ServerTokens Full` → version disclosure
- Missing `<Directory>` deny-by-default before allow rules

## Databases
**MySQL/MariaDB** (`/etc/mysql/my.cnf`, `mysqld.cnf`):
- `bind-address = 0.0.0.0` (or absent) with no firewall → DB reachable network-wide
- `skip-grant-tables` present → auth completely bypassed
- `local-infile = 1` → file read/write via SQLi (`LOAD DATA LOCAL INFILE`)
- Weak/default root password (check separately, don't put creds in the report)

**PostgreSQL** (`postgresql.conf`, `pg_hba.conf`):
- `listen_addresses = '*'` combined with permissive `pg_hba.conf`
- `pg_hba.conf` lines using `trust` for non-local connections → no auth at all
- `ssl = off` where remote connections are allowed

**Redis** (`redis.conf`):
- `bind 0.0.0.0` (or no `bind` line) → open to the network
- `protected-mode no` with no `bind`/`requirepass` → unauthenticated RCE-adjacent risk (module load, RDB write to cron/authorized_keys)
- No `requirepass` set

## FTP — `/etc/vsftpd.conf` or `/etc/proftpd/proftpd.conf`
- `anonymous_enable = YES` → anonymous access
- `anon_upload_enable = YES` alongside anonymous access → anonymous write
- `no_anon_password = YES` → skips password check entirely
- Plaintext auth without TLS (`ssl_enable` off / `implicit_ssl`/`TLSRequired` missing)

## NFS — `/etc/exports`
- `no_root_squash` → client root maps to server root on that export
- `rw` combined with a broad or missing client restriction (e.g. `*`)
- `insecure` option allowing non-privileged source ports

## Docker — `/etc/docker/daemon.json`, `docker-compose.yml`
- `"insecure-registries"` pointing anywhere non-local
- TCP daemon socket exposed without TLS (`-H tcp://0.0.0.0:2375`)
- Containers run `privileged: true` or mount `/var/run/docker.sock` unnecessarily
- Host `/etc`, `/root`, or the whole filesystem bind-mounted into a container

## Host-level: sudoers, cron, systemd
- `/etc/sudoers` and `/etc/sudoers.d/*`: `NOPASSWD` entries, wildcard command
  paths (`/usr/bin/*`), or entries granting a broad binary known for
  privesc (`vim`, `less`, `find`, `python`, etc. — check GTFOBins-style abuse
  potential for whatever binary is granted).
- `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`, and each referenced
  script: flag any script path that is **world-writable** or owned by a
  lower-privileged user than the job's runtime user — classic privesc.
- systemd unit files (`/etc/systemd/system/*.service`): `User=root` where
  unnecessary, `ExecStart` referencing a world-writable script, missing
  sandboxing directives (`ProtectSystem`, `NoNewPrivileges`) on services that
  accept untrusted input.
- `/etc/passwd`/`/etc/shadow` permissions: shadow must not be world-readable;
  flag any non-root UID 0 entries.

## Output format
Report each finding as:
```
[SEVERITY] <service> — <file>:<line/directive>
Current: <value>
Expected: <safe value>
Why: <one-line exploit/impact rationale>
```
Group by service, lead with Critical/High. Do not include recovered
credentials, key material, or shadow hashes in the written report — reference
that they were found and where, not the values themselves.
