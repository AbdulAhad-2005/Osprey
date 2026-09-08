---
name: smb-enumeration
description: "SMB enumeration when 445/139 are open: enum4linux and variants (enum4linux-ng, smbmap, netexec); responder is high-risk and governance-gated."
phases: [network]
tags: [network, smb]
---

# SMB Enumeration

**When:** Ports 445 or 139 are open on a Windows/Samba host.

**Default:** `enum4linux_scan` with `target`.

**Alternatives:** `enum4linux_ng_advanced`, `smbmap_scan`, `netexec_scan` for credentialed or deeper enum.

**Flags:** Pass enum4linux/smbmap/netexec options freely via `additional_args` (shares, users, `-a` full enum, etc.).

**Caution:** `responder_credential_harvest` is high-risk — only when governance approves.

## What to actually check, beyond running the tool

A raw enum4linux dump is a data point, not a finding — pull these specific signals out of it:
- **Null session allowed** (`enum4linux -a` succeeds with no credentials at all) — itself a
  finding: anonymous share/user enumeration shouldn't work on a hardened host.
- **RID cycling** (enum4linux/netexec's `--rid-brute`) walks well-known SIDs
  (`S-1-5-21-<domain>-500`, `-501`, `-1000`+) to enumerate usernames even when normal SAM
  enumeration is blocked — a common bypass for "we disabled null-session enum" configs that
  didn't also block RID cycling.
- **Writable shares** (`smbmap_scan` or `netexec_scan --shares`) — a writable share reachable
  without creds is a direct foothold (plant a file, wait for it to execute, or read what's
  already there) — check write access explicitly, don't just note the share exists.
- **SMB signing not required** (`nmap --script smb2-security-mode`, or `netexec smb <target>`
  shows `signing:False`) — the precondition for an NTLM relay attack (see
  `active-directory/phase-overview`'s coercion+relay section); flag it even without a domain
  context, since it also enables local-account relay.
- **SMBv1 enabled** — an EternalBlue-class-vulnerability candidate on its own; `nmap --script
  smb-protocols` shows the negotiated dialects.

## If this turns out to be a domain-joined host

Null-session/RID-cycling results, share names, and OS version all feed directly into
`active-directory/phase-overview` once you have — or this host reveals — actual domain
credentials or a hint the host is domain-joined (a domain name in the enum4linux output, or
`hostnamectl`/registry showing AD membership post-shell). SMB enumeration here is reconnaissance
for that phase, not a dead end if creds never materialize from this step alone.
