# SMB Enumeration

**When:** Ports 445 or 139 are open on a Windows/Samba host.

**Default:** `enum4linux_scan` with `target`.

**Alternatives:** `enum4linux_ng_advanced`, `smbmap_scan`, `netexec_scan` for credentialed or deeper enum.

**Flags:** Pass enum4linux/smbmap/netexec options freely via `additional_args` (shares, users, `-a` full enum, etc.).

**Caution:** `responder_credential_harvest` is high-risk — only when governance approves.
