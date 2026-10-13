# Network-Device Exploitation — Benchmark & Gap Analysis

Benchmarks Osprey's network-device (firewall/router/switch/IoT) capability
against the top open-source tool and records the gap list. Scoring uses the
replay-benchmark lens (`benchmarks/README.md`): per stage, **coverage** (does
the capability exist), **success mode**, and **failure mode**. This is a
capability comparison — a live head-to-head needs RouterSploit installed and an
authorized target (§5 runbook).

## 1. Tools surveyed

**RouterSploit** (threat9) is the benchmark baseline — the de-facto OSS router/
IoT exploitation framework: `scanners/autopwn` (check a target against all
bundled exploits), `exploits/` (device/CVE), `creds/` (default/dict logins over
ftp/ssh/telnet/http/snmp), `payloads`, `generic`. Also surveyed: Metasploit
(already integrated as `metasploit_run`), EXPLIoT (IoT/radio/hardware — out of
scope for a remote pentest), binwalk/FACT/emba (firmware — `binwalk_analyze`
integrated), Nipper-ng (offline config audit — covered by the
`config-misconfig-audit` skill).

Sources: [threat9/routersploit](https://github.com/threat9/routersploit) · [routersploit (PyPI)](https://pypi.org/project/routersploit) · [EXPLIoT](https://pypi.org/project/expliot) · [Router Penetration Testing](https://www.hackingarticles.in/router-penetration-testing/).

## 2. Osprey vs RouterSploit — stage scoring

| Stage | Osprey | RouterSploit | Verdict |
|---|---|---|---|
| Host/port discovery | ✅ naabu/nmap/masscan/rustscan + `-sV` | ❌ none | Osprey ahead |
| Appliance identification | ✅ `web_fingerprint` (vendor/product from the web UI) | ⚠️ implicit (operator picks a module) | Parity |
| Vuln candidate research | ✅ `searchsploit_lookup`, `nuclei_scan` | ✅ `scanners/autopwn` | Parity |
| Device-specific exploitation | ✅ `routersploit_run` + `metasploit_run` | ✅ curated exploit set | Parity (RouterSploit live-pending — §4) |
| Default/dictionary creds | ✅ `routersploit_run` creds/* + `hydra_attack` | ✅ per-service creds modules | Parity |
| SNMP enumeration | ❌ no dedicated tool | ⚠️ snmp creds module | Gap |
| Firmware analysis | ✅ `binwalk_analyze` | ❌ none | Osprey ahead |
| Config/hardening audit | ✅ `config-misconfig-audit` skill | ❌ none | Osprey ahead |

## 3. Gap list

Closed by this ticket:
- Appliance **fingerprinting** — `web_fingerprint` (typed tool, auto-run on every live host). Live-verified against a real router.
- **Device-specific exploitation / default creds** — `routersploit_run` (GATED; live-pending, §4/§5).

Open:
1. No dedicated **SNMP** enumeration/default-community tool (`onesixtyone`/`snmpwalk`).
2. No parser-backed **config audit** (Nipper-style) — only the methodology skill.
3. No **switch/L2** or **IDS/IPS**-specific checks beyond generic nmap/nuclei.
4. HTTP(S)-only identification — no SSH/Telnet/SNMP **banner** fingerprinting.

## 4. Delivered

- **`web_fingerprint`** — passive HTTP(S) appliance fingerprinter. Integrated
  (registered `NETWORK`/`PASSIVE`, typed MCP tool, `tech_dispatch` rule so the
  engine fingerprints every live host). Identifies enterprise firewalls/VPNs and
  common SOHO routers (TP-Link/Huawei/ZTE/Netgear/ASUS/OpenWrt). Follows one
  meta-refresh hop and probes vendor login paths when the root is inconclusive;
  retries unverified on a cert failure (appliances are self-signed).
  **Live-verified** against a real router — correctly identified a TP-Link
  gateway via its `/webpages/` UI through the cert-fallback + meta-refresh path.
- **`routersploit_run`** — RouterSploit integration (GATED exploit tool driving
  `scanners/autopwn` / `exploits/*` / `creds/*` via the rsf console, with input
  sanitization and a status-line parser). Registered + typed + unit-tested;
  **live confirmation pending** (§5).

## 5. Acceptance criteria

- **AC1 — benchmark report + gap list:** met (this document).
- **AC2 — integrated + functional vs a real device:** `web_fingerprint`
  live-verified against a real router. `routersploit_run` is integrated and
  unit-tested but not yet run against a live device — no RouterSploit install or
  authorized router/firewall was available for an exploit run. Close it with:

```bash
# rsf installed (pip install routersploit) + an AUTHORIZED target, exploitation enabled:
platform_exec tool=routersploit_run params_json='{"module":"scanners/autopwn","target":"<AUTHORIZED_IP>"}'
# Expect: {"vulnerable": true|false|null, "status_lines":[...], "credentials":[...], "raw":"..."}
```

A RouterSploit `[+]` is a scanner claim until a PoC/repro confirms it — file
findings with real evidence per the usual discipline.

## 6. Suggested Router Exploitation Framework features

1. **SNMP module** — `onesixtyone` community brute + `snmpwalk` sysDescr → feeds vendor/model back into recon.
2. **Vendor→default-cred selection** — once `web_fingerprint` names the device, auto-pick the matching RouterSploit `creds/*` module.
3. **Config-audit parser** — turn the `config-misconfig-audit` skill into a tool emitting typed findings.
4. **Firmware→CVE pipeline** — `binwalk_analyze` → component/version detection → `searchsploit`/`nuclei`.
5. **L2/switch + IDS/IPS** management-plane checks.
