# Network-Device Exploitation — Benchmark & Gap Analysis

> **Ticket:** benchmark Osprey's network-device (firewall/router/switch/IDS/IoT)
> capability against the top existing tool(s), document the gap list, and
> integrate RouterSploit + relevant tooling.
> **Method:** the same stage-scoring lens as the replay benchmarks
> (`benchmarks/README.md`) — per stage we score **coverage** (does the
> capability exist), **success mode** (what it produces when it works), and
> **failure mode** (how it fails). This is a *capability* comparison, not a live
> head-to-head: a live head-to-head needs RouterSploit installed and an
> authorized router/firewall target (see §7 runbook) — that remains the open
> item for acceptance-criterion 2.

## 1. Top tools identified

| Tool | Focus | Relevance |
|---|---|---|
| **RouterSploit** (threat9) | Routers/firewalls/cameras/embedded — `scanners` (autopwn), `exploits` (device/CVE), `creds` (ftp/ssh/telnet/http/snmp default/dict), `payloads`, `generic` | **Top pick** — the de-facto open-source router/IoT exploitation framework; chosen as the benchmark baseline. |
| Metasploit | General exploitation incl. some SCADA/router/IoT aux+exploit modules | Already integrated (`metasploit_run`); complementary to RouterSploit. |
| EXPLIoT | IoT/radio/hardware (BLE, Zigbee, SPI/I2C/JTAG, CoAP/MQTT) | Hardware/radio IoT — out of scope for a remote network pentest; noted for the future framework. |
| binwalk / FACT / emba | Firmware extraction & analysis | `binwalk_analyze` already integrated; FACT/emba are heavier offline analyzers. |
| Nipper-ng | Offline network-device **config** audit | No OSS tool integrated; Osprey covers this via the `config-misconfig-audit` skill (methodology, not a parser). |

Sources: [threat9/routersploit](https://github.com/threat9/routersploit) · [routersploit on PyPI](https://pypi.org/project/routersploit) · [EXPLIoT](https://pypi.org/project/expliot) · [Router Penetration Testing (hackingarticles)](https://www.hackingarticles.in/router-penetration-testing/).

## 2. Osprey vs RouterSploit — stage scoring

| Stage | Osprey (before this ticket) | RouterSploit | Verdict |
|---|---|---|---|
| **Host/port discovery** | ✅ naabu / nmap / masscan / rustscan, service versioning (`-sV`) | ❌ none (assumes a target) | **Osprey ahead** — RouterSploit has no discovery. |
| **Appliance identification** | ⚠️ generic tech fingerprint only — no firewall/router/VPN vendor signatures | ⚠️ implicit (picks a device-specific module by hand) | **Gap → closed this ticket** by `web_fingerprint` (vendor/product from the web UI). |
| **Vuln candidate research** | ✅ `searchsploit_lookup`, `nuclei_scan` (network/router templates) | ✅ `scanners/autopwn` checks the target against all bundled exploits | **Parity on research; RouterSploit's device-specific check library was the gap.** |
| **Device-specific exploitation** | ⚠️ `metasploit_run` (some router/IoT modules) only | ✅ large curated router/camera/firewall exploit set | **Gap → closed this ticket** by `routersploit_run` (integration; live-confirmation pending). |
| **Default / dictionary creds** | ⚠️ `hydra_attack` (generic brute, needs a wordlist) | ✅ per-service default-cred modules (ftp/ssh/telnet/http/snmp) | **Gap narrowed** — RouterSploit `creds/*` now reachable via `routersploit_run`. |
| **SNMP enumeration** | ❌ no dedicated SNMP tool | ⚠️ snmp default-cred creds module | **Gap remains** (see §3). |
| **Firmware analysis** | ✅ `binwalk_analyze` | ❌ none | **Osprey ahead.** |
| **Config/hardening audit** | ✅ `config-misconfig-audit` skill (methodology) | ❌ none | **Osprey ahead** (methodology; no parser yet). |

**Summary:** Osprey was already *stronger* on discovery, firmware and config
audit, at *parity* on CVE research, and *behind* on exactly two things —
(a) identifying that a live host **is** a network appliance, and (b) a curated
**device-specific exploit/default-cred** library. This ticket closes both.

## 3. Gap list (prioritized)

1. **[closed]** No firewall/router/VPN **fingerprinting** → `web_fingerprint` (integrated: typed tool + auto-run on every live host).
2. **[closed, live-pending]** No **device-specific exploitation**/default-cred library → `routersploit_run` (integrated as a GATED exploit tool; needs §7 live confirmation).
3. **[open]** No dedicated **SNMP** enumeration/default-community tool (`onesixtyone`/`snmpwalk`) — common on routers/switches/printers.
4. **[open]** `web_fingerprint` fetches only the given URL (follows redirects) — it does not actively probe the appliance **login paths** its own signatures target (`/remote/login`, `/dana-na/`, `/+CSCOE+/`, `/vpn/index.html`), so a device with a bland root and no redirect under-matches.
5. **[open]** No parser-backed **config audit** (Nipper-style) — only the methodology skill.
6. **[open]** No **switch/L2** or **IDS/IPS**-specific checks (SNMP RW, management-plane exposure, known IDS mgmt CVEs) beyond generic nmap/nuclei.
7. **[open]** HTTP(S)-only fingerprinting — no SSH/Telnet/SNMP **banner** fingerprinting as a device-identification signal.

## 4. What this ticket delivered

- **`web_fingerprint`** — passive HTTP(S) appliance fingerprinter (Hadi's branch), reviewed, TLS-verify fallback added, and **fully integrated**: registered `NETWORK`/`PASSIVE`, exposed as a typed MCP tool, and wired into `tech_dispatch` so the deterministic engine fingerprints **every live host** (rule `live_host_appliance_fingerprint`).
- **`routersploit_run`** — RouterSploit integration: a GATED exploit tool driving `scanners/autopwn`, `exploits/*`, and `creds/*` via the rsf console (stdin), with a defensive status-line parser. Registered + typed + unit-tested; **live confirmation pending** (§7).
- **Skills** — `recon/subdomain-takeover` sibling `network/config-misconfig-audit` and `network/Update-fingerprints-for-router` (fingerprint-DB extension methodology).

## 5. Suggested features for the Router Exploitation Framework

Driven by the gap list, in priority order:

1. **Login-path probing** for `web_fingerprint` (gap #4) — try a bounded set of vendor login paths when the root is inconclusive; biggest single accuracy win.
2. **SNMP module** (gap #3) — `onesixtyone` community brute + `snmpwalk` sysDescr fingerprint → feeds device vendor/model back into recon.
3. **Default-credential matrix** keyed by fingerprinted vendor/model — once `web_fingerprint` names the device, auto-select the matching RouterSploit `creds/*` module instead of a blind brute.
4. **Config-audit parser** (gap #5) — turn the `config-misconfig-audit` skill into a tool that parses a pulled config and emits typed findings.
5. **Firmware→CVE pipeline** — chain `binwalk_analyze` extraction → version/component detection → `searchsploit`/`nuclei` candidates.
6. **L2/switch + IDS/IPS** management-plane checks (gap #6).

## 6. Acceptance-criteria status

- **AC1 — benchmark report + documented gap list:** ✅ **met** (this document).
- **AC2 — RouterSploit + network-device MCPs integrated and functional, confirmed against a real router/firewall:** 🟡 **integrated + unit-tested; live confirmation pending.** No RouterSploit install and no *authorized* router/firewall target are available in this environment, and scanning an arbitrary real device is out of scope. Run §7 against an authorized target to close it.

## 7. Live-confirmation runbook (closes AC2)

Prereqs: RouterSploit installed in the Kali container (`pip install routersploit`,
exposes `rsf.py`), and an **authorized** router/firewall test target.

```bash
# 1. The tool must be allowed (GATED): enable exploitation on the engagement, then:
#    via the typed tool (LLM/operator), or platform_exec:
platform_exec tool=routersploit_run params_json='{"module":"scanners/autopwn","target":"<AUTHORIZED_IP>"}'

# 2. Expect structured JSON: {"vulnerable": true|false|null, "status_lines":[...],
#    "credentials":[...], "module":"scanners/autopwn", "raw":"..."}.
#    A '[+] ... vulnerable to exploits/...' line sets vulnerable=true.

# 3. Default-cred check example:
platform_exec tool=routersploit_run params_json='{"module":"creds/routers/mikrotik/ssh_default_creds","target":"<AUTHORIZED_IP>"}'
```

Confirm: (a) the command runs rsf and returns parsed JSON, (b) `vulnerable`/
`credentials` reflect the target, (c) findings are filed with real evidence per
the usual evidence discipline (a RouterSploit `[+]` is a scanner claim until a
PoC/repro confirms it).
