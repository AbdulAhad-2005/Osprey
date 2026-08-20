# Recon Report — geo.tv
_Generated 2026-08-20 05:52 UTC_

## Summary
- Sister/associated domains: 0
- Subdomains discovered: 31
- Unique IPs: 3
- Open ports: 22
- Services identified: 0
- Orphan hosts (not clearly under seed/sisters): 5
- Total individual findings/tool outputs recorded: 53

## Tools Executed
| Tool | Findings/Outputs |
|---|---|
| subfinder_scan | 31 |
| nmap_custom_scan | 14 |
| whois_lookup | 5 |
| dnsx_resolve | 3 |

## Asset Overview
_Structural skeleton only — ports/services/tech shown here are what made it into structured fields. See **Detailed Findings by Tool** below for everything each tool actually returned, including unparsed output._

### Seed Domain
#### geo.tv _seed_
##### apnegn.geo.tv

##### apnegnu.geo.tv

##### apps.geo.tv

##### asool.geo.tv

##### asr.geo.tv

##### autodiscover.geo.tv

##### dns1.geo.tv

##### dns2.geo.tv

##### ebooking.geo.tv

##### election2013.geo.tv

##### emm.geo.tv

##### fb.geo.tv

##### geovision.geo.tv

##### lab.geo.tv

##### live.geo.tv

##### m.geo.tv

##### mail.geo.tv
- **Ports:** mail.geo.tv:80, mail.geo.tv:443, mail.geo.tv:80/tcp tcpwrapped, mail.geo.tv:443/tcp tcpwrapped

##### mail2.geo.tv

##### mail3.geo.tv

##### mx1.geo.tv

##### newsite.geo.tv

##### ns2.geo.tv

##### ramadan.geo.tv

##### shop.geo.tv

##### sql.geo.tv

##### store.geo.tv

##### talent.geo.tv

##### team.geo.tv

##### urdu.geo.tv

##### www.geo.tv

##### www.mail.geo.tv

### Other Discovered Hosts
_Hosts found but not clearly linked to the seed or a sister domain._

#### 104.16.218.243
- **IPs:** 104.16.218.243
- **Ports:** 104.16.218.243:80, 104.16.218.243:443, 104.16.218.243:8080, 104.16.218.243:8443, 104.16.218.243:80/tcp tcpwrapped, 104.16.218.243:443/tcp ssl/tcpwrapped, 104.16.218.243:8080/tcp tcpwrapped, 104.16.218.243:8443/tcp ssl/tcpwrapped
- **Tags:** dns_resolve

#### 104.16.219.243
- **IPs:** 104.16.219.243
- **Ports:** 104.16.219.243:80, 104.16.219.243:443, 104.16.219.243:2082, 104.16.219.243:8080, 104.16.219.243:8443, 104.16.219.243:80/tcp tcpwrapped, 104.16.219.243:443/tcp tcpwrapped, 104.16.219.243:2082/tcp tcpwrapped, 104.16.219.243:8080/tcp tcpwrapped, 104.16.219.243:8443/tcp tcpwrapped
- **Tags:** dns_resolve

#### 203.176.191.34
- **IPs:** 203.176.191.34
- **Tags:** dns_resolve

#### jack.ns.cloudflare.com

#### ruth.ns.cloudflare.com

## Contact Info / WHOIS / OSINT
### WHOIS
- WHOIS: geo.tv
- Whois Privacy Protection Service, Inc.
- DNSSEC not configured on geo.tv
- geo.tv NS -> jack.ns.cloudflare.com
- geo.tv NS -> ruth.ns.cloudflare.com

### Organizations / People / Usernames
- [org] Whois Privacy Protection Service, Inc.

## Vulnerabilities
_None confirmed yet — this run focused on recon/surface mapping._

## Detailed Findings by Tool
_Everything each tool returned, grouped by target — including raw/unparsed output. This is the full technical record; the sections above are curated summaries of it._

### dnsx_resolve (3 finding(s) across 1 target(s))
**apnegn.geo.tv
apnegnu.geo.tv
apps.geo.tv
asool.geo.tv
asr.geo.tv
autodiscover.geo.tv
dns1.geo.tv
dns2.geo.tv
ebooking.geo.tv
election2013.geo.tv
emm.geo.tv
fb.geo.tv
geo.tv
geovision.geo.tv
lab.geo.tv
live.geo.tv
m.geo.tv
mail.geo.tv
mail2.geo.tv
mail3.geo.tv
mx1.geo.tv
newsite.geo.tv
ns2.geo.tv
ramadan.geo.tv
shop.geo.tv
sql.geo.tv
store.geo.tv
talent.geo.tv
team.geo.tv
urdu.geo.tv
www.geo.tv
www.mail.geo.tv**
- 104.16.218.243
  ```
  www.geo.tv -> 104.16.218.243
  ```
- 104.16.219.243
  ```
  www.geo.tv -> 104.16.219.243
  ```
- 203.176.191.34
  ```
  mail.geo.tv -> 203.176.191.34
  ```

### nmap_custom_scan (14 finding(s) across 3 target(s))
**104.16.218.243**
- 104.16.218.243:80/tcp tcpwrapped
  ```
  80/tcp   open  tcpwrapped
  ```
- 104.16.218.243:443/tcp ssl/tcpwrapped
  ```
  443/tcp  open  ssl/tcpwrapped
  ```
- 104.16.218.243:8080/tcp tcpwrapped
  ```
  8080/tcp open  tcpwrapped
  ```
- 104.16.218.243:8443/tcp ssl/tcpwrapped
  ```
  8443/tcp open  ssl/tcpwrapped
  ```
- OS: Cisco SF300 or SG300 switch (93%), Sony Ericsson W705 or W715 Walkman mobile phone (90%), Nokia 3600i mobile phone (
  ```
  Cisco SF300 or SG300 switch (93%), Sony Ericsson W705 or W715 Walkman mobile phone (90%), Nokia 3600i mobile phone (89%), Apple Time Capsule NAS device (88%), Sony PlayStation 3 game console (88%), Ci
  ```

**104.16.219.243**
- 104.16.219.243:80/tcp tcpwrapped
  ```
  80/tcp   open  tcpwrapped
  ```
- 104.16.219.243:443/tcp tcpwrapped
  ```
  443/tcp  open  tcpwrapped
  ```
- 104.16.219.243:2082/tcp tcpwrapped
  ```
  2082/tcp open  tcpwrapped
  ```
- 104.16.219.243:8080/tcp tcpwrapped
  ```
  8080/tcp open  tcpwrapped
  ```
- 104.16.219.243:8443/tcp tcpwrapped
  ```
  8443/tcp open  tcpwrapped
  ```
- OS: Cisco SF300 or SG300 switch (93%), Sony Ericsson W705 or W715 Walkman mobile phone (90%), Nokia 3600i mobile phone (
  ```
  Cisco SF300 or SG300 switch (93%), Sony Ericsson W705 or W715 Walkman mobile phone (90%), Nokia 3600i mobile phone (89%), Apple Time Capsule NAS device (88%), Sony PlayStation 3 game console (88%), Ci
  ```

**mail.geo.tv**
- mail.geo.tv:80/tcp tcpwrapped
  ```
  80/tcp  open  tcpwrapped
  ```
- mail.geo.tv:443/tcp tcpwrapped
  ```
  443/tcp open  tcpwrapped
  ```
- OS: Cisco SF300 or SG300 switch (93%), Sony Ericsson W705 or W715 Walkman mobile phone (90%), Nokia 3600i mobile phone (
  ```
  Cisco SF300 or SG300 switch (93%), Sony Ericsson W705 or W715 Walkman mobile phone (90%), Nokia 3600i mobile phone (89%), Apple Time Capsule NAS device (88%), Sony PlayStation 3 game console (88%), Ci
  ```

### subfinder_scan (31 finding(s) across 1 target(s))
**geo.tv**
- ramadan.geo.tv
- store.geo.tv
- asool.geo.tv
- mail.geo.tv
- apnegn.geo.tv
- ebooking.geo.tv
- ns2.geo.tv
- sql.geo.tv
- team.geo.tv
- geovision.geo.tv
- m.geo.tv
- mx1.geo.tv
- dns1.geo.tv
- lab.geo.tv
- www.geo.tv
- emm.geo.tv
- newsite.geo.tv
- urdu.geo.tv
- mail3.geo.tv
- apnegnu.geo.tv
- election2013.geo.tv
- fb.geo.tv
- live.geo.tv
- mail2.geo.tv
- talent.geo.tv
- autodiscover.geo.tv
- www.mail.geo.tv
- apps.geo.tv
- dns2.geo.tv
- asr.geo.tv
- shop.geo.tv

### whois_lookup (5 finding(s) across 1 target(s))
**geo.tv**
- WHOIS: geo.tv
  ```
  registrar=eNom, LLC; created=2002-03-28T15:29:07Z; expiry=2027-03-28T14:29:07Z; dnssec=unsigned; ns=2
  ```
- Whois Privacy Protection Service, Inc.
  ```
  WHOIS registrant: Whois Privacy Protection Service, Inc.
  ```
- DNSSEC not configured on geo.tv
  ```
  WHOIS DNSSEC: unsigned
  ```
- geo.tv NS -> jack.ns.cloudflare.com
  ```
  nameserver jack.ns.cloudflare.com
  ```
- geo.tv NS -> ruth.ns.cloudflare.com
  ```
  nameserver ruth.ns.cloudflare.com
  ```
