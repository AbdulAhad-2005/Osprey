# Recon Report — bolnews.com

_Generated 2026-08-16 03:40 UTC_

## Summary

- Sister/associated domains: 2
- Subdomains discovered: 37
- Unique IPs: 3
- Open ports: 6
- Services identified: 0
- Orphan hosts (not clearly under seed/sisters): 5
- Total individual findings/tool outputs recorded: 74

## Tools Executed

| Tool                 | Findings/Outputs |
| -------------------- | ---------------- |
| subfinder_scan       | 37               |
| whois_lookup         | 5                |
| cdn_origin_probe     | 4                |
| dnsx_resolve         | 4                |
| httpx_probe          | 4                |
| nmap_custom_scan     | 4                |
| domain_hunter        | 2                |
| email_security_probe | 2                |
| naabu_port_scan      | 2                |
| nmap_service_scan    | 2                |
| tech_stack_analyze   | 2                |
| tlsx_inspect         | 2                |
| wafw00f_scan         | 2                |
| crt_sh_query         | 1                |
| shodan_host_info     | 1                |

## Asset Overview

_Structural skeleton only — ports/services/tech shown here are what made it into structured fields. See **Detailed Findings by Tool** below for everything each tool actually returned, including unparsed output._

### Seed Domain

#### bolnews.com _seed_

##### bolnews.com

- **Tags:** dns_record, mx, ns, tls, tls_san, whois

##### ads.bolnews.com

##### api.bolnews.com

##### apiv2.bolnews.com

##### autodiscover.bolnews.com

##### bolnewswp-api.bolnews.com

##### bolnewswp-app.bolnews.com

##### cdn.bolnews.com

##### cdnurdu.bolnews.com

##### cruiseway.bolnews.com

##### datav1.bolnews.com

- **Technologies:** SUCCESS

##### forum.bolnews.com

##### img2.bolnews.com

##### live.bolnews.com

##### login.bolnews.com

##### m.bolnews.com

##### mail.bolnews.com

##### media.bolnews.com

##### newspaperadmin.bolnews.com

##### ns1.bolnews.com

##### ns2.bolnews.com

##### ns3.bolnews.com

##### ostracodermi.bolnews.com

##### pakistan.bolnews.com

##### pop.bolnews.com

##### server.bolnews.com

##### server2.bolnews.com

##### server3.bolnews.com

##### server4.bolnews.com

##### staging.bolnews.com

##### status.bolnews.com

##### textwp.bolnews.com

##### us.bolnews.com

##### v2.bolnews.com

##### vdo.bolnews.com

##### vdo2.bolnews.com

##### www.bolnews.com

- **Ports:** www.bolnews.com:8443, www.bolnews.com:80, www.bolnews.com:8443/tcp open, www.bolnews.com:80/tcp open, www.bolnews.com:80/tcp http     Cloudflare http proxy, www.bolnews.com:8443/tcp ssl/http Cloudflare http proxy
- **Technologies:** SUCCESS
- **Tags:** naabu

##### www.server.bolnews.com

### Sister / Associated Domains

#### avads.live _sister_

##### avads.live

- **Tags:** domain_hunter, sister_domain

#### google.com _sister_

##### google.com

- **Tags:** domain_hunter, scrape_noise, sister_domain, unverified_affiliate

### Other Discovered Hosts

_Hosts found but not clearly linked to the seed or a sister domain._

#### 104.26.10.66

- **IPs:** 104.26.10.66
- **Tags:** dns_resolve

#### 104.26.11.66

- **IPs:** 104.26.11.66
- **Tags:** dns_resolve

#### 172.67.68.39

- **IPs:** 172.67.68.39
- **Tags:** dns_resolve

#### arnold.ns.cloudflare.com

#### cecelia.ns.cloudflare.com

## Contact Info / WHOIS / OSINT

### WHOIS

- WHOIS: bolnews.com
- Jewella Privacy LLC Privacy ID# 14618728
- DNSSEC not configured on bolnews.com
- bolnews.com NS -> arnold.ns.cloudflare.com
- bolnews.com NS -> cecelia.ns.cloudflare.com

### Organizations / People / Usernames

- [org] Jewella Privacy LLC Privacy ID# 14618728

## Vulnerabilities

_None confirmed yet — this run focused on recon/surface mapping._

## Detailed Findings by Tool

_Everything each tool returned, grouped by target — including raw/unparsed output. This is the full technical record; the sections above are curated summaries of it._

### cdn_origin_probe (4 finding(s) across 2 target(s))

**datav1.bolnews.com**

- CDN hint: cloudflare
- Redirect: Location: https://datav1.bolnews.com/
  ```
  Location: https://datav1.bolnews.com/
  ```

**www.bolnews.com**

- CDN hint: cloudflare
- Redirect: Location: https://www.bolnews.com/
  ```
  Location: https://www.bolnews.com/
  ```

### crt_sh_query (1 finding(s) across 1 target(s))

**bolnews.com**

- Output from crt_sh_query
  ```
  [{"issuer_ca_id":432952,"issuer_name":"C=US, O=Let's Encrypt, CN=YE1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925475296,"entry_timestamp":"2026-07-14T12:08:19.1","not_before":"2026-07-14T11:09:47","not_after":"2026-10-12T11:09:46","serial_number":"05e3a32fa27096fe00ecf39b8077799f4b5e","result_count":3},{"issuer_ca_id":432952,"issuer_name":"C=US, O=Let's Encrypt, CN=YE1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925458968,"entry_timestamp":"2026-07-14T12:08:16.621","not_before":"2026-07-14T11:09:47","not_after":"2026-10-12T11:09:46","serial_number":"05e3a32fa27096fe00ecf39b8077799f4b5e","result_count":3},{"issuer_ca_id":432476,"issuer_name":"C=US, O=Let's Encrypt, CN=YR1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925475254,"entry_timestamp":"2026-07-14T12:08:14.881","not_before":"2026-07-14T11:09:43","not_after":"2026-10-12T11:09:42","serial_number":"053f8d77bf308f7b7620fad8e5a3f7deeff8","result_count":3},{"issuer_ca_id":432476,"issuer_name":"C=US, O=Let's Encrypt, CN=YR1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925457646,"entry_timestamp":"2026-07-14T12:08:12.566","not_before":"2026-07-14T11:09:43","not_after":"2026-10-12T11:09:42","serial_number":"053f8d77bf308f7b7620fad8e5a3f7deeff8","result_count":3},{"issuer_ca_id":286236,"issuer_name":"C=US, O=Google Trust Services, CN=WE1","common_name":"bolnews.com","name_value":"*.bolnews.com\
  ```

### dnsx_resolve (4 finding(s) across 1 target(s))

**bolnews.com**

- 172.67.68.39
  ```
  bolnews.com -> 172.67.68.39
  ```
- 104.26.10.66
  ```
  bolnews.com -> 104.26.10.66
  ```
- 104.26.11.66
  ```
  bolnews.com -> 104.26.11.66
  ```
- bolnews.com MX -> mail.bolnews.com
  ```
  bolnews.com MX mail.bolnews.com
  ```

### domain_hunter (2 finding(s) across 1 target(s))

**bolnews.com**

- avads.live
  ```
  method=site_scrape; live_probe confidence=low live=yes
  ```
- google.com
  ```
  method=site_scrape; live_probe confidence=low live=yes
  ```

### email_security_probe (2 finding(s) across 1 target(s))

**bolnews.com**

- Email security posture: bolnews.com
  ```
  spf="v=spf1 mx a ip4:221.132.113.227/32 include;bolnetwork..com ~all"; dmarc="v=DMARC1; p=none; sp=none; rua=mailto:dmarc@bolnews.com; ruf=mailto:dmarc@bolnews.com; rf=afrf; pct=100; ri=86400"
  ```
- Weak email anti-spoofing on bolnews.com
  ```
  SPF ~all (softfail) — does not hard-fail spoofed senders; DMARC p=none — monitoring only, does not block spoofed mail
  ```

### httpx_probe (4 finding(s) across 2 target(s))

**https://datav1.bolnews.com**

- https://datav1.bolnews.com
  ```
  https://datav1.bolnews.com [SUCCESS]
  ```
- SUCCESS
  ```
  https://datav1.bolnews.com [SUCCESS]
  ```

**https://www.bolnews.com**

- https://www.bolnews.com
  ```
  https://www.bolnews.com [SUCCESS]
  ```
- SUCCESS
  ```
  https://www.bolnews.com [SUCCESS]
  ```

### naabu_port_scan (2 finding(s) across 1 target(s))

**www.bolnews.com**

- www.bolnews.com:8443/tcp open
  ```
  www.bolnews.com:8443
  ```
- www.bolnews.com:80/tcp open
  ```
  www.bolnews.com:80
  ```

### nmap_custom_scan (4 finding(s) across 1 target(s))

**www.bolnews.com**

- http-server-header output (www.bolnews.com:80)
  ```
  cloudflare
  ```
- http-title output (www.bolnews.com:8443)
  ```
  Site doesn't have a title.
  ```
- ssl-cert output (www.bolnews.com:8443)
  ```
  Subject: commonName=bolnews.com
  Subject Alternative Name: DNS:bolnews.com, DNS:*.bolnews.com
  Not valid before: 2026-06-29T15:45:25
  Not valid after:  2026-09-27T16:45:08
  ```
- http-server-header output (www.bolnews.com:8443)
  ```
  cloudflare
  ```

### nmap_service_scan (2 finding(s) across 1 target(s))

**www.bolnews.com**

- www.bolnews.com:80/tcp http     Cloudflare http proxy
  ```
  80/tcp   open  http     Cloudflare http proxy
  ```
- www.bolnews.com:8443/tcp ssl/http Cloudflare http proxy
  ```
  8443/tcp open  ssl/http Cloudflare http proxy
  ```

### shodan_host_info (1 finding(s) across 1 target(s))

**bolnews.com**

- shodan_host_info raw output (failed)
  ```
  python3: can't open file '/mcp-servers/recon/tools/_shodan_cli.py': [Errno 2] No such file or directory
  ```

### subfinder_scan (37 finding(s) across 1 target(s))

**bolnews.com**

- www.bolnews.com
- forum.bolnews.com
- ns1.bolnews.com
- ns3.bolnews.com
- apiv2.bolnews.com
- cruiseway.bolnews.com
- pop.bolnews.com
- api.bolnews.com
- ads.bolnews.com
- cdn.bolnews.com
- cdnurdu.bolnews.com
- datav1.bolnews.com
- pakistan.bolnews.com
- v2.bolnews.com
- bolnewswp-api.bolnews.com
- server2.bolnews.com
- staging.bolnews.com
- vdo2.bolnews.com
- live.bolnews.com
- textwp.bolnews.com
- mail.bolnews.com
- newspaperadmin.bolnews.com
- bolnewswp-app.bolnews.com
- m.bolnews.com
- server4.bolnews.com
- media.bolnews.com
- vdo.bolnews.com
- autodiscover.bolnews.com
- ns2.bolnews.com
- server.bolnews.com
- status.bolnews.com
- login.bolnews.com
- ostracodermi.bolnews.com
- img2.bolnews.com
- server3.bolnews.com
- us.bolnews.com
- www.server.bolnews.com

### tech_stack_analyze (2 finding(s) across 2 target(s))

**datav1.bolnews.com**

- tech_stack_analyze raw output
  ```
  {"target": "https://datav1.bolnews.com", "methods": {"whatweb": {"technologies": [{"name": "HTTPServer", "version": ""}, {"name": "RedirectLocation", "version": ""}, {"name": "X-Powered-By", "version": ""}, {"name": "HTML5", "version": ""}, {"name": "HTTPServer", "version": ""}, {"name": "Script", "version": ""}, {"name": "Title", "version": ""}, {"name": "X-Powered-By", "version": ""}], "raw_plugins": ["Country", "HTTPServer", "IP", "RedirectLocation", "UncommonHeaders", "X-Powered-By", "Country", "HTML5", "HTTPServer", "IP", "Script", "Title", "UncommonHeaders", "X-Powered-By"]}}, "unified_stack": [{"name": "HTTPServer", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "RedirectLocation", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "X-Powered-By", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "HTML5", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "Script", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "Title", "version": "", "categories": [], "detected_by": ["whatweb"]}], "total_technologies": 6}
  {"target": "https://datav1.bolnews.com", "methods": {"whatweb": {"technologies": [{"name": "HTTPServer", "version": ""}, {"name": "RedirectLocation", "version": ""}, {"name": "X-Powered-By", "version": ""}, {"name": "HTML5", "version": ""}, {"name": "HTTPServer", "version": ""}, {"name": "Script", "version": ""}, {"name": "Title", "version": ""}, {"name": "X-P
  ```

**www.bolnews.com**

- tech_stack_analyze raw output
  ```
  {"target": "https://www.bolnews.com", "methods": {"whatweb": {"technologies": [{"name": "Frame", "version": ""}, {"name": "Google-Analytics", "version": "Universal"}, {"name": "HTML5", "version": ""}, {"name": "HTTPServer", "version": ""}, {"name": "JQuery", "version": "3.7.1"}, {"name": "Lightbox", "version": ""}, {"name": "MetaGenerator", "version": ""}, {"name": "Open-Graph-Protocol", "version": "website"}, {"name": "Script", "version": ""}, {"name": "Title", "version": ""}, {"name": "WordPress", "version": "6.8.8"}, {"name": "X-UA-Compatible", "version": ""}], "raw_plugins": ["Country", "Frame", "Google-Analytics", "HTML5", "HTTPServer", "IP", "JQuery", "Lightbox", "MetaGenerator", "Open-Graph-Protocol", "Script", "Title", "UncommonHeaders", "WordPress", "X-UA-Compatible"]}}, "unified_stack": [{"name": "Frame", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "Google-Analytics", "version": "Universal", "categories": [], "detected_by": ["whatweb"]}, {"name": "HTML5", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "HTTPServer", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "JQuery", "version": "3.7.1", "categories": [], "detected_by": ["whatweb"]}, {"name": "Lightbox", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "MetaGenerator", "version": "", "categories": [], "detected_by": ["whatweb"]}, {"name": "Open-Graph-Protocol", "version": "website", "categories": [], "detected_by": ["
  ```

### tlsx_inspect (2 finding(s) across 1 target(s))

**bolnews.com**

- TLS bolnews.com:443
  ```
  {"timestamp":"2026-08-16T03:35:54.695858027Z","host":"bolnews.com","ip":"104.26.11.66","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-06-29T15:45:25Z","not_after":"2026-09-27T16:45:08Z","subject_dn":"CN=bolnews.com","subject_cn":"bolnews.com","subject_an":["bolnews.com","*.bolnews.com"],"serial":"EB:1B:6F:08:19:65:C7:EC:0E:4C:67:D9:DE:96:95:F4","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"febe6edf84d4081320bde4c69565c4a0","sha1":"8465dea84d3f469350c980c074a48648bbd90475","sha256":"36191a71c6b241e9562ab38fb5ced500b2d4af6dd36de76999efb60ede702040"},"wildcard_certificate":true,"tls_connection":"ctls","sni":"boln
  ```
- bolnews.com

### wafw00f_scan (2 finding(s) across 2 target(s))

**datav1.bolnews.com**

- WAF: [1;96mCloudflare (Cloudflare Inc.)[0m
  ```
  is behind [1;96mCloudflare (Cloudflare Inc.)[0m WAF
  ```

**www.bolnews.com**

- WAF: [1;96mCloudflare (Cloudflare Inc.)[0m
  ```
  is behind [1;96mCloudflare (Cloudflare Inc.)[0m WAF
  ```

### whois_lookup (5 finding(s) across 1 target(s))

**bolnews.com**

- WHOIS: bolnews.com
  ```
  registrar=DNC Holdings, Inc.; created=2004-04-28T19:49:31Z; expiry=2031-04-28T19:49:31Z; dnssec=unsigned; ns=2
  ```
- Jewella Privacy LLC Privacy ID# 14618728
  ```
  WHOIS registrant: Jewella Privacy LLC Privacy ID# 14618728
  ```
- DNSSEC not configured on bolnews.com
  ```
  WHOIS DNSSEC: unsigned
  ```
- bolnews.com NS -> arnold.ns.cloudflare.com
  ```
  nameserver arnold.ns.cloudflare.com
  ```
- bolnews.com NS -> cecelia.ns.cloudflare.com
  ```
  nameserver cecelia.ns.cloudflare.com
  ```
