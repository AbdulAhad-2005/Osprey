# Recon Report — geo.tv
_Generated 2026-08-27 13:19 UTC_

## Summary
- Sister/associated domains: 1
- Subdomains discovered: 34
- Unique IPs: 5
- Open ports: 26
- Services identified: 1
- Orphan hosts (not clearly under seed/sisters): 9
- Total individual findings/tool outputs recorded: 720

## Tools Executed
| Tool | Findings/Outputs |
|---|---|
| waybackurls_discovery | 301 |
| gau_discovery | 298 |
| subfinder_scan | 32 |
| httpx_probe | 21 |
| nmap_service_scan | 16 |
| well_known_probe | 12 |
| dnsx_resolve | 7 |
| katana_crawl | 6 |
| naabu_port_scan | 6 |
| cdn_origin_probe | 5 |
| rustscan_fast_scan | 3 |
| whois_lookup | 3 |
| tlsx_inspect | 2 |
| amass_scan | 1 |
| crt_sh_query | 1 |
| dnsenum_scan | 1 |
| domain_hunter | 1 |
| email_security_probe | 1 |
| subdomain_takeover_check | 1 |

_Note: rate_governor flagged rate-limiting/blocking while pacing calls (2 signal(s)) — see Detailed Findings._

## Asset Overview
_Structural skeleton only — ports/services/tech shown here are what made it into structured fields. See **Detailed Findings by Tool** below for everything each tool actually returned, including unparsed output._

### Seed Domain
#### geo.tv _seed_
##### geo.tv
- **Ports:** geo.tv:443, geo.tv:8080, geo.tv:8443, geo.tv:80, geo.tv:443/tcp open, geo.tv:8080/tcp open, geo.tv:8443/tcp open, geo.tv:80/tcp open
- **Technologies:** SUCCESS
- **Tags:** dns_record, mx, naabu, ns, tls, url_history

##### _dmarc.geo.tv

##### apnegn.geo.tv
- **Technologies:** SUCCESS

##### apnegnu.geo.tv
- **Technologies:** SUCCESS

##### apps.geo.tv

##### asool.geo.tv
- **Technologies:** SUCCESS

##### asr.geo.tv

##### autodiscover.geo.tv
- **IPs:** 203.176.191.34
- **Technologies:** SUCCESS
- **Tags:** cname, dns_record

##### dns1.geo.tv

##### dns2.geo.tv

##### ebooking.geo.tv

##### election2013.geo.tv

##### emm.geo.tv

##### fb.geo.tv

##### geovision.geo.tv

##### lab.geo.tv

##### live.geo.tv
- **IPs:** 104.16.218.243
- **Technologies:** SUCCESS

##### m.geo.tv

##### mail.geo.tv
- **IPs:** 203.176.191.34
- **Ports:** mail.geo.tv:80, mail.geo.tv:443, mail.geo.tv:443/tcp https?
- **Services:** mail.geo.tv:80/tcp http    Microsoft IIS httpd 10.0
- **Technologies:** SUCCESS

##### mail2.geo.tv

##### mail3.geo.tv

##### mx1.geo.tv

##### newsite.geo.tv

##### ns2.geo.tv

##### ramadan.geo.tv
- **Technologies:** SUCCESS

##### shop.geo.tv

##### sql.geo.tv

##### store.geo.tv

##### talent.geo.tv
- **IPs:** 104.16.218.243
- **Technologies:** SUCCESS

##### team.geo.tv

##### urdu.geo.tv
- **Technologies:** SUCCESS

##### www.geo.tv
- **IPs:** 104.16.218.243
- **Ports:** www.geo.tv:80, www.geo.tv:80/tcp open
- **Technologies:** SUCCESS
- **Tags:** crawl, katana, naabu, url_history

##### www.mail.geo.tv

### Sister / Associated Domains
#### geoit.tv _sister_
##### geoit.tv
- **Tags:** domain_hunter, sister_domain

##### mx1.geoit.tv
- **Ports:** mx1.geoit.tv:25, mx1.geoit.tv:25/tcp smtp    FortiMail smtpd (time zone: +0500)

##### mx2.geoit.tv
- **Ports:** mx2.geoit.tv:25, mx2.geoit.tv:587, mx2.geoit.tv:25/tcp smtp    FortiMail smtpd (time zone: +0500), mx2.geoit.tv:587/tcp smtp    FortiMail smtpd (time zone: +0500)

### Other Discovered Hosts
_Hosts found but not clearly linked to the seed or a sister domain._

#### 104.16.218.243
- **IPs:** 104.16.218.243
- **Tags:** dns_resolve

#### 104.16.218.243,104.16.219.243
- **Ports:** 104.16.218.243,104.16.219.243:80, 104.16.218.243,104.16.219.243:443, 104.16.218.243:80/tcp open, 104.16.219.243:80/tcp open, 104.16.218.243:443/tcp open
- **Tags:** script_parsed

#### 104.16.219.243
- **IPs:** 104.16.219.243
- **Tags:** dns_resolve

#### 203.176.191.28
- **IPs:** 203.176.191.28
- **Ports:** 203.176.191.28:25, 203.176.191.28:25/tcp open
- **Tags:** naabu, origin_candidate

#### 203.176.191.29
- **IPs:** 203.176.191.29
- **Tags:** origin_candidate

#### 203.176.191.34
- **IPs:** 203.176.191.34
- **Tags:** origin_candidate

#### jack.ns.cloudflare.com

#### robots disallow
- **Tags:** robots_disallow

#### ruth.ns.cloudflare.com

## Contact Info / WHOIS / OSINT
### WHOIS
- WHOIS: geo.tv
- Whois Privacy Protection Service, Inc.
- DNSSEC not configured on geo.tv

### Organizations / People / Usernames
- [org] Whois Privacy Protection Service, Inc.

## Vulnerabilities
_None confirmed yet — this run focused on recon/surface mapping._

## Detailed Findings by Tool
_Everything each tool returned, grouped by target — including raw/unparsed output. This is the full technical record; the sections above are curated summaries of it._

### amass_scan (1 finding(s) across 1 target(s))
**geo.tv**
- geo.tv

### cdn_origin_probe (5 finding(s) across 1 target(s))
**geo.tv**
- CDN hint: cloudflare
- 203.176.191.28
  ```
  signals=['probe']
  ```
- 203.176.191.29
  ```
  signals=['probe']
  ```
- 203.176.191.34
  ```
  signals=['probe']
  ```
- Redirect: location: https://www.geo.tv/
  ```
  location: https://www.geo.tv/
  ```

### crt_sh_query (1 finding(s) across 1 target(s))
**geo.tv**
- crt_sh_query raw output (failed)
  ```
  <html>
  <head><title>502 Bad Gateway</title></head>
  <body>
  <center><h1>502 Bad Gateway</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>502 Bad Gateway</title></head>
  <body>
  <center><h1>502 Bad Gateway</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>502 Bad Gateway</title></head>
  <body>
  <center><h1>502 Bad Gateway</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>502 Bad Gateway</title></head>
  <body>
  <center><h1>502 Bad Gateway</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

### dnsenum_scan (1 finding(s) across 1 target(s))
**geo.tv**
- dnsenum_scan raw output (failed)
  ```
  Execution timed out after 600s
  ```

### dnsx_resolve (7 finding(s) across 2 target(s))
**autodiscover.geo.tv**
- autodiscover.geo.tv CNAME -> mail.geo.tv
  ```
  autodiscover.geo.tv CNAME mail.geo.tv
  ```

**geo.tv**
- 104.16.218.243
  ```
  geo.tv -> 104.16.218.243
  ```
- 104.16.219.243
  ```
  geo.tv -> 104.16.219.243
  ```
- geo.tv NS -> jack.ns.cloudflare.com
  ```
  geo.tv NS jack.ns.cloudflare.com
  ```
- geo.tv NS -> ruth.ns.cloudflare.com
  ```
  geo.tv NS ruth.ns.cloudflare.com
  ```
- geo.tv MX -> mx2.geoit.tv
  ```
  geo.tv MX mx2.geoit.tv
  ```
- geo.tv MX -> mx1.geoit.tv
  ```
  geo.tv MX mx1.geoit.tv
  ```

### domain_hunter (1 finding(s) across 1 target(s))
**geo.tv**
- geoit.tv
  ```
  method=certs; dns confidence=medium live=no
  ```

### email_security_probe (1 finding(s) across 1 target(s))
**geo.tv**
- Email security posture: geo.tv
  ```
  spf="v=spf1 include:geoit.tv -all"; dmarc="v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc.rua@geoit.tv; ruf=mailto:dmarc.ruf@geoit.tv; pct=100;
  ```

### gau_discovery (298 finding(s) across 2 target(s))
**geo.tv**
- gau_discovery: 255 additional URL(s) not stored individually
  ```
  total=555 stored=300 excluded=255
  ```
- https://geo.tv/4-21-2010
- https://geo.tv/4-23-2010
- https://geo.tv/4-27-2010
- https://geo.tv/4-28-2010
- https://geo.tv/9-18-2008/25092.htm
- https://geo.tv/latest/328931-gwyneth-paltrow-reminisces-on-the-time-she-refused-the-titanic

**www.geo.tv**
- http://www.geo.tv/
- https://www.geo.tv/amp/437451-two-men-gang-rape-girl-under-the-guise-of-providing-relief-goods-in-sanghar
- https://www.geo.tv/amp/478744-amanda-bynes-psychiatric-hold-is-reportedly-extended
- https://www.geo.tv/amp/489576-austin-butler-bonds-with-kaia-gerbers-parents-at-casual-dinner-outing
- https://www.geo.tv/amp/543200-donald-trump-is-now-cryptocurrencys-biggest-supporter-in-us
- https://www.geo.tv/amp/623578-baz-luhrmann-praises-elvis-presley-prime-goofy-side
- https://www.geo.tv/amp/627339-taylor-swift-drops-the-life-of-a-showgirl-deluxe-with-secret-studio-voice-memos
- https://www.geo.tv/amp/627917-saudi-prince-visits-karachi-expresses-interest-in-investment
- https://www.geo.tv/amp/632891-27th-amendment-bill-set-to-be-tabled-in-senate-today-after-coalition-partners-nod
- https://www.geo.tv/amp/636043-marcello-hernndez-skyler-gisondo-bring-new-energy-to-shrek-5
- https://www.geo.tv/amp/636191-kelly-stafford-gives-heartbreaking-news-to-her-fans
- https://www.geo.tv/amp/637953-queen-camilla-receives-somber-note-from-children-this-holiday-season
- https://www.geo.tv/amp/638701-pakistan-finalises-record-rs6596bn-settlement-of-power-sector-debt-says-minister
- https://www.geo.tv/amp/639107-convicted-ex-spymaster-retained-classified-documents-after-retirement
- https://www.geo.tv/amp/639343-king-charless-green-act-crumbles-as-royal-riches-come-into-focus
- https://www.geo.tv/amp/644756-glen-powell-reacts-to-being-compared-to-late-legend-robin-williams
- https://www.geo.tv/amp/646426-domhnall-gleeson-jokes-rachel-mcadams-doesnt-deserve-walk-of-fame-star
- https://www.geo.tv/amp/646452-taylor-swift-adds-another-milestone-with-songwriters-hall-of-fame-induction
- https://www.geo.tv/amp/673782-palace-reacts-to-leaked-details-from-king-charles-reunion-with-sussexes
- https://www.geo.tv/article-179667-First-PIA-flight-departs-to-evacuate-Pakistanis-from-Yemen
- https://www.geo.tv/article-190323-Option-to-use-nuclear-weapons-always-available-Asif-
- https://www.geo.tv/category/bollywood
- https://www.geo.tv/category/food
- https://www.geo.tv/category/life-style
- https://www.geo.tv/ct2017/
- https://www.geo.tv/ct2017/latest/594670-clashes-erupt-after-cricket-victory-celebrations-outside-mosque-in-india
- https://www.geo.tv/ct2017/pointstable
- https://www.geo.tv/election/candidates
- https://www.geo.tv/election/candidates/BAP
- https://www.geo.tv/election/candidates/GAP
- https://www.geo.tv/election/candidates/IPP
- https://www.geo.tv/election/candidates/PFP
- https://www.geo.tv/election/candidates/TLI
- https://www.geo.tv/election/constituency
- https://www.geo.tv/election/NA-102
- https://www.geo.tv/election/NA-169
- https://www.geo.tv/election/NA-188
- https://www.geo.tv/election/NA-200
- https://www.geo.tv/election/NA-239
- https://www.geo.tv/election/PK-31
- _(+251 more URLs — see raw tool output)_

### httpx_probe (21 finding(s) across 11 target(s))
**https://apnegn.geo.tv**
- SUCCESS
  ```
  https://apnegn.geo.tv [SUCCESS]
  ```
- https://apnegn.geo.tv

**https://apnegnu.geo.tv**
- SUCCESS
  ```
  https://apnegnu.geo.tv [SUCCESS]
  ```
- https://apnegnu.geo.tv

**https://asool.geo.tv**
- SUCCESS
  ```
  https://asool.geo.tv [SUCCESS]
  ```
- https://asool.geo.tv

**https://autodiscover.geo.tv**
- SUCCESS
  ```
  https://autodiscover.geo.tv [SUCCESS]
  ```
- https://autodiscover.geo.tv

**https://geo.tv**
- SUCCESS
  ```
  https://geo.tv [SUCCESS]
  ```
- https://geo.tv

**https://live.geo.tv**
- SUCCESS
  ```
  https://live.geo.tv [SUCCESS]
  ```
- https://live.geo.tv

**https://mail.geo.tv**
- SUCCESS
  ```
  https://mail.geo.tv [SUCCESS]
  ```
- https://mail.geo.tv

**https://ramadan.geo.tv**
- SUCCESS
  ```
  https://ramadan.geo.tv [SUCCESS]
  ```
- https://ramadan.geo.tv

**https://talent.geo.tv**
- SUCCESS
  ```
  https://talent.geo.tv [SUCCESS]
  ```
- https://talent.geo.tv

**https://urdu.geo.tv**
- SUCCESS
  ```
  https://urdu.geo.tv [SUCCESS]
  ```
- https://urdu.geo.tv

**https://www.geo.tv**
- SUCCESS
  ```
  https://www.geo.tv [SUCCESS]
  ```

### katana_crawl (6 finding(s) across 6 target(s))
**https://www.geo.tv/latest/677799-before-we-fix-the-system**
- https://www.geo.tv/latest/677799-before-we-fix-the-system

**https://www.geo.tv/latest/677900-the-wars-no-one-declared**
- https://www.geo.tv/latest/677900-the-wars-no-one-declared

**https://www.geo.tv/latest/678054-democracy-vs-democracy**
- https://www.geo.tv/latest/678054-democracy-vs-democracy

**https://www.geo.tv/latest/678249-government-by-competence**
- https://www.geo.tv/latest/678249-government-by-competence

**https://www.geo.tv/latest/678405-makkah-pact-beyond-pax-americana**
- https://www.geo.tv/latest/678405-makkah-pact-beyond-pax-americana

**https://www.geo.tv/latest/678561-reform-before-its-time**
- https://www.geo.tv/latest/678561-reform-before-its-time

### naabu_port_scan (6 finding(s) across 3 target(s))
**203.176.191.28**
- 203.176.191.28:25/tcp open
  ```
  203.176.191.28:25
  ```

**geo.tv**
- geo.tv:443/tcp open
  ```
  geo.tv:443
  ```
- geo.tv:8080/tcp open
  ```
  geo.tv:8080
  ```
- geo.tv:8443/tcp open
  ```
  geo.tv:8443
  ```
- geo.tv:80/tcp open
  ```
  geo.tv:80
  ```

**www.geo.tv**
- www.geo.tv:80/tcp open
  ```
  www.geo.tv:80
  ```

### nmap_service_scan (16 finding(s) across 3 target(s))
**mail.geo.tv**
- mail.geo.tv:80/tcp http    Microsoft IIS httpd 10.0
  ```
  80/tcp  open  http    Microsoft IIS httpd 10.0
  ```
- http-title output (mail.geo.tv:80)
  ```
  Site doesn't have a title.
  ```
- http-server-header output (mail.geo.tv:80)
  ```
  Microsoft-IIS/10.0
  ```
- mail.geo.tv:443/tcp https?
  ```
  443/tcp open  https?
  ```
- ssl-cert output (mail.geo.tv:443)
  ```
  Subject: commonName=mail.geo.tv
  Subject Alternative Name: DNS:mail.geo.tv, DNS:www.mail.geo.tv, DNS:oos.geoit.tv, DNS:autodiscover.geo.tv
  Not valid before: 2026-01-17T23:28:18
  Not valid after:  2027-02-18T23:28:18
  ```
- ssl-date output (mail.geo.tv:443)
  ```
  TLS randomness does not represent time
  ```

**mx1.geoit.tv**
- mx1.geoit.tv:25/tcp smtp    FortiMail smtpd (time zone: +0500)
  ```
  25/tcp open  smtp    FortiMail smtpd (time zone: +0500)
  ```
- smtp-commands output (mx1.geoit.tv:25)
  ```
  mx1.geoit.tv Hello [182.190.178.80], pleased to meet you, ENHANCEDSTATUSCODES, PIPELINING, 8BITMIME, SIZE 52428800, DSN, STARTTLS, DELIVERBY, HELP
  ```
- ssl-cert output (mx1.geoit.tv:25)
  ```
  Subject: commonName=FE400FT922000101/organizationName=Fortinet/stateOrProvinceName=California/countryName=US
  Not valid before: 2022-04-08T21:55:05
  Not valid after:  2056-01-19T03:14:07
  ```
- ssl-date output (mx1.geoit.tv:25)
  ```
  TLS randomness does not represent time
  ```

**mx2.geoit.tv**
- mx2.geoit.tv:25/tcp smtp    FortiMail smtpd (time zone: +0500)
  ```
  25/tcp  open  smtp    FortiMail smtpd (time zone: +0500)
  ```
- smtp-commands output (mx2.geoit.tv:25)
  ```
  SMTP EHLO mx2.geoit.tv: failed to receive data: connection closed
  ```
- ssl-cert output (mx2.geoit.tv:25)
  ```
  Subject: commonName=FE400FT922000078/organizationName=Fortinet/stateOrProvinceName=California/countryName=US
  Not valid before: 2022-04-08T21:54:55
  Not valid after:  2056-01-19T03:14:07
  ```
- mx2.geoit.tv:587/tcp smtp    FortiMail smtpd (time zone: +0500)
  ```
  587/tcp open  smtp    FortiMail smtpd (time zone: +0500)
  ```
- smtp-commands output (mx2.geoit.tv:587)
  ```
  SMTP EHLO mx2.geoit.tv: failed to receive data: connection closed
  ```
- ssl-cert output (mx2.geoit.tv:587)
  ```
  Subject: commonName=FE400FT922000078/organizationName=Fortinet/stateOrProvinceName=California/countryName=US
  Not valid before: 2022-04-08T21:54:55
  Not valid after:  2056-01-19T03:14:07
  ```

### rustscan_fast_scan (3 finding(s) across 1 target(s))
**104.16.218.243,104.16.219.243**
- 104.16.218.243:80/tcp open
  ```
  104.16.218.243:80
  Open
  ```
- 104.16.219.243:80/tcp open
  ```
  104.16.219.243:80
  Open
  ```
- 104.16.218.243:443/tcp open
  ```
  104.16.218.243:443
  Open
  ```

### subdomain_takeover_check (1 finding(s) across 1 target(s))
**geo.tv**
- Output from subdomain_takeover_check
  ```
  {
    "vulnerable": [],
    "potential": [],
    "safe": [
      "geo.tv"
    ],
    "summary": {
      "tested": 1,
      "vulnerable": 0,
      "potential": 0,
      "safe": 1
    }
  }
  ```

### subfinder_scan (32 finding(s) across 1 target(s))
**geo.tv**
- election2013.geo.tv
- newsite.geo.tv
- autodiscover.geo.tv
- live.geo.tv
- apnegnu.geo.tv
- mail.geo.tv
- asool.geo.tv
- mail3.geo.tv
- shop.geo.tv
- mx1.geo.tv
- ns2.geo.tv
- store.geo.tv
- team.geo.tv
- emm.geo.tv
- m.geo.tv
- apps.geo.tv
- geovision.geo.tv
- lab.geo.tv
- mail2.geo.tv
- urdu.geo.tv
- www.geo.tv
- www.mail.geo.tv
- ramadan.geo.tv
- ebooking.geo.tv
- sql.geo.tv
- talent.geo.tv
- _dmarc.geo.tv
- dns1.geo.tv
- fb.geo.tv
- apnegn.geo.tv
- asr.geo.tv
- dns2.geo.tv

### tlsx_inspect (2 finding(s) across 1 target(s))
**geo.tv**
- TLS geo.tv:443
  ```
  {"timestamp":"2026-08-27T12:15:27.303127656Z","host":"geo.tv","ip":"104.16.218.243","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-07-19T03:32:39Z","not_after":"2026-10-17T04:32:24Z","subject_dn":"CN=geo.tv","subject_cn":"geo.tv","subject_an":["geo.tv","*.geo.tv"],"serial":"3F:8F:D3:C6:E2:37:AA:C7:13:2B:8F:CD:F2:A3:43:DD","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"4bd239fd040a2501c35d7c4bec8e0f4e","sha1":"47eda198188974e3d64e83a8c868656cd19170b9","sha256":"754cd3e6bd70c46e1d73239c952059ce2e66d2d7ea11874e866f397991597cc4"},"wildcard_certificate":true,"tls_connection":"ctls","sni":"geo.tv"}
  ```
- TLS geo.tv:443
  ```
  {"timestamp":"2026-08-27T13:13:38.865915288Z","host":"geo.tv","ip":"104.16.219.243","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-07-19T03:32:39Z","not_after":"2026-10-17T04:32:24Z","subject_dn":"CN=geo.tv","subject_cn":"geo.tv","subject_an":["geo.tv","*.geo.tv"],"serial":"3F:8F:D3:C6:E2:37:AA:C7:13:2B:8F:CD:F2:A3:43:DD","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"4bd239fd040a2501c35d7c4bec8e0f4e","sha1":"47eda198188974e3d64e83a8c868656cd19170b9","sha256":"754cd3e6bd70c46e1d73239c952059ce2e66d2d7ea11874e866f397991597cc4"},"wildcard_certificate":true,"tls_connection":"ctls","sni":"geo.tv"}
  ```

### waybackurls_discovery (301 finding(s) across 2 target(s))
**geo.tv**
- waybackurls_discovery: 244 additional URL(s) not stored individually
  ```
  total=544 stored=300 excluded=244
  ```
- http://geo.tv/
- http://geo.tv/11-4-2009/52376.htm

**www.geo.tv**
- https://www.geo.tv/
- https://www.geo.tv
- http://www.geo.tv/1-26-2010/57883.htm
- https://www.geo.tv/1-26-2010/57883.htm
- https://www.geo.tv/11-4-2009/52376.htm
- http://www.geo.tv/4-10-2009/39529.htm
- https://www.geo.tv/4-10-2009/39529.htm
- http://www.geo.tv/5-3-2009/41241.htm
- https://www.geo.tv/5-3-2009/41241.htm
- https://www.geo.tv/9-22-2008/25443.htm
- https://www.geo.tv/about-us
- http://www.geo.tv/amankiasha/
- https://www.geo.tv/amankiasha/
- https://www.geo.tv/category/amazing
- https://www.geo.tv/category/amazing/2
- https://www.geo.tv/category/amazing/3
- https://www.geo.tv/category/amazing/9
- https://www.geo.tv/category/Blog-Sport
- https://www.geo.tv/category/business
- https://www.geo.tv/category/business/2
- https://www.geo.tv/category/business/3
- https://www.geo.tv/category/business/9
- https://www.geo.tv/category/entertainment/3
- https://www.geo.tv/category/entertainment/9
- https://www.geo.tv/category/health
- https://www.geo.tv/category/health/3
- https://www.geo.tv/category/health/9
- https://www.geo.tv/category/Opinion
- https://www.geo.tv/category/pakistan
- https://www.geo.tv/category/pakistan/2
- https://www.geo.tv/category/pakistan/3
- https://www.geo.tv/category/pakistan/9
- https://www.geo.tv/category/sci-tech
- https://www.geo.tv/category/sci-tech/2
- https://www.geo.tv/category/sci-tech/3
- https://www.geo.tv/category/sponsor
- https://www.geo.tv/category/sports
- https://www.geo.tv/category/sports/2
- https://www.geo.tv/category/sports/3
- https://www.geo.tv/category/sports/9
- _(+258 more URLs — see raw tool output)_

### well_known_probe (12 finding(s) across 12 target(s))
**https://geo.tv**
- SPA/HTML shell body — do not treat path as open API without JSON proof
  ```
  <!DOCTYPE html
  ```

**https://geo.tv/.well-known/ai-plugin.json**
- /.well-known/ai-plugin.json present [200]

**https://geo.tv/.well-known/apple-app-site-association**
- /.well-known/apple-app-site-association present [200]

**https://geo.tv/.well-known/assetlinks.json**
- /.well-known/assetlinks.json present [200]

**https://geo.tv/.well-known/change-password**
- /.well-known/change-password present [200]

**https://geo.tv/.well-known/openid-configuration**
- /.well-known/openid-configuration present [200]

**https://geo.tv/.well-known/security.txt**
- /.well-known/security.txt present [200]

**https://geo.tv/crossdomain.xml**
- /crossdomain.xml present [200]

**https://geo.tv/humans.txt**
- /humans.txt present [200]

**https://geo.tv/robots.txt**
- /robots.txt present [200]

**https://geo.tv/sitemap.xml**
- /sitemap.xml present [200]

**sitemap:**
- robots Disallow: sitemap:

### whois_lookup (3 finding(s) across 1 target(s))
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
