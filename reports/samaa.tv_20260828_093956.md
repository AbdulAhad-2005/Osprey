# Recon Report — samaa.tv
_Generated 2026-08-28 09:39 UTC_

## Summary
- Sister/associated domains: 12
- Subdomains discovered: 150
- Unique IPs: 42
- Open ports: 40
- Services identified: 1
- Orphan hosts (not clearly under seed/sisters): 124
- Total individual findings/tool outputs recorded: 651
- Some sections were capped even at report-generation size — surface is unusually large.

## Tools Executed
| Tool | Findings/Outputs |
|---|---|
| subfinder_scan | 137 |
| dnsx_resolve | 135 |
| asn_enum | 130 |
| tech_stack_analyze | 37 |
| shodan_host_info | 35 |
| cdn_origin_probe | 27 |
| nmap_service_scan | 27 |
| web_contact_harvest | 25 |
| httpx_probe | 20 |
| email_permute | 13 |
| dnsx_reverse | 12 |
| domain_hunter | 12 |
| wafw00f_scan | 11 |
| phoneinfoga | 6 |
| whois_lookup | 6 |
| nmap_custom_scan | 4 |
| holehe | 3 |
| theharvester | 3 |
| naabu_port_scan | 2 |
| tlsx_inspect | 2 |
| crt_sh_query | 1 |
| email_security_probe | 1 |
| gobuster_scan | 1 |
| origin_ip_attribution | 1 |

## Asset Overview
_Structural skeleton only — ports/services/tech shown here are what made it into structured fields. See **Detailed Findings by Tool** below for everything each tool actually returned, including unparsed output._

### Seed Domain
#### samaa.tv _seed_
##### samaa.tv
- **Ports:** samaa.tv:80, samaa.tv:443, samaa.tv:993, samaa.tv:995, samaa.tv:587, samaa.tv:110, samaa.tv:143, samaa.tv:25, samaa.tv:80/tcp open, samaa.tv:443/tcp open, 3.160.77.17:80/tcp, 13.224.236.45:80/tcp, 13.224.236.61:80/tcp, 40.99.26.178:993/tcp, 40.99.26.178:995/tcp, 40.99.26.178:587/tcp, 40.99.26.178:110/tcp, 40.99.26.178:143/tcp, 40.99.26.178:80/tcp, 40.99.26.178:25/tcp, samaa.tv:80/tcp http     Amazon CloudFront httpd, samaa.tv:443/tcp ssl/http Amazon CloudFront httpd, 40.99.27.18:993/tcp, 40.99.27.18:995/tcp, 40.99.27.18:587/tcp, 40.99.27.18:143/tcp, 40.99.27.18:80/tcp, 40.99.27.18:443/tcp, 40.99.60.8:80/tcp
- **Technologies:** SUCCESS, Amazon Cloudfront, Amazon Web Services, React, TLS TLSv1.3, Cloudfront (Amazon) WAF
- **Tags:** dns_record, fingerprint, mx, naabu, ns, passive, port, shodan, technology, tls, tls_san, waf, whois

##### *.samaa.tv
- **Tags:** osint

##### 2fimages.samaa.tv
- **Tags:** osint

##### admin.samaa.tv

##### adminpanel.samaa.tv
- **Ports:** adminpanel.samaa.tv:80, adminpanel.samaa.tv:80/tcp http    Amazon CloudFront httpd
- **Technologies:** SUCCESS, Amazon Cloudfront, Amazon Web Services, Custom JavaScript, TLS TLSv1.3, Cloudfront (Amazon) WAF
- **Tags:** fingerprint, technology, waf

##### api.samaa.tv

##### app.samaa.tv

##### autodiscover.dev.samaa.tv

##### autodiscover.elections.samaa.tv

##### autodiscover.f.samaa.tv

##### autodiscover.i.samaa.tv

##### autodiscover.inventory.samaa.tv

##### autodiscover.live.samaa.tv

##### autodiscover.practise.samaa.tv

##### autodiscover.samaa.tv
- **IPs:** 40.99.26.184
- **Ports:** autodiscover.samaa.tv:80
- **Services:** autodiscover.samaa.tv:80/tcp http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
- **Technologies:** SUCCESS
- **Tags:** cname, dns_record

##### autodiscover.sports.samaa.tv

##### autodiscover.tasks.samaa.tv

##### autodiscover.test.samaa.tv

##### autodiscover.urdu-sports.samaa.tv

##### autodiscover.urdu.samaa.tv

##### beta.samaa.tv

##### cdn.samaa.tv

##### cpanel.dev.samaa.tv

##### cpanel.elections.samaa.tv

##### cpanel.f.samaa.tv

##### cpanel.i.samaa.tv

##### cpanel.inventory.samaa.tv

##### cpanel.live.samaa.tv

##### cpanel.practise.samaa.tv

##### cpanel.sports.samaa.tv

##### cpanel.tasks.samaa.tv

##### cpanel.test.samaa.tv

##### cpanel.urdu-sports.samaa.tv

##### cpanel.urdu.samaa.tv

##### cpcalendars.dev.samaa.tv

##### cpcalendars.elections.samaa.tv

##### cpcalendars.f.samaa.tv

##### cpcalendars.i.samaa.tv

##### cpcalendars.inventory.samaa.tv

##### cpcalendars.live.samaa.tv

##### cpcalendars.practise.samaa.tv

##### cpcalendars.sports.samaa.tv

##### cpcalendars.tasks.samaa.tv

##### cpcalendars.test.samaa.tv

##### cpcalendars.urdu-sports.samaa.tv

##### cpcalendars.urdu.samaa.tv

##### cpcontacts.dev.samaa.tv

##### cpcontacts.elections.samaa.tv

##### cpcontacts.f.samaa.tv

##### cpcontacts.i.samaa.tv

##### cpcontacts.inventory.samaa.tv

##### cpcontacts.live.samaa.tv

##### cpcontacts.practise.samaa.tv

##### cpcontacts.sports.samaa.tv

##### cpcontacts.tasks.samaa.tv

##### cpcontacts.test.samaa.tv

##### cpcontacts.urdu-sports.samaa.tv

##### cpcontacts.urdu.samaa.tv

##### dev.samaa.tv

##### elections.samaa.tv

##### english.samaa.tv

##### f.samaa.tv

##### google.samaa.tv

##### gw.samaa.tv

##### i.samaa.tv

##### images.samaa.tv
- **IPs:** 13.224.236.53
- **Ports:** images.samaa.tv:80, images.samaa.tv:80/tcp http    Amazon CloudFront httpd
- **Technologies:** SUCCESS, Amazon-CloudFront, Via-Proxy, Amazon S3, Amazon Cloudfront, Amazon Web Services, TLS TLSv1.3, Cloudfront (Amazon) WAF
- **Tags:** cname, dns_record, fingerprint, ns, technology, waf

##### inventory.samaa.tv

##### jaitex2k10-1.samaa.tv

##### jaitex2k13-1.samaa.tv

##### jaitex2k13-2.samaa.tv

##### jaitex2k16-1.samaa.tv

##### jaitex2k16-2.samaa.tv

##### legacy.samaa.tv

##### live.samaa.tv

##### livewire.samaa.tv

##### local.admin.samaa.tv

##### mail.dev.samaa.tv

##### mail.elections.samaa.tv

##### mail.f.samaa.tv

##### mail.i.samaa.tv

##### mail.inventory.samaa.tv

##### mail.live.samaa.tv

##### mail.practise.samaa.tv

##### mail.samaa.tv
- **Technologies:** SUCCESS, Microsoft-HTTPAPI 2.0, RedirectLocation, Cookies, X-UA-Compatible, Microsoft HTTPAPI 2.0, TLS TLSv1.3
- **Tags:** cname, dns_record, fingerprint, technology

##### mail.sports.samaa.tv

##### mail.tasks.samaa.tv

##### mail.test.samaa.tv

##### mail.urdu-sports.samaa.tv

##### mail.urdu.samaa.tv

##### mail1.samaa.tv

##### mail2.samaa.tv

##### practise.samaa.tv

##### sftp.samaa.tv
- **IPs:** 160.30.108.246
- **Tags:** active, dns, subdomain-enum

##### sports.samaa.tv

##### tasks.samaa.tv

##### test.samaa.tv

##### testing.samaa.tv

##### urdu-sports.samaa.tv

##### urdu.samaa.tv
- **Ports:** urdu.samaa.tv:80, urdu.samaa.tv:80/tcp http    Amazon CloudFront httpd
- **Technologies:** SUCCESS, Amazon Cloudfront, Amazon Web Services, jQuery, TLS TLSv1.3, Cloudfront (Amazon) WAF
- **Tags:** fingerprint, technology, waf

##### videos.samaa.tv

##### webdisk.dev.samaa.tv

##### webdisk.elections.samaa.tv

##### webdisk.f.samaa.tv

##### webdisk.i.samaa.tv

##### webdisk.inventory.samaa.tv

##### webdisk.live.samaa.tv

##### webdisk.practise.samaa.tv

##### webdisk.sports.samaa.tv

##### webdisk.tasks.samaa.tv

##### webdisk.test.samaa.tv

##### webdisk.urdu-sports.samaa.tv

##### webdisk.urdu.samaa.tv

##### webmail.dev.samaa.tv

##### webmail.elections.samaa.tv

##### webmail.f.samaa.tv

##### webmail.i.samaa.tv

##### webmail.inventory.samaa.tv

##### webmail.live.samaa.tv

##### webmail.practise.samaa.tv

##### webmail.samaa.tv
- **Technologies:** SUCCESS, Microsoft-HTTPAPI 2.0, RedirectLocation, Cookies, X-UA-Compatible, Microsoft HTTPAPI 2.0, TLS TLSv1.3
- **Tags:** cname, dns_record, fingerprint, technology

##### webmail.sports.samaa.tv

##### webmail.tasks.samaa.tv

##### webmail.test.samaa.tv

##### webmail.urdu-sports.samaa.tv

##### webmail.urdu.samaa.tv

##### www.adminpanel.samaa.tv
- **Ports:** www.adminpanel.samaa.tv:80, www.adminpanel.samaa.tv:80/tcp http    Amazon CloudFront httpd
- **Technologies:** SUCCESS
- **Tags:** cname, dns_record

##### www.dev.samaa.tv

##### www.elections.samaa.tv

##### www.f.samaa.tv

##### www.i.samaa.tv

##### www.inventory.samaa.tv

##### www.live.samaa.tv

##### www.mail.samaa.tv

##### www.practise.samaa.tv

##### www.samaa.tv
- **IPs:** 3.160.77.125
- **Ports:** www.samaa.tv:80, www.samaa.tv:80/tcp http    Amazon CloudFront httpd
- **Technologies:** SUCCESS, Amazon Cloudfront, Amazon Web Services, React, TLS TLSv1.3, Cloudfront (Amazon) WAF
- **Tags:** fingerprint, technology, waf

##### www.sports.samaa.tv

##### www.tasks.samaa.tv

##### www.test.samaa.tv

##### www.urdu-sports.samaa.tv

##### www.urdu.samaa.tv

##### www2.samaa.tv

### Sister / Associated Domains
#### avads.live _sister_
##### avads.live
- **Tags:** domain_hunter, sister_domain

#### outlook.com _sister_
##### outlook.com
- **IPs:** 40.99.26.178, 40.99.27.18
- **Tags:** dns_record, domain_hunter, mx, ns, passive, shodan, sister_domain

##### autodiscover.outlook.com

##### hotmail-com.olc.protection.outlook.com

##### mail-am7pr02cu00203.inbound.protection.outlook.com
- **IPs:** 52.101.73.155
- **Tags:** ptr, reverse_dns

##### mail-db8pr02cu00101.inbound.protection.outlook.com
- **IPs:** 52.101.68.25
- **Tags:** ptr, reverse_dns

##### outlook-com.olc.protection.outlook.com

##### samaa-tv.mail.eo.outlook.com

#### samaa.biz _sister_
##### samaa.biz
- **Tags:** domain_hunter, sister_domain

#### samaa.com _sister_
##### samaa.com
- **Tags:** domain_hunter, sister_domain

#### samaa.io _sister_
##### samaa.io
- **Tags:** domain_hunter, sister_domain

#### samaa.net _sister_
##### samaa.net
- **Tags:** domain_hunter, sister_domain

#### samaa.org _sister_
##### samaa.org
- **Tags:** domain_hunter, sister_domain

#### sitemaps.org _sister_
##### sitemaps.org
- **Tags:** domain_hunter, sister_domain

#### awsdns-03.co.uk _sister_
##### awsdns-03.co.uk
- **Tags:** domain_hunter, sister_domain

##### ns-1565.awsdns-03.co.uk

#### awsdns-10.org _sister_
##### awsdns-10.org
- **Tags:** domain_hunter, sister_domain

##### ns-1110.awsdns-10.org

#### awsdns-27.net _sister_
##### awsdns-27.net
- **Tags:** domain_hunter, sister_domain

##### ns-729.awsdns-27.net

#### awsdns-35.com _sister_
##### awsdns-35.com
- **Tags:** domain_hunter, sister_domain

##### ns-281.awsdns-35.com

### Other Discovered Hosts
_Hosts found but not clearly linked to the seed or a sister domain._

#### 13.224.236.124
- **IPs:** 13.224.236.124
- **Tags:** dns_resolve

#### 13.224.236.129
- **IPs:** 13.224.236.129
- **Tags:** dns_resolve

#### 13.224.236.14
- **IPs:** 13.224.236.14
- **Tags:** dns_resolve

#### 13.224.236.45
- **IPs:** 13.224.236.45
- **Tags:** dns_resolve

#### 13.224.236.52
- **IPs:** 13.224.236.52
- **Tags:** dns_resolve

#### 13.224.236.53
- **IPs:** 13.224.236.53
- **Tags:** dns_resolve

#### 13.224.236.6
- **IPs:** 13.224.236.6
- **Tags:** dns_resolve

#### 13.224.236.61
- **IPs:** 13.224.236.61
- **Tags:** dns_resolve

#### 160.30.108.246
- **IPs:** 160.30.108.246
- **Tags:** dns_resolve

#### 185.206.135.204
- **IPs:** 185.206.135.204
- **Tags:** dns_resolve

#### 20.119.0.28
- **IPs:** 20.119.0.28
- **Tags:** dns_resolve

#### 204.79.197.212
- **IPs:** 204.79.197.212
- **Tags:** dns_resolve

#### 3.160.77.103
- **IPs:** 3.160.77.103
- **Tags:** dns_resolve

#### 3.160.77.125
- **IPs:** 3.160.77.125
- **Tags:** dns_resolve

#### 3.160.77.17
- **IPs:** 3.160.77.17
- **Tags:** dns_resolve

#### 3.160.77.75
- **IPs:** 3.160.77.75
- **Tags:** dns_resolve

#### 40.100.7.128
- **IPs:** 40.100.7.128
- **Tags:** dns_resolve

#### 40.104.56.130
- **IPs:** 40.104.56.130
- **Tags:** dns_resolve

#### 40.104.56.210
- **IPs:** 40.104.56.210
- **Tags:** dns_resolve

#### 40.104.66.2
- **IPs:** 40.104.66.2
- **Tags:** dns_resolve

#### 40.104.77.178
- **IPs:** 40.104.77.178
- **Tags:** dns_resolve

#### 40.104.79.2
- **IPs:** 40.104.79.2
- **Tags:** dns_resolve

#### 40.112.243.53
- **IPs:** 40.112.243.53
- **Tags:** dns_resolve

#### 40.97.22.19
- **IPs:** 40.97.22.19
- **Tags:** dns_resolve

#### 40.97.4.122
- **IPs:** 40.97.4.122
- **Tags:** dns_resolve

#### 40.97.4.98
- **IPs:** 40.97.4.98
- **Tags:** dns_resolve

#### 40.99.168.210
- **IPs:** 40.99.168.210
- **Tags:** dns_resolve

#### 40.99.26.178
- **IPs:** 40.99.26.178
- **Tags:** edge_ip

#### 40.99.26.184
- **IPs:** 40.99.26.184
- **Tags:** origin_candidate

#### 40.99.26.210
- **IPs:** 40.99.26.210
- **Tags:** edge_ip

#### 40.99.26.216
- **IPs:** 40.99.26.216
- **Tags:** edge_ip

#### 40.99.27.18
- **IPs:** 40.99.27.18
- **Tags:** origin_candidate

#### 40.99.27.2
- **IPs:** 40.99.27.2
- **Tags:** origin_candidate

#### 40.99.27.24
- **IPs:** 40.99.27.24
- **Tags:** edge_ip

#### 40.99.27.8
- **IPs:** 40.99.27.8
- **Tags:** edge_ip

#### 40.99.32.114
- **IPs:** 40.99.32.114
- **Tags:** edge_ip

#### 40.99.32.120
- **IPs:** 40.99.32.120
- **Tags:** dns_resolve

#### 40.99.60.2
- **IPs:** 40.99.60.2
- **Tags:** edge_ip

#### 40.99.60.8
- **IPs:** 40.99.60.8
- **Tags:** dns_resolve

#### 40.99.68.34
- **IPs:** 40.99.68.34
- **Tags:** dns_resolve

## Contact Info / WHOIS / OSINT
### WHOIS
- WHOIS: samaa.tv
- DNSSEC not configured on samaa.tv
- samaa.tv NS -> ns-729.awsdns-27.net
- samaa.tv NS -> ns-1565.awsdns-03.co.uk
- samaa.tv NS -> ns-1110.awsdns-10.org
- samaa.tv NS -> ns-281.awsdns-35.com

### Emails
- cmartorella@edge-security.com (via theharvester)
- s.tv@samaa.tv (via email_permute)
- samaa-tv@samaa.tv (via email_permute)
- samaa.t@samaa.tv (via email_permute)
- samaa.tv@samaa.tv (via email_permute)
- samaa@samaa.tv (via email_permute)
- samaa_tv@samaa.tv (via email_permute)
- samaat@samaa.tv (via email_permute)
- samaatv@samaa.tv (via email_permute)
- st@samaa.tv (via email_permute)
- stv@samaa.tv (via email_permute)
- tv.samaa@samaa.tv (via email_permute)
- tv@samaa.tv (via email_permute)
- tvsamaa@samaa.tv (via email_permute)

### Phone Numbers
- 01 02 03 04 05 (via web_contact_harvest)
- 2023 2022 2021 (via web_contact_harvest)
- 2026 2025 2024 (via web_contact_harvest)

### Organizations / People / Usernames
- [person] SAMAA TV
- [username] samaatvnews
- [username] SAMAATV
- [username] samaadigital
- [username] samaa-tv
- [username] tweet
- [username] sharing
- [username] ForeignOfficePk
- [username] pin
- [username] AusHCPak

### Subdomains via theHarvester
- *.samaa.tv
- 2fimages.samaa.tv

## Vulnerabilities
_None confirmed yet — this run focused on recon/surface mapping._

## Detailed Findings by Tool
_Everything each tool returned, grouped by target — including raw/unparsed output. This is the full technical record; the sections above are curated summaries of it._

### asn_enum (130 finding(s) across 65 target(s))
**13.224.236.124**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.124   | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.124   | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.129**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.129   | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.129   | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.14**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.14    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.14    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.45**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.45    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.45    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.52**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.52    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.52    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.53**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.53    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.53    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.6**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.6     | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.6     | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**13.224.236.61**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 13.224.236.61    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 13.224.236.0/24 (AS16509)
  ```
  16509   | 13.224.236.61    | 13.224.236.0/24     | US | arin     | 2019-10-01 | AMAZON-02 - Amazon.com, Inc., US
  ```

**160.30.108.246**
- AS133551 ORIGINNET-AS-AP - OriginNet, PK
  ```
  133551  | 160.30.108.246   | 160.30.108.0/24     | PK | apnic    | 2024-08-13 | ORIGINNET-AS-AP - OriginNet, PK
  ```
- Netblock 160.30.108.0/24 (AS133551)
  ```
  133551  | 160.30.108.246   | 160.30.108.0/24     | PK | apnic    | 2024-08-13 | ORIGINNET-AS-AP - OriginNet, PK
  ```

**185.206.135.204**
- AS202105 WafaiNet-AS - Al wafai International For Communication and Information Technology LLC, SA
  ```
  202105  | 185.206.135.204  | 185.206.135.0/24    | SA | ripencc  | 2017-06-01 | WafaiNet-AS - Al wafai International For Communication and Information Technology LLC, SA
  ```
- Netblock 185.206.135.0/24 (AS202105)
  ```
  202105  | 185.206.135.204  | 185.206.135.0/24    | SA | ripencc  | 2017-06-01 | WafaiNet-AS - Al wafai International For Communication and Information Technology LLC, SA
  ```

**20.119.0.28**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 20.119.0.28      | 20.64.0.0/10        | US | arin     | 2017-10-18 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 20.64.0.0/10 (AS8075)
  ```
  8075    | 20.119.0.28      | 20.64.0.0/10        | US | arin     | 2017-10-18 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**204.79.197.212**
- AS8068 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8068    | 204.79.197.212   | 204.79.197.0/24     | US | arin     | 1994-12-15 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 204.79.197.0/24 (AS8068)
  ```
  8068    | 204.79.197.212   | 204.79.197.0/24     | US | arin     | 1994-12-15 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**3.160.77.103**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 3.160.77.103     | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 3.160.76.0/23 (AS16509)
  ```
  16509   | 3.160.77.103     | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```

**3.160.77.125**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 3.160.77.125     | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 3.160.76.0/23 (AS16509)
  ```
  16509   | 3.160.77.125     | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```

**3.160.77.17**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 3.160.77.17      | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 3.160.76.0/23 (AS16509)
  ```
  16509   | 3.160.77.17      | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```

**3.160.77.75**
- AS16509 AMAZON-02 - Amazon.com, Inc., US
  ```
  16509   | 3.160.77.75      | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```
- Netblock 3.160.76.0/23 (AS16509)
  ```
  16509   | 3.160.77.75      | 3.160.76.0/23       | US | arin     | 2018-06-25 | AMAZON-02 - Amazon.com, Inc., US
  ```

**40.100.7.128**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.100.7.128     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.100.7.128     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.104.56.130**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.104.56.130    | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.104.0.0/15 (AS8075)
  ```
  8075    | 40.104.56.130    | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.104.56.210**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.104.56.210    | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.104.0.0/15 (AS8075)
  ```
  8075    | 40.104.56.210    | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.104.66.2**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.104.66.2      | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.104.0.0/15 (AS8075)
  ```
  8075    | 40.104.66.2      | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.104.77.178**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.104.77.178    | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.104.0.0/15 (AS8075)
  ```
  8075    | 40.104.77.178    | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.104.79.2**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.104.79.2      | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.104.0.0/15 (AS8075)
  ```
  8075    | 40.104.79.2      | 40.104.0.0/15       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.112.243.53**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.112.243.53    | 40.112.0.0/13       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.112.0.0/13 (AS8075)
  ```
  8075    | 40.112.243.53    | 40.112.0.0/13       | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.97.22.19**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.97.22.19      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.97.22.19      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.97.4.122**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.97.4.122      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.97.4.122      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.97.4.98**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.97.4.98       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.97.4.98       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.168.210**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.168.210    | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.168.210    | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.26.178**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.26.178     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.26.178     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.26.184**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.26.184     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.26.184     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.26.210**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.26.210     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.26.210     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.26.216**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.26.216     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.26.216     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.27.18**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.27.18      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.27.18      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.27.2**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.27.2       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.27.2       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.27.24**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.27.24      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.27.24      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.27.8**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.27.8       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.27.8       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.32.114**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.32.114     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.32.114     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.32.120**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.32.120     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.32.120     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.60.2**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.60.2       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.60.2       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.60.8**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.60.8       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.60.8       | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.68.34**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.68.34      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.68.34      | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.178**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.178     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.178     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.184**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.184     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.184     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.194**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.194     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.194     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.200**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.200     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.200     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.210**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.210     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.210     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.216**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.216     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.216     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.226**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.226     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.226     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**40.99.70.232**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 40.99.70.232     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 40.96.0.0/13 (AS8075)
  ```
  8075    | 40.99.70.232     | 40.96.0.0/13        | US | arin     | 2015-02-23 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.101.68.25**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.101.68.25     | 52.96.0.0/12        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/12 (AS8075)
  ```
  8075    | 52.101.68.25     | 52.96.0.0/12        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.101.73.155**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.101.73.155    | 52.96.0.0/12        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/12 (AS8075)
  ```
  8075    | 52.101.73.155    | 52.96.0.0/12        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.111.82**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.111.82     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.111.82     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.172.98**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.172.98     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.172.98     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.214.50**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.214.50     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.214.50     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.222.194**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.222.194    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.222.194    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.222.226**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.222.226    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.222.226    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.223.2**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.223.2      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.223.2      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.228.130**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.228.130    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.228.130    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.229.242**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.229.242    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.229.242    | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.96.91.34**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.96.91.34      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.96.91.34      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.97.92.114**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.97.92.114     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.97.92.114     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.97.92.146**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.97.92.146     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.97.92.146     | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.98.61.34**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.98.61.34      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.98.61.34      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.98.61.40**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.98.61.40      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.98.61.40      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.98.61.50**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.98.61.50      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.98.61.50      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

**52.98.61.56**
- AS8075 MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
  8075    | 52.98.61.56      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```
- Netblock 52.96.0.0/14 (AS8075)
  ```
  8075    | 52.98.61.56      | 52.96.0.0/14        | US | arin     | 2015-11-24 | MICROSOFT-CORP-MSN-AS-BLOCK - Microsoft Corporation, US
  ```

### cdn_origin_probe (27 finding(s) across 9 target(s))
**adminpanel.samaa.tv**
- CDN hint: cloudfront
- Redirect: Location: https://adminpanel.samaa.tv/
  ```
  Location: https://adminpanel.samaa.tv/
  ```

**autodiscover.samaa.tv**
- 40.99.27.24
- 40.99.26.216
- 40.99.27.8
- Redirect: Location: https://autodiscover.samaa.tv/
  ```
  Location: https://autodiscover.samaa.tv/
  ```

**images.samaa.tv**
- CDN hint: cloudfront
- Redirect: Location: https://images.samaa.tv/
  ```
  Location: https://images.samaa.tv/
  ```

**mail.samaa.tv**
- 40.99.60.2
- 40.99.32.114
- 52.98.61.50
- Redirect: Location: https://mail.samaa.tv/
  ```
  Location: https://mail.samaa.tv/
  ```

**samaa.tv**
- CDN hint: cloudfront
- 52.101.68.25
  ```
  signals=['probe']
  ```
- 40.99.27.2
  ```
  signals=['probe']
  ```
- 40.99.27.18
  ```
  signals=['probe']
  ```
- 40.99.26.184
  ```
  signals=['probe']
  ```
- Redirect: Location: https://samaa.tv/
  ```
  Location: https://samaa.tv/
  ```

**urdu.samaa.tv**
- CDN hint: cloudfront
- Redirect: Location: https://urdu.samaa.tv/
  ```
  Location: https://urdu.samaa.tv/
  ```

**webmail.samaa.tv**
- 40.99.26.178
- 40.99.26.210
- 40.99.70.210
  ```
  signals=['probe']
  ```
- Redirect: Location: https://webmail.samaa.tv/
  ```
  Location: https://webmail.samaa.tv/
  ```

**www.adminpanel.samaa.tv**
- CDN hint: cloudfront

**www.samaa.tv**
- CDN hint: cloudfront
- Redirect: Location: https://www.samaa.tv/
  ```
  Location: https://www.samaa.tv/
  ```

### crt_sh_query (1 finding(s) across 1 target(s))
**samaa.tv**
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

### dnsx_resolve (135 finding(s) across 22 target(s))
**attachment.outlook.live.net**
- attachment.outlook.live.net CNAME -> outlook.office365.com
  ```
  attachment.outlook.live.net CNAME outlook.office365.com
  ```
- attachment.outlook.live.net CNAME -> outlook.cloud.microsoft
  ```
  attachment.outlook.live.net CNAME outlook.cloud.microsoft
  ```
- attachment.outlook.live.net CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  attachment.outlook.live.net CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- attachment.outlook.live.net CNAME -> outlook.ms-acdc.office.com
  ```
  attachment.outlook.live.net CNAME outlook.ms-acdc.office.com
  ```
- attachment.outlook.live.net CNAME -> dxb-efz.ms-acdc.office.com
  ```
  attachment.outlook.live.net CNAME dxb-efz.ms-acdc.office.com
  ```
- attachment.outlook.live.net CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  attachment.outlook.live.net CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**attachment.outlook.office.net**
- 40.99.68.34
  ```
  attachment.outlook.office.net -> 40.99.68.34
  ```
- attachment.outlook.office.net CNAME -> edge-attachment.outlook.office365.com
  ```
  attachment.outlook.office.net CNAME edge-attachment.outlook.office365.com
  ```
- attachment.outlook.office.net CNAME -> outlook.office365.com
  ```
  attachment.outlook.office.net CNAME outlook.office365.com
  ```
- attachment.outlook.office.net CNAME -> outlook.cloud.microsoft
  ```
  attachment.outlook.office.net CNAME outlook.cloud.microsoft
  ```
- attachment.outlook.office.net CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  attachment.outlook.office.net CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- attachment.outlook.office.net CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  attachment.outlook.office.net CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**attachment.outlook.officeppe.net**
- 204.79.197.212
  ```
  attachment.outlook.officeppe.net -> 204.79.197.212
  ```
- attachment.outlook.officeppe.net CNAME -> sdfpilot.live.com
  ```
  attachment.outlook.officeppe.net CNAME sdfpilot.live.com
  ```
- attachment.outlook.officeppe.net CNAME -> a-0010.a-msedge.net
  ```
  attachment.outlook.officeppe.net CNAME a-0010.a-msedge.net
  ```

**attachments-sdf.office.net**
- 40.97.4.98
  ```
  attachments-sdf.office.net -> 40.97.4.98
  ```
- 40.97.4.122
  ```
  attachments-sdf.office.net -> 40.97.4.122
  ```
- attachments-sdf.office.net CNAME -> outlook-sdf.office.com
  ```
  attachments-sdf.office.net CNAME outlook-sdf.office.com
  ```
- attachments-sdf.office.net CNAME -> sdf.outlook.cloud.microsoft
  ```
  attachments-sdf.office.net CNAME sdf.outlook.cloud.microsoft
  ```
- attachments-sdf.office.net CNAME -> acdcatm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
  attachments-sdf.office.net CNAME acdcatm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
- attachments-sdf.office.net CNAME -> atm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
  attachments-sdf.office.net CNAME atm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
- attachments-sdf.office.net CNAME -> shed.outlook.acdc.sdf.tm.svc.cloud.microsoft
  ```
  attachments-sdf.office.net CNAME shed.outlook.acdc.sdf.tm.svc.cloud.microsoft
  ```

**attachments.office.net**
- attachments.office.net CNAME -> substrate.office.com
  ```
  attachments.office.net CNAME substrate.office.com
  ```
- attachments.office.net CNAME -> outlook.cloud.microsoft
  ```
  attachments.office.net CNAME outlook.cloud.microsoft
  ```
- attachments.office.net CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  attachments.office.net CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- attachments.office.net CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  attachments.office.net CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**autodiscover.samaa.tv**
- 40.99.32.120
  ```
  autodiscover.samaa.tv -> 40.99.32.120
  ```
- 40.99.60.8
  ```
  autodiscover.samaa.tv -> 40.99.60.8
  ```
- 40.99.70.184
  ```
  autodiscover.samaa.tv -> 40.99.70.184
  ```
- 40.99.70.200
  ```
  autodiscover.samaa.tv -> 40.99.70.200
  ```
- 40.99.70.216
  ```
  autodiscover.samaa.tv -> 40.99.70.216
  ```
- 40.99.70.232
  ```
  autodiscover.samaa.tv -> 40.99.70.232
  ```
- 52.98.61.40
  ```
  autodiscover.samaa.tv -> 52.98.61.40
  ```
- 52.98.61.56
  ```
  autodiscover.samaa.tv -> 52.98.61.56
  ```
- autodiscover.samaa.tv CNAME -> autodiscover.outlook.com
  ```
  autodiscover.samaa.tv CNAME autodiscover.outlook.com
  ```
- autodiscover.samaa.tv CNAME -> autodiscover.outlook.cloud.microsoft
  ```
  autodiscover.samaa.tv CNAME autodiscover.outlook.cloud.microsoft
  ```
- autodiscover.samaa.tv CNAME -> acdcatm.autodiscover.mira.tm.svc.cloud.microsoft
  ```
  autodiscover.samaa.tv CNAME acdcatm.autodiscover.mira.tm.svc.cloud.microsoft
  ```
- autodiscover.samaa.tv CNAME -> atm.autodiscover.mira.tm.svc.cloud.microsoft
  ```
  autodiscover.samaa.tv CNAME atm.autodiscover.mira.tm.svc.cloud.microsoft
  ```

**ccs.login.microsoftonline.com**
- ccs.login.microsoftonline.com CNAME -> outlook.office365.com
  ```
  ccs.login.microsoftonline.com CNAME outlook.office365.com
  ```
- ccs.login.microsoftonline.com CNAME -> outlook.cloud.microsoft
  ```
  ccs.login.microsoftonline.com CNAME outlook.cloud.microsoft
  ```
- ccs.login.microsoftonline.com CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  ccs.login.microsoftonline.com CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- ccs.login.microsoftonline.com CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  ccs.login.microsoftonline.com CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```
- ccs.login.microsoftonline.com CNAME -> outlook.ms-acdc.office.com
  ```
  ccs.login.microsoftonline.com CNAME outlook.ms-acdc.office.com
  ```
- ccs.login.microsoftonline.com CNAME -> dxb-efz.ms-acdc.office.com
  ```
  ccs.login.microsoftonline.com CNAME dxb-efz.ms-acdc.office.com
  ```

**hotmail.com**
- hotmail.com NS -> ns1-205.azure-dns.com
  ```
  hotmail.com NS ns1-205.azure-dns.com
  ```
- hotmail.com NS -> ns2-205.azure-dns.net
  ```
  hotmail.com NS ns2-205.azure-dns.net
  ```
- hotmail.com NS -> ns3-205.azure-dns.org
  ```
  hotmail.com NS ns3-205.azure-dns.org
  ```
- hotmail.com NS -> ns4-205.azure-dns.info
  ```
  hotmail.com NS ns4-205.azure-dns.info
  ```
- hotmail.com MX -> hotmail-com.olc.protection.outlook.com
  ```
  hotmail.com MX hotmail-com.olc.protection.outlook.com
  ```

**images.samaa.tv**
- 13.224.236.61
  ```
  images.samaa.tv -> 13.224.236.61
  ```
- 13.224.236.124
  ```
  images.samaa.tv -> 13.224.236.124
  ```
- 13.224.236.6
  ```
  images.samaa.tv -> 13.224.236.6
  ```
- 13.224.236.53
  ```
  images.samaa.tv -> 13.224.236.53
  ```
- images.samaa.tv CNAME -> d2wrtqbkk7w74p.cloudfront.net
  ```
  images.samaa.tv CNAME d2wrtqbkk7w74p.cloudfront.net
  ```
- images.samaa.tv NS -> ns-312.awsdns-39.com
  ```
  images.samaa.tv NS ns-312.awsdns-39.com
  ```
- images.samaa.tv NS -> ns-824.awsdns-39.net
  ```
  images.samaa.tv NS ns-824.awsdns-39.net
  ```
- images.samaa.tv NS -> ns-1183.awsdns-19.org
  ```
  images.samaa.tv NS ns-1183.awsdns-19.org
  ```
- images.samaa.tv NS -> ns-1764.awsdns-28.co.uk
  ```
  images.samaa.tv NS ns-1764.awsdns-28.co.uk
  ```

**legacy.samaa.tv**
- 185.206.135.204
  ```
  legacy.samaa.tv -> 185.206.135.204
  ```

**mail.samaa.tv**
- 40.99.70.178
  ```
  mail.samaa.tv -> 40.99.70.178
  ```
- 40.99.70.226
  ```
  mail.samaa.tv -> 40.99.70.226
  ```
- 52.98.61.34
  ```
  mail.samaa.tv -> 52.98.61.34
  ```
- 40.99.70.194
  ```
  mail.samaa.tv -> 40.99.70.194
  ```
- mail.samaa.tv CNAME -> outlook.office.com
  ```
  mail.samaa.tv CNAME outlook.office.com
  ```
- mail.samaa.tv CNAME -> outlook.cloud.microsoft
  ```
  mail.samaa.tv CNAME outlook.cloud.microsoft
  ```
- mail.samaa.tv CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  mail.samaa.tv CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- mail.samaa.tv CNAME -> outlook.ms-acdc.office.com
  ```
  mail.samaa.tv CNAME outlook.ms-acdc.office.com
  ```
- mail.samaa.tv CNAME -> dxb-efz.ms-acdc.office.com
  ```
  mail.samaa.tv CNAME dxb-efz.ms-acdc.office.com
  ```
- mail.samaa.tv CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  mail.samaa.tv CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**mail.services.live.com**
- mail.services.live.com CNAME -> outlook.office365.com
  ```
  mail.services.live.com CNAME outlook.office365.com
  ```
- mail.services.live.com CNAME -> outlook.cloud.microsoft
  ```
  mail.services.live.com CNAME outlook.cloud.microsoft
  ```
- mail.services.live.com CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  mail.services.live.com CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- mail.services.live.com CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  mail.services.live.com CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**office365.com**
- 20.119.0.28
  ```
  office365.com -> 20.119.0.28
  ```
- 40.112.243.53
  ```
  office365.com -> 40.112.243.53
  ```
- office365.com NS -> ns4-07.azure-dns.info
  ```
  office365.com NS ns4-07.azure-dns.info
  ```
- office365.com NS -> ns2-07.azure-dns.net
  ```
  office365.com NS ns2-07.azure-dns.net
  ```
- office365.com NS -> ns3-07.azure-dns.org
  ```
  office365.com NS ns3-07.azure-dns.org
  ```
- office365.com NS -> ns1-07.azure-dns.com
  ```
  office365.com NS ns1-07.azure-dns.com
  ```

**outlook.com**
- 52.96.111.82
  ```
  outlook.com -> 52.96.111.82
  ```
- 52.96.172.98
  ```
  outlook.com -> 52.96.172.98
  ```
- 52.96.214.50
  ```
  outlook.com -> 52.96.214.50
  ```
- 52.96.222.194
  ```
  outlook.com -> 52.96.222.194
  ```
- 52.96.222.226
  ```
  outlook.com -> 52.96.222.226
  ```
- 52.96.223.2
  ```
  outlook.com -> 52.96.223.2
  ```
- 52.96.228.130
  ```
  outlook.com -> 52.96.228.130
  ```
- 52.96.229.242
  ```
  outlook.com -> 52.96.229.242
  ```
- 52.96.91.34
  ```
  outlook.com -> 52.96.91.34
  ```
- outlook.com NS -> ns3-05.azure-dns.org
  ```
  outlook.com NS ns3-05.azure-dns.org
  ```
- outlook.com NS -> ns4-05.azure-dns.info
  ```
  outlook.com NS ns4-05.azure-dns.info
  ```
- outlook.com NS -> ns1-05.azure-dns.com
  ```
  outlook.com NS ns1-05.azure-dns.com
  ```
- outlook.com NS -> ns2-05.azure-dns.net
  ```
  outlook.com NS ns2-05.azure-dns.net
  ```
- outlook.com MX -> outlook-com.olc.protection.outlook.com
  ```
  outlook.com MX outlook-com.olc.protection.outlook.com
  ```

**outlook.office.com**
- outlook.office.com CNAME -> outlook.cloud.microsoft
  ```
  outlook.office.com CNAME outlook.cloud.microsoft
  ```
- outlook.office.com CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  outlook.office.com CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- outlook.office.com CNAME -> outlook.ms-acdc.office.com
  ```
  outlook.office.com CNAME outlook.ms-acdc.office.com
  ```
- outlook.office.com CNAME -> dxb-efz.ms-acdc.office.com
  ```
  outlook.office.com CNAME dxb-efz.ms-acdc.office.com
  ```
- outlook.office.com CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  outlook.office.com CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**samaa.tv**
- 3.160.77.125
  ```
  samaa.tv -> 3.160.77.125
  ```
- 3.160.77.75
  ```
  samaa.tv -> 3.160.77.75
  ```
- 3.160.77.103
  ```
  samaa.tv -> 3.160.77.103
  ```
- 3.160.77.17
  ```
  samaa.tv -> 3.160.77.17
  ```
- samaa.tv MX -> samaa-tv.mail.eo.outlook.com
  ```
  samaa.tv MX samaa-tv.mail.eo.outlook.com
  ```

**sftp.samaa.tv**
- 160.30.108.246
  ```
  sftp.samaa.tv -> 160.30.108.246
  ```

**substrate-sdf.office.com**
- 40.97.22.19
  ```
  substrate-sdf.office.com -> 40.97.22.19
  ```
- 40.99.168.210
  ```
  substrate-sdf.office.com -> 40.99.168.210
  ```
- substrate-sdf.office.com CNAME -> sdf.outlook.cloud.microsoft
  ```
  substrate-sdf.office.com CNAME sdf.outlook.cloud.microsoft
  ```
- substrate-sdf.office.com CNAME -> acdcatm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
  substrate-sdf.office.com CNAME acdcatm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
- substrate-sdf.office.com CNAME -> shed.outlook.acdc.sdf.tm.svc.cloud.microsoft
  ```
  substrate-sdf.office.com CNAME shed.outlook.acdc.sdf.tm.svc.cloud.microsoft
  ```
- substrate-sdf.office.com CNAME -> atm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```
  substrate-sdf.office.com CNAME atm.outlook.mira.sdf.tm.svc.cloud.microsoft
  ```

**substrate.office.com**
- substrate.office.com CNAME -> outlook.cloud.microsoft
  ```
  substrate.office.com CNAME outlook.cloud.microsoft
  ```
- substrate.office.com CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  substrate.office.com CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- substrate.office.com CNAME -> outlook.ms-acdc.office.com
  ```
  substrate.office.com CNAME outlook.ms-acdc.office.com
  ```
- substrate.office.com CNAME -> dxb-efz.ms-acdc.office.com
  ```
  substrate.office.com CNAME dxb-efz.ms-acdc.office.com
  ```
- substrate.office.com CNAME -> doh-efz.ms-acdc.office.com
  ```
  substrate.office.com CNAME doh-efz.ms-acdc.office.com
  ```
- substrate.office.com CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  substrate.office.com CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```

**urdu.samaa.tv**
- 13.224.236.14
  ```
  urdu.samaa.tv -> 13.224.236.14
  ```
- 13.224.236.45
  ```
  urdu.samaa.tv -> 13.224.236.45
  ```
- 13.224.236.52
  ```
  urdu.samaa.tv -> 13.224.236.52
  ```
- 13.224.236.129
  ```
  urdu.samaa.tv -> 13.224.236.129
  ```

**webmail.samaa.tv**
- 40.100.7.128
  ```
  webmail.samaa.tv -> 40.100.7.128
  ```
- 40.104.56.130
  ```
  webmail.samaa.tv -> 40.104.56.130
  ```
- 40.104.56.210
  ```
  webmail.samaa.tv -> 40.104.56.210
  ```
- 40.104.66.2
  ```
  webmail.samaa.tv -> 40.104.66.2
  ```
- 40.104.77.178
  ```
  webmail.samaa.tv -> 40.104.77.178
  ```
- 40.104.79.2
  ```
  webmail.samaa.tv -> 40.104.79.2
  ```
- 52.97.92.114
  ```
  webmail.samaa.tv -> 52.97.92.114
  ```
- 52.97.92.146
  ```
  webmail.samaa.tv -> 52.97.92.146
  ```
- webmail.samaa.tv CNAME -> outlook.office.com
  ```
  webmail.samaa.tv CNAME outlook.office.com
  ```
- webmail.samaa.tv CNAME -> outlook.cloud.microsoft
  ```
  webmail.samaa.tv CNAME outlook.cloud.microsoft
  ```
- webmail.samaa.tv CNAME -> acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
  webmail.samaa.tv CNAME acdcatm.outlook.mira.tm.svc.cloud.microsoft
  ```
- webmail.samaa.tv CNAME -> atm.outlook.mira.tm.svc.cloud.microsoft
  ```
  webmail.samaa.tv CNAME atm.outlook.mira.tm.svc.cloud.microsoft
  ```
- webmail.samaa.tv CNAME -> outlook.ms-acdc.office.com
  ```
  webmail.samaa.tv CNAME outlook.ms-acdc.office.com
  ```
- webmail.samaa.tv CNAME -> dxb-efz.ms-acdc.office.com
  ```
  webmail.samaa.tv CNAME dxb-efz.ms-acdc.office.com
  ```

**www.adminpanel.samaa.tv**
- www.adminpanel.samaa.tv CNAME -> adminpanel.samaa.tv
  ```
  www.adminpanel.samaa.tv CNAME adminpanel.samaa.tv
  ```

### dnsx_reverse (12 finding(s) across 12 target(s))
**13.224.236.124**
- server-13-224-236-124.dxb53.r.cloudfront.net
  ```
  13.224.236.124 PTR server-13-224-236-124.dxb53.r.cloudfront.net
  ```

**13.224.236.129**
- server-13-224-236-129.dxb53.r.cloudfront.net
  ```
  13.224.236.129 PTR server-13-224-236-129.dxb53.r.cloudfront.net
  ```

**13.224.236.14**
- server-13-224-236-14.dxb53.r.cloudfront.net
  ```
  13.224.236.14 PTR server-13-224-236-14.dxb53.r.cloudfront.net
  ```

**13.224.236.52**
- server-13-224-236-52.dxb53.r.cloudfront.net
  ```
  13.224.236.52 PTR server-13-224-236-52.dxb53.r.cloudfront.net
  ```

**13.224.236.53**
- server-13-224-236-53.dxb53.r.cloudfront.net
  ```
  13.224.236.53 PTR server-13-224-236-53.dxb53.r.cloudfront.net
  ```

**13.224.236.6**
- server-13-224-236-6.dxb53.r.cloudfront.net
  ```
  13.224.236.6 PTR server-13-224-236-6.dxb53.r.cloudfront.net
  ```

**204.79.197.212**
- a-0010.a-msedge.net
  ```
  204.79.197.212 PTR a-0010.a-msedge.net
  ```

**3.160.77.103**
- server-3-160-77-103.dxb53.r.cloudfront.net
  ```
  3.160.77.103 PTR server-3-160-77-103.dxb53.r.cloudfront.net
  ```

**3.160.77.125**
- server-3-160-77-125.dxb53.r.cloudfront.net
  ```
  3.160.77.125 PTR server-3-160-77-125.dxb53.r.cloudfront.net
  ```

**3.160.77.75**
- server-3-160-77-75.dxb53.r.cloudfront.net
  ```
  3.160.77.75 PTR server-3-160-77-75.dxb53.r.cloudfront.net
  ```

**52.101.68.25**
- mail-db8pr02cu00101.inbound.protection.outlook.com
  ```
  52.101.68.25 PTR mail-db8pr02cu00101.inbound.protection.outlook.com
  ```

**52.101.73.155**
- mail-am7pr02cu00203.inbound.protection.outlook.com
  ```
  52.101.73.155 PTR mail-am7pr02cu00203.inbound.protection.outlook.com
  ```

### domain_hunter (12 finding(s) across 1 target(s))
**samaa.tv**
- avads.live
  ```
  method=site_scrape; live_probe confidence=low live=yes
  ```
- outlook.com
  ```
  method=dns; live_probe confidence=low live=yes
  ```
- samaa.biz
  ```
  method=tld_variant; live_probe confidence=low live=yes
  ```
- samaa.com
  ```
  method=tld_variant; live_probe confidence=low live=yes
  ```
- samaa.io
  ```
  method=tld_variant; live_probe confidence=low live=yes
  ```
- samaa.net
  ```
  method=tld_variant; live_probe confidence=low live=yes
  ```
- samaa.org
  ```
  method=tld_variant; live_probe confidence=low live=yes
  ```
- sitemaps.org
  ```
  method=site_scrape; live_probe confidence=low live=yes
  ```
- awsdns-03.co.uk
  ```
  method=dns confidence=low live=no
  ```
- awsdns-10.org
  ```
  method=dns confidence=low live=no
  ```
- awsdns-27.net
  ```
  method=dns confidence=low live=no
  ```
- awsdns-35.com
  ```
  method=dns confidence=low live=no
  ```

### email_permute (13 finding(s) across 1 target(s))
**samaa.tv**
- s.tv@samaa.tv
- samaa-tv@samaa.tv
- samaa.t@samaa.tv
- samaa.tv@samaa.tv
- samaa@samaa.tv
- samaa_tv@samaa.tv
- samaat@samaa.tv
- samaatv@samaa.tv
- st@samaa.tv
- stv@samaa.tv
- tv.samaa@samaa.tv
- tv@samaa.tv
- tvsamaa@samaa.tv

### email_security_probe (1 finding(s) across 1 target(s))
**samaa.tv**
- Email security posture: samaa.tv
  ```
  spf="v=spf1 include:spf.protection.outlook.com ip4:202.141.235.212 -all"; dmarc="v=DMARC1; p=reject; pct=100; rua=mailto:report.admin@samaa.tv"
  ```

### gobuster_scan (1 finding(s) across 1 target(s))
**samaa.tv**
- sftp.samaa.tv
  ```
  sftp.samaa.tv 160.30.108.246
  ```

### holehe (3 finding(s) across 1 target(s))
**(engagement-wide)**
- registered at twitter.com
- registered at Email
- registered at office365.com

### httpx_probe (20 finding(s) across 11 target(s))
**http://autodiscover.samaa.tv**
- SUCCESS
  ```
  http://autodiscover.samaa.tv [SUCCESS]
  ```
- http://autodiscover.samaa.tv

**http://www.adminpanel.samaa.tv**
- SUCCESS
  ```
  http://www.adminpanel.samaa.tv [SUCCESS]
  ```
- http://www.adminpanel.samaa.tv

**https://adminpanel.samaa.tv**
- SUCCESS
  ```
  https://adminpanel.samaa.tv [SUCCESS]
  ```
- https://adminpanel.samaa.tv

**https://images.samaa.tv**
- SUCCESS
  ```
  https://images.samaa.tv [SUCCESS]
  ```
- https://images.samaa.tv

**https://mail.samaa.tv**
- SUCCESS
  ```
  https://mail.samaa.tv [SUCCESS]
  ```
- https://mail.samaa.tv

**https://samaa.tv**
- SUCCESS
  ```
  https://samaa.tv [SUCCESS]
  ```
- https://samaa.tv

**https://urdu.samaa.tv**
- SUCCESS
  ```
  https://urdu.samaa.tv [SUCCESS]
  ```
- https://urdu.samaa.tv

**https://webmail.samaa.tv**
- SUCCESS
  ```
  https://webmail.samaa.tv [SUCCESS]
  ```
- https://webmail.samaa.tv

**https://www.samaa.tv**
- SUCCESS
  ```
  https://www.samaa.tv [SUCCESS]
  ```
- https://www.samaa.tv

**legacy.samaa.tv**
- Output from httpx_probe
  ```
  http://legacy.samaa.tv [FAILED]
  ```

**sftp.samaa.tv**
- Output from httpx_probe
  ```
  http://sftp.samaa.tv [FAILED]
  ```

### naabu_port_scan (2 finding(s) across 1 target(s))
**samaa.tv**
- samaa.tv:80/tcp open
  ```
  samaa.tv:80
  ```
- samaa.tv:443/tcp open
  ```
  samaa.tv:443
  ```

### nmap_custom_scan (4 finding(s) across 4 target(s))
**legacy.samaa.tv**
- Output from nmap_custom_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-27 15:56 +0000
  Nmap scan report for legacy.samaa.tv (185.206.135.204)
  Host is up.
  All 100 scanned ports on legacy.samaa.tv (185.206.135.204) are in ignored states.
  Not shown: 100 filtered tcp ports (no-response)
  
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 22.22 seconds
  ```

**mail.samaa.tv**
- Output from nmap_custom_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-27 15:56 +0000
  Nmap scan report for mail.samaa.tv (52.98.61.50)
  Host is up (0.046s latency).
  Other addresses for mail.samaa.tv (not scanned): 2603:1046:c0c:c0d::2 2603:1046:c0c:c11::2 2603:1046:c0c:c0f::2 2603:1046:c0c:c10::2 2603:1046:c0c:c0e::2 2603:1046:c0c:814::2 2603:1046:c0c:c0c::2 2603:1046:c0c:815::2 40.99.70.226 40.99.70.178 40.99.32.114 40.99.60.2 52.98.61.34 40.99.70.194 40.99.70.210
  Skipping host mail.samaa.tv (52.98.61.50) due to host timeout
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 93.29 seconds
  ```

**sftp.samaa.tv**
- Output from nmap_custom_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-27 15:56 +0000
  Nmap scan report for sftp.samaa.tv (160.30.108.246)
  Host is up.
  All 100 scanned ports on sftp.samaa.tv (160.30.108.246) are in ignored states.
  Not shown: 100 filtered tcp ports (no-response)
  
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 21.85 seconds
  ```

**webmail.samaa.tv**
- Output from nmap_custom_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-27 15:54 +0000
  Nmap scan report for webmail.samaa.tv (40.99.32.114)
  Host is up (0.046s latency).
  Other addresses for webmail.samaa.tv (not scanned): 2603:1046:c0f:40e::2 2603:1046:c0f:40f::2 2603:1046:c0f:4::2 2603:1046:c0f:802::2 40.99.68.34 40.99.70.210 52.98.61.34 40.99.70.178 40.99.60.2 40.99.70.194 52.98.61.50
  Skipping host webmail.samaa.tv (40.99.32.114) due to host timeout
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 95.63 seconds
  ```

### nmap_service_scan (27 finding(s) across 9 target(s))
**adminpanel.samaa.tv**
- adminpanel.samaa.tv:80/tcp http    Amazon CloudFront httpd
  ```
  80/tcp open  http    Amazon CloudFront httpd
  ```
- http-server-header output (adminpanel.samaa.tv:80)
  ```
  CloudFront
  ```
- http-title output (adminpanel.samaa.tv:80)
  ```
  Did not follow redirect to https://adminpanel.samaa.tv/
  ```

**autodiscover.samaa.tv**
- autodiscover.samaa.tv:80/tcp http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
  ```
  80/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
  ```
- http-title output (autodiscover.samaa.tv:80)
  ```
  Did not follow redirect to https://autodiscover.samaa.tv/
  ```
- http-server-header output (autodiscover.samaa.tv:80)
  ```
  Microsoft-HTTPAPI/2.0
  ```

**images.samaa.tv**
- images.samaa.tv:80/tcp http    Amazon CloudFront httpd
  ```
  80/tcp open  http    Amazon CloudFront httpd
  ```
- http-server-header output (images.samaa.tv:80)
  ```
  CloudFront
  ```
- http-title output (images.samaa.tv:80)
  ```
  Did not follow redirect to https://images.samaa.tv/
  ```

**mail.samaa.tv**
- Output from nmap_service_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-27 15:53 +0000
  Nmap scan report for mail.samaa.tv (40.99.26.178)
  Host is up (0.056s latency).
  Other addresses for mail.samaa.tv (not scanned): 40.99.27.2 40.99.27.18 40.99.26.210 2603:1046:c0c:c0e::2 2603:1046:c0c:c00::2 2603:1046:c0c:815::2 2603:1046:c0c:c0d::2 2603:1046:c0c:c0c::2 2603:1046:c0c:814::2 2603:1046:c0c:c11::2 2603:1046:c0c:c10::2
  Skipping host mail.samaa.tv (40.99.26.178) due to host timeout
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 93.82 seconds
  ```

**samaa.tv**
- samaa.tv:80/tcp http     Amazon CloudFront httpd
  ```
  80/tcp  open  http     Amazon CloudFront httpd
  ```
- http-server-header output (samaa.tv:80)
  ```
  CloudFront
  ```
- http-title output (samaa.tv:80)
  ```
  Did not follow redirect to https://samaa.tv/
  ```
- samaa.tv:443/tcp ssl/http Amazon CloudFront httpd
  ```
  443/tcp open  ssl/http Amazon CloudFront httpd
  ```
- http-title output (samaa.tv:443)
  ```
  ERROR: The request could not be satisfied
  ```
- http-server-header output (samaa.tv:443)
  ```
  CloudFront
  ```
- ssl-cert output (samaa.tv:443)
  ```
  Subject: commonName=samaa.tv
  Subject Alternative Name: DNS:samaa.tv, DNS:*.samaa.tv
  Not valid before: 2026-01-23T00:00:00
  Not valid after:  2027-02-21T23:59:59
  ```

**urdu.samaa.tv**
- urdu.samaa.tv:80/tcp http    Amazon CloudFront httpd
  ```
  80/tcp open  http    Amazon CloudFront httpd
  ```
- http-title output (urdu.samaa.tv:80)
  ```
  Did not follow redirect to https://urdu.samaa.tv/
  ```
- http-server-header output (urdu.samaa.tv:80)
  ```
  CloudFront
  ```

**webmail.samaa.tv**
- Output from nmap_service_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-27 15:52 +0000
  Nmap scan report for webmail.samaa.tv (40.99.27.18)
  Host is up (0.057s latency).
  Other addresses for webmail.samaa.tv (not scanned): 40.99.26.178 40.99.27.2 40.99.26.210 2603:1046:c0c:c0d::2 2603:1046:c0c:815::2 2603:1046:c0c:c0c::2 2603:1046:c0c:c00::2 2603:1046:c0c:c11::2 2603:1046:c0c:c0f::2 2603:1046:c0c:c10::2 2603:1046:c0c:c0e::2
  Skipping host webmail.samaa.tv (40.99.27.18) due to host timeout
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 95.86 seconds
  ```

**www.adminpanel.samaa.tv**
- www.adminpanel.samaa.tv:80/tcp http    Amazon CloudFront httpd
  ```
  80/tcp open  http    Amazon CloudFront httpd
  ```
- http-server-header output (www.adminpanel.samaa.tv:80)
  ```
  CloudFront
  ```
- http-title output (www.adminpanel.samaa.tv:80)
  ```
  ERROR: The request could not be satisfied
  ```

**www.samaa.tv**
- www.samaa.tv:80/tcp http    Amazon CloudFront httpd
  ```
  80/tcp open  http    Amazon CloudFront httpd
  ```
- http-title output (www.samaa.tv:80)
  ```
  Did not follow redirect to https://www.samaa.tv/
  ```
- http-server-header output (www.samaa.tv:80)
  ```
  CloudFront
  ```

### origin_ip_attribution (1 finding(s) across 1 target(s))
**samaa.tv**
- 52.101.73.155
  ```
  signals=['probe']
  ```

### phoneinfoga (6 finding(s) across 1 target(s))
**(engagement-wide)**
- Output from phoneinfoga
  ```
  Running scan for phone number 01 02 03 04 05...
  ```
- Raw local: 2320222021
- Local: 2320222021
- Country: EG
- Raw local: 2620252024
- Local: 2620252024

### shodan_host_info (35 finding(s) across 1 target(s))
**samaa.tv**
- shodan_host_info raw output (failed)
  ```
  ERROR: Shodan HTTP 404: {"error": "No information available for that IP."}
  ```
- 3.160.77.17:80/tcp
  ```
  shodan host 3.160.77.17 ports include 80
  ```
- server-3-160-77-17.dxb53.r.cloudfront.net
  ```
  server-3-160-77-17.dxb53.r.cloudfront.net @ 3.160.77.17
  ```
- 13.224.236.45:80/tcp
  ```
  shodan host 13.224.236.45 ports include 80
  ```
- server-13-224-236-45.dxb53.r.cloudfront.net
  ```
  server-13-224-236-45.dxb53.r.cloudfront.net @ 13.224.236.45
  ```
- 13.224.236.61:80/tcp
  ```
  shodan host 13.224.236.61 ports include 80
  ```
- server-13-224-236-61.dxb53.r.cloudfront.net
  ```
  server-13-224-236-61.dxb53.r.cloudfront.net @ 13.224.236.61
  ```
- OS: Windows
  ```
  shodan os=Windows
  ```
- 40.99.26.178:993/tcp
  ```
  shodan host 40.99.26.178 ports include 993
  ```
- 40.99.26.178:995/tcp
  ```
  shodan host 40.99.26.178 ports include 995
  ```
- 40.99.26.178:587/tcp
  ```
  shodan host 40.99.26.178 ports include 587
  ```
- 40.99.26.178:110/tcp
  ```
  shodan host 40.99.26.178 ports include 110
  ```
- 40.99.26.178:143/tcp
  ```
  shodan host 40.99.26.178 ports include 143
  ```
- 40.99.26.178:80/tcp
  ```
  shodan host 40.99.26.178 ports include 80
  ```
- 40.99.26.178:25/tcp
  ```
  shodan host 40.99.26.178 ports include 25
  ```
- attachment.outlook.office.net
  ```
  attachment.outlook.office.net @ 40.99.26.178
  ```
- substrate.office.com
  ```
  substrate.office.com @ 40.99.26.178
  ```
- attachments.office.net
  ```
  attachments.office.net @ 40.99.26.178
  ```
- hotmail.com
  ```
  hotmail.com @ 40.99.26.178
  ```
- outlook.office.com
  ```
  outlook.office.com @ 40.99.26.178
  ```
- outlook.com
  ```
  outlook.com @ 40.99.26.178
  ```
- office365.com
  ```
  office365.com @ 40.99.26.178
  ```
- attachment.outlook.officeppe.net
  ```
  attachment.outlook.officeppe.net @ 40.99.26.178
  ```
- attachment.outlook.live.net
  ```
  attachment.outlook.live.net @ 40.99.26.178
  ```
- attachments-sdf.office.net
  ```
  attachments-sdf.office.net @ 40.99.26.178
  ```
- mail.services.live.com
  ```
  mail.services.live.com @ 40.99.26.178
  ```
- substrate-sdf.office.com
  ```
  substrate-sdf.office.com @ 40.99.26.178
  ```
- ccs.login.microsoftonline.com
  ```
  ccs.login.microsoftonline.com @ 40.99.26.178
  ```
- 40.99.27.18:993/tcp
  ```
  shodan host 40.99.27.18 ports include 993
  ```
- 40.99.27.18:995/tcp
  ```
  shodan host 40.99.27.18 ports include 995
  ```
- 40.99.27.18:587/tcp
  ```
  shodan host 40.99.27.18 ports include 587
  ```
- 40.99.27.18:143/tcp
  ```
  shodan host 40.99.27.18 ports include 143
  ```
- 40.99.27.18:80/tcp
  ```
  shodan host 40.99.27.18 ports include 80
  ```
- 40.99.27.18:443/tcp
  ```
  shodan host 40.99.27.18 ports include 443
  ```
- 40.99.60.8:80/tcp
  ```
  shodan host 40.99.60.8 ports include 80
  ```

### subfinder_scan (137 finding(s) across 1 target(s))
**samaa.tv**
- cpcontacts.inventory.samaa.tv
- www.inventory.samaa.tv
- mail.practise.samaa.tv
- cpanel.sports.samaa.tv
- urdu.samaa.tv
- cpcontacts.f.samaa.tv
- mail1.samaa.tv
- urdu-sports.samaa.tv
- webdisk.urdu-sports.samaa.tv
- www.mail.samaa.tv
- www.i.samaa.tv
- mail.samaa.tv
- gw.samaa.tv
- webdisk.elections.samaa.tv
- adminpanel.samaa.tv
- beta.samaa.tv
- www.sports.samaa.tv
- cpanel.tasks.samaa.tv
- webdisk.tasks.samaa.tv
- www.samaa.tv
- mail.inventory.samaa.tv
- webmail.tasks.samaa.tv
- www.test.samaa.tv
- webdisk.dev.samaa.tv
- autodiscover.elections.samaa.tv
- google.samaa.tv
- cpcontacts.urdu.samaa.tv
- webdisk.urdu.samaa.tv
- english.samaa.tv
- webmail.inventory.samaa.tv
- jaitex2k13-2.samaa.tv
- www.urdu-sports.samaa.tv
- dev.samaa.tv
- webdisk.sports.samaa.tv
- cpcalendars.tasks.samaa.tv
- f.samaa.tv
- cpcontacts.i.samaa.tv
- cpanel.inventory.samaa.tv
- live.samaa.tv
- webmail.live.samaa.tv
- cpcontacts.tasks.samaa.tv
- jaitex2k16-2.samaa.tv
- cpcalendars.f.samaa.tv
- mail.sports.samaa.tv
- webdisk.test.samaa.tv
- admin.samaa.tv
- cpanel.dev.samaa.tv
- www.urdu.samaa.tv
- cpanel.urdu-sports.samaa.tv
- cpcalendars.sports.samaa.tv
- webdisk.f.samaa.tv
- mail.i.samaa.tv
- cpcalendars.inventory.samaa.tv
- webmail.dev.samaa.tv
- local.admin.samaa.tv
- sports.samaa.tv
- webmail.elections.samaa.tv
- cpcalendars.i.samaa.tv
- jaitex2k13-1.samaa.tv
- videos.samaa.tv
- www2.samaa.tv
- tasks.samaa.tv
- webmail.urdu.samaa.tv
- i.samaa.tv
- webmail.i.samaa.tv
- cpcalendars.live.samaa.tv
- livewire.samaa.tv
- webmail.samaa.tv
- webmail.test.samaa.tv
- elections.samaa.tv
- app.samaa.tv
- mail.dev.samaa.tv
- webdisk.i.samaa.tv
- webdisk.inventory.samaa.tv
- autodiscover.live.samaa.tv
- api.samaa.tv
- cpcontacts.elections.samaa.tv
- autodiscover.inventory.samaa.tv
- mail.live.samaa.tv
- www.live.samaa.tv
- autodiscover.tasks.samaa.tv
- cpcalendars.urdu.samaa.tv
- mail.f.samaa.tv
- cpcontacts.live.samaa.tv
- cpanel.test.samaa.tv
- autodiscover.i.samaa.tv
- cpcalendars.practise.samaa.tv
- www.practise.samaa.tv
- cpcontacts.sports.samaa.tv
- images.samaa.tv
- mail.test.samaa.tv
- cpanel.urdu.samaa.tv
- autodiscover.dev.samaa.tv
- cpanel.elections.samaa.tv
- webdisk.live.samaa.tv
- cpcontacts.practise.samaa.tv
- webmail.practise.samaa.tv
- inventory.samaa.tv
- webdisk.practise.samaa.tv
- autodiscover.sports.samaa.tv
- autodiscover.urdu.samaa.tv
- autodiscover.urdu-sports.samaa.tv
- jaitex2k16-1.samaa.tv
- cpanel.live.samaa.tv
- cpcalendars.urdu-sports.samaa.tv
- www.adminpanel.samaa.tv
- cpcalendars.dev.samaa.tv
- www.tasks.samaa.tv
- autodiscover.test.samaa.tv
- mail.urdu-sports.samaa.tv
- cpcalendars.elections.samaa.tv
- www.f.samaa.tv
- practise.samaa.tv
- cpcontacts.urdu-sports.samaa.tv
- cdn.samaa.tv
- cpanel.f.samaa.tv
- autodiscover.practise.samaa.tv
- cpanel.practise.samaa.tv
- cpcontacts.test.samaa.tv
- jaitex2k10-1.samaa.tv
- autodiscover.samaa.tv
- autodiscover.f.samaa.tv
- mail.urdu.samaa.tv
- www.elections.samaa.tv
- mail.tasks.samaa.tv
- cpcontacts.dev.samaa.tv
- cpanel.i.samaa.tv
- test.samaa.tv
- webmail.urdu-sports.samaa.tv
- www.dev.samaa.tv
- mail.elections.samaa.tv
- webmail.f.samaa.tv
- legacy.samaa.tv
- webmail.sports.samaa.tv
- testing.samaa.tv
- cpcalendars.test.samaa.tv
- mail2.samaa.tv

### tech_stack_analyze (37 finding(s) across 10 target(s))
**adminpanel.samaa.tv**
- Amazon Cloudfront
  ```
  {"name": "Amazon Cloudfront", "version": "", "categories": ["CDN"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Amazon Web Services
  ```
  {"name": "Amazon Web Services", "version": "", "categories": ["PaaS"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Custom JavaScript
  ```
  {"name": "Custom JavaScript", "version": "", "categories": ["JavaScript"], "detected_by": ["bundle"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

**images.samaa.tv**
- Amazon-CloudFront
  ```
  {"name": "Amazon-CloudFront", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- Via-Proxy
  ```
  {"name": "Via-Proxy", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- Amazon S3
  ```
  {"name": "Amazon S3", "version": "", "categories": ["Miscellaneous"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Amazon Cloudfront
  ```
  {"name": "Amazon Cloudfront", "version": "", "categories": ["CDN"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Amazon Web Services
  ```
  {"name": "Amazon Web Services", "version": "", "categories": ["PaaS"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

**legacy.samaa.tv**
- Output from tech_stack_analyze
  ```
  {"target": "https://legacy.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://legacy.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='legacy.samaa.tv', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='legacy.samaa.tv', port=443) at 0x7c81e46dcd70>, 'Connection to legacy.samaa.tv timed out. (connect timeout=10)'))"}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://legacy.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='legacy.samaa.tv', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='legacy.samaa.tv', port=443) at 0x7c81e46dcd70>, 'Connection to legacy.samaa.tv timed out. (connect timeout=10)'))"}, "headers": {"error": "<urlopen error timed out>"}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://legacy.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='legacy.samaa.tv', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='legacy.samaa.tv', port=443) at 0x7c81e46dcd70>, 'Connection to legacy.samaa.tv timed out. (connect timeout=10)'))"}, "headers": {"error": "<urlopen error timed out>"
  ```

**mail.samaa.tv**
- Microsoft-HTTPAPI 2.0
  ```
  {"name": "Microsoft-HTTPAPI", "version": "2.0", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- RedirectLocation
  ```
  {"name": "RedirectLocation", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- Cookies
  ```
  {"name": "Cookies", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- X-UA-Compatible
  ```
  {"name": "X-UA-Compatible", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- Microsoft HTTPAPI 2.0
  ```
  {"name": "Microsoft HTTPAPI", "version": "2.0", "categories": ["Web servers"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

**samaa.tv**
- Amazon Cloudfront
  ```
  {"name": "Amazon Cloudfront", "version": "", "categories": ["CDN"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Amazon Web Services
  ```
  {"name": "Amazon Web Services", "version": "", "categories": ["PaaS"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- React
  ```
  {"name": "React", "version": "", "categories": ["JavaScript Framework"], "detected_by": ["bundle"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

**sftp.samaa.tv**
- Output from tech_stack_analyze
  ```
  {"target": "https://sftp.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://sftp.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='sftp.samaa.tv', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='sftp.samaa.tv', port=443) at 0x719e60670d70>, 'Connection to sftp.samaa.tv timed out. (connect timeout=10)'))"}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://sftp.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='sftp.samaa.tv', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='sftp.samaa.tv', port=443) at 0x719e60670d70>, 'Connection to sftp.samaa.tv timed out. (connect timeout=10)'))"}, "headers": {"error": "<urlopen error timed out>"}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://sftp.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='sftp.samaa.tv', port=443): Max retries exceeded with url: / (Caused by ConnectTimeoutError(<HTTPSConnection(host='sftp.samaa.tv', port=443) at 0x719e60670d70>, 'Connection to sftp.samaa.tv timed out. (connect timeout=10)'))"}, "headers": {"error": "<urlopen error timed out>"}, "bundle": {"technologie
  ```

**urdu.samaa.tv**
- Amazon Cloudfront
  ```
  {"name": "Amazon Cloudfront", "version": "", "categories": ["CDN"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Amazon Web Services
  ```
  {"name": "Amazon Web Services", "version": "", "categories": ["PaaS"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- jQuery
  ```
  {"name": "jQuery", "version": "", "categories": ["JavaScript Library"], "detected_by": ["bundle"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

**webmail.samaa.tv**
- Microsoft-HTTPAPI 2.0
  ```
  {"name": "Microsoft-HTTPAPI", "version": "2.0", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- RedirectLocation
  ```
  {"name": "RedirectLocation", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- Cookies
  ```
  {"name": "Cookies", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- X-UA-Compatible
  ```
  {"name": "X-UA-Compatible", "version": "", "categories": [], "detected_by": ["whatweb"], "confidence": null}
  ```
- Microsoft HTTPAPI 2.0
  ```
  {"name": "Microsoft HTTPAPI", "version": "2.0", "categories": ["Web servers"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

**www.adminpanel.samaa.tv**
- Output from tech_stack_analyze
  ```
  {"target": "https://www.adminpanel.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://www.adminpanel.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='www.adminpanel.samaa.tv', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] ssl/tls alert handshake failure (_ssl.c:1033)')))"}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://www.adminpanel.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='www.adminpanel.samaa.tv', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] ssl/tls alert handshake failure (_ssl.c:1033)')))"}, "headers": {"error": "<urlopen error [SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] ssl/tls alert handshake failure (_ssl.c:1033)>"}}, "unified_stack": [], "total_technologies": 0}
  {"target": "https://www.adminpanel.samaa.tv", "methods": {"whatweb": {"technologies": [], "raw_plugins": []}, "wappalyzer": {"error": "HTTPSConnectionPool(host='www.adminpanel.samaa.tv', port=443): Max retries exceeded with url: / (Caused by SSLError(SSLError(1, '[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] ssl/tls alert handshake failure (_ssl.c:1033)')))"}, "headers": {"error": "<urlopen error [SSL: SSLV3_ALERT_HANDSHAK
  ```

**www.samaa.tv**
- Amazon Cloudfront
  ```
  {"name": "Amazon Cloudfront", "version": "", "categories": ["CDN"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- Amazon Web Services
  ```
  {"name": "Amazon Web Services", "version": "", "categories": ["PaaS"], "detected_by": ["wappalyzer"], "confidence": null}
  ```
- React
  ```
  {"name": "React", "version": "", "categories": ["JavaScript Framework"], "detected_by": ["bundle"], "confidence": null}
  ```
- TLS TLSv1.3
  ```
  {"name": "TLS TLSv1.3", "version": "", "categories": ["TLS"], "detected_by": ["tls"], "confidence": null}
  ```

### theharvester (3 finding(s) across 1 target(s))
**samaa.tv**
- cmartorella@edge-security.com
- *.samaa.tv
- 2fimages.samaa.tv

### tlsx_inspect (2 finding(s) across 1 target(s))
**samaa.tv**
- TLS samaa.tv:443
  ```
  {"timestamp":"2026-08-27T15:12:32.686706274Z","host":"samaa.tv","ip":"3.160.77.103","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-01-23T00:00:00Z","not_after":"2027-02-21T23:59:59Z","subject_dn":"CN=samaa.tv","subject_cn":"samaa.tv","subject_an":["samaa.tv","*.samaa.tv"],"serial":"0D:54:C6:1B:48:5E:B6:A6:64:49:8B:0D:0C:E0:1D:CF","issuer_dn":"CN=Amazon RSA 2048 M01, O=Amazon, C=US","issuer_cn":"Amazon RSA 2048 M01","issuer_org":["Amazon"],"fingerprint_hash":{"md5":"fa5372c56da70b327a815a174fc0f71d","sha1":"94226a8f4ba7e1c4d4f5055d85a972ac6019c614","sha256":"0e5c21353545b09e9ec0f25c953ab7208f5ba66a68d6e2475a997224d16116ce"},"wildcard_certificate":true,"tls_connection":"ctls","sni":"samaa.tv"}
  ```
- samaa.tv

### wafw00f_scan (11 finding(s) across 11 target(s))
**adminpanel.samaa.tv**
- Cloudfront (Amazon) WAF
  ```
  [+] The site https://adminpanel.samaa.tv is behind Cloudfront (Amazon) WAF.
  ```

**autodiscover.samaa.tv**
- wafw00f_scan raw output (ok)
  ```
  [1;97m______
                    [1;97m/      \
                   [1;97m(  Woof! )
                    [1;97m\  ____/                      [1;91m)
                    [1;97m,,                           [1;91m) ([1;93m_
               [1;93m.-. [1;97m-    [1;92m_______                 [1;91m( [1;93m|__|
              [1;93m()``; [1;92m|==|_______)                [1;91m.)[1;93m|__|
              [1;93m/ ('        [1;92m/|\                  [1;91m(  [1;93m|__|
          [1;93m(  /  )       [1;92m / | \                  [1;91m. [1;93m|__|
           [1;93m\(_)_))      [1;92m/  |  \                   [1;93m|__|[0m
  
                      [1;96m~ WAFW00F : [1;94mv2.4.2 ~[1;97m
      The Web Application Firewall Fingerprinting Toolkit
      [0m
  [*] Checking https://autodiscover.samaa.tv
  ```

**images.samaa.tv**
- Cloudfront (Amazon) WAF
  ```
  [+] The site https://images.samaa.tv is behind Cloudfront (Amazon) WAF.
  ```

**legacy.samaa.tv**
- wafw00f_scan raw output (ok)
  ```
  [1;97m______
                    [1;97m/      \
                   [1;97m(  Woof! )
                    [1;97m\  ____/                      [1;91m)
                    [1;97m,,                           [1;91m) ([1;93m_
               [1;93m.-. [1;97m-    [1;92m_______                 [1;91m( [1;93m|__|
              [1;93m()``; [1;92m|==|_______)                [1;91m.)[1;93m|__|
              [1;93m/ ('        [1;92m/|\                  [1;91m(  [1;93m|__|
          [1;93m(  /  )       [1;92m / | \                  [1;91m. [1;93m|__|
           [1;93m\(_)_))      [1;92m/  |  \                   [1;93m|__|[0m
  
                      [1;96m~ WAFW00F : [1;94mv2.4.2 ~[1;97m
      The Web Application Firewall Fingerprinting Toolkit
      [0m
  [*] Checking https://legacy.samaa.tv
  ```

**mail.samaa.tv**
- wafw00f_scan raw output (ok)
  ```
  ?              ,.   (   .      )        .      "
           __        ??          ("     )  )'     ,'        )  . (`     '`
      (___()'`;   ???          .; )  ' (( (" )    ;(,     ((  (  ;)  "  )")
      /,___ /`                 _"., ,._'_.,)_(..,( . )_  _' )_') (. _..( ' )
      \\   \\                 |____|____|____|____|____|____|____|____|____|
  
                                  ~ WAFW00F : v2.4.2 ~
                      ~ Sniffing Web Application Firewalls since 2009 ~
  
  [*] Checking https://mail.samaa.tv
  [+] Generic Detection results:
  [-] No WAF detected by the generic detection
  [~] Number of requests: 7
  ```

**samaa.tv**
- Cloudfront (Amazon) WAF
  ```
  [+] The site https://samaa.tv is behind Cloudfront (Amazon) WAF.
  ```

**sftp.samaa.tv**
- wafw00f_scan raw output (ok)
  ```
  [1;97m______
                    [1;97m/      \
                   [1;97m(  Woof! )
                    [1;97m\  ____/                      [1;91m)
                    [1;97m,,                           [1;91m) ([1;93m_
               [1;93m.-. [1;97m-    [1;92m_______                 [1;91m( [1;93m|__|
              [1;93m()``; [1;92m|==|_______)                [1;91m.)[1;93m|__|
              [1;93m/ ('        [1;92m/|\                  [1;91m(  [1;93m|__|
          [1;93m(  /  )       [1;92m / | \                  [1;91m. [1;93m|__|
           [1;93m\(_)_))      [1;92m/  |  \                   [1;93m|__|[0m
  
                      [1;96m~ WAFW00F : [1;94mv2.4.2 ~[1;97m
      The Web Application Firewall Fingerprinting Toolkit
      [0m
  [*] Checking https://sftp.samaa.tv
  ```

**urdu.samaa.tv**
- Cloudfront (Amazon) WAF
  ```
  [+] The site https://urdu.samaa.tv is behind Cloudfront (Amazon) WAF.
  ```

**webmail.samaa.tv**
- wafw00f_scan raw output (ok)
  ```
  ?              ,.   (   .      )        .      "
           __        ??          ("     )  )'     ,'        )  . (`     '`
      (___()'`;   ???          .; )  ' (( (" )    ;(,     ((  (  ;)  "  )")
      /,___ /`                 _"., ,._'_.,)_(..,( . )_  _' )_') (. _..( ' )
      \\   \\                 |____|____|____|____|____|____|____|____|____|
  
                                  ~ WAFW00F : v2.4.2 ~
                      ~ Sniffing Web Application Firewalls since 2009 ~
  
  [*] Checking https://webmail.samaa.tv
  [+] Generic Detection results:
  [-] No WAF detected by the generic detection
  [~] Number of requests: 7
  ```

**www.adminpanel.samaa.tv**
- wafw00f_scan raw output (ok)
  ```
  [1;97m______
                 [1;97m/      \
                [1;97m(  W00f! )
                 [1;97m\  ____/
                 [1;97m,,    [1;92m__            [1;93m404 Hack Not Found
             [1;96m|`-.__   [1;92m/ /                     [1;91m __     __
             [1;96m/"  _/  [1;92m/_/                       [1;91m\ \   / /
            [1;94m*===*    [1;92m/                          [1;91m\ \_/ /  [1;93m405 Not Allowed
           [1;96m/     )__//                           [1;91m\   /
      [1;96m/|  /     /---`                        [1;93m403 Forbidden
      [1;96m\\/`   \ |                                 [1;91m/ _ \
      [1;96m`\    /_\\_              [1;93m502 Bad Gateway  [1;91m/ / \ \  [1;93m500 Internal Error
        [1;96m`_____``-`                             [1;91m/_/   \_\\
  
                          [1;96m~ WAFW00F : [1;94mv2.4.2 ~[1;97m
          The Web Application Firewall Fingerprinting Toolkit
      [0m
  [*] Checking https://www.adminpanel.samaa.tv
  ```

**www.samaa.tv**
- Cloudfront (Amazon) WAF
  ```
  [+] The site https://www.samaa.tv is behind Cloudfront (Amazon) WAF.
  ```

### web_contact_harvest (25 finding(s) across 1 target(s))
**samaa.tv**
- 01 02 03 04 05
- 2023 2022 2021
- 2026 2025 2024
- SAMAA TV
- https://www.facebook.com/samaatvnews/
- samaatvnews
- https://twitter.com/SAMAATV
- SAMAATV
- https://www.instagram.com/samaatv/
- https://www.tiktok.com/@samaadigital
- samaadigital
- https://www.youtube.com/samaatvnews
- https://www.linkedin.com/company/samaa-tv/mycompany/
- samaa-tv
- https://www.facebook.com/samaatvnews
- https://twitter.com/intent/tweet
- tweet
- https://www.linkedin.com/sharing/share-offsite/
- sharing
- https://x.com/ForeignOfficePk/status/2092980954730250560
- ForeignOfficePk
- https://pinterest.com/pin/create/button/
- pin
- https://x.com/AusHCPak/status/2092888810329952677
- AusHCPak

### whois_lookup (6 finding(s) across 1 target(s))
**samaa.tv**
- WHOIS: samaa.tv
  ```
  registrar=Network Solutions, LLC; created=2007-07-31T08:38:59Z; expiry=2027-07-31T08:38:59Z; dnssec=unsigned; ns=4
  ```
- DNSSEC not configured on samaa.tv
  ```
  WHOIS DNSSEC: unsigned
  ```
- samaa.tv NS -> ns-729.awsdns-27.net
  ```
  nameserver ns-729.awsdns-27.net
  ```
- samaa.tv NS -> ns-1565.awsdns-03.co.uk
  ```
  nameserver ns-1565.awsdns-03.co.uk
  ```
- samaa.tv NS -> ns-1110.awsdns-10.org
  ```
  nameserver ns-1110.awsdns-10.org
  ```
- samaa.tv NS -> ns-281.awsdns-35.com
  ```
  nameserver ns-281.awsdns-35.com
  ```
