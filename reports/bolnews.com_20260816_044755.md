# Recon Report — bolnews.com
_Generated 2026-08-16 04:47 UTC_

## Summary
- Sister/associated domains: 108
- Subdomains discovered: 44
- Unique IPs: 4
- Open ports: 14
- Services identified: 0
- Orphan hosts (not clearly under seed/sisters): 10
- Total individual findings/tool outputs recorded: 940

## Tools Executed
| Tool | Findings/Outputs |
|---|---|
| waybackurls_discovery | 619 |
| domain_hunter | 108 |
| gau_discovery | 81 |
| subfinder_scan | 44 |
| amass_scan | 25 |
| crt_sh_query | 14 |
| tlsx_inspect | 8 |
| dnsx_resolve | 7 |
| naabu_port_scan | 6 |
| whois_lookup | 5 |
| cdn_origin_probe | 4 |
| httpx_probe | 4 |
| nmap_custom_scan | 4 |
| nmap_service_scan | 3 |
| email_security_probe | 2 |
| tech_stack_analyze | 2 |
| wafw00f_scan | 2 |
| dnsx_reverse | 1 |
| shodan_host_info | 1 |

## Asset Overview
_Structural skeleton only — ports/services/tech shown here are what made it into structured fields. See **Detailed Findings by Tool** below for everything each tool actually returned, including unparsed output._

### Seed Domain
#### bolnews.com _seed_
##### bolnews.com
- **Tags:** dns_record, mx, ns, tls, tls_san, whois

##### ads.bolnews.com

##### api.bolnews.com
- **Tags:** url_history

##### apiv2.bolnews.com
- **Tags:** url_history

##### autodiscover.bolnews.com

##### bolnewswp-api.bolnews.com
- **Tags:** url_history

##### bolnewswp-app.bolnews.com
- **Tags:** url_history

##### cdn.bolnews.com
- **Tags:** cname, dns_record

##### cdnurdu.bolnews.com
- **Tags:** cname, dns_record

##### cpanel.staging.bolnews.com

##### cpcalendars.staging.bolnews.com

##### cpcontacts.staging.bolnews.com

##### cruiseway.bolnews.com

##### datav1.bolnews.com
- **Ports:** datav1.bolnews.com:443, datav1.bolnews.com:8443, datav1.bolnews.com:80, datav1.bolnews.com:8080, datav1.bolnews.com:443/tcp open, datav1.bolnews.com:8443/tcp open, datav1.bolnews.com:80/tcp open, datav1.bolnews.com:8080/tcp open
- **Technologies:** SUCCESS
- **Tags:** naabu, tls, url_history

##### forum.bolnews.com

##### img2.bolnews.com

##### live.bolnews.com
- **Tags:** url_history

##### login.bolnews.com

##### m.bolnews.com
- **Tags:** url_history

##### mail.bolnews.com
- **Tags:** tls

##### mail.staging.bolnews.com

##### media.bolnews.com

##### newspaperadmin.bolnews.com
- **Tags:** url_history

##### ns1.bolnews.com

##### ns2.bolnews.com

##### ns3.bolnews.com

##### ostracodermi.bolnews.com

##### pakistan.bolnews.com

##### pop.bolnews.com

##### server.bolnews.com

##### server2.bolnews.com
- **Tags:** url_history

##### server3.bolnews.com

##### server4.bolnews.com
- **Tags:** tls, url_history

##### staging.bolnews.com
- **Tags:** tls, url_history

##### status.bolnews.com

##### textwp.bolnews.com

##### us.bolnews.com

##### v2.bolnews.com

##### vdo.bolnews.com

##### vdo2.bolnews.com

##### webdisk.staging.bolnews.com

##### webmail.staging.bolnews.com

##### www.bolnews.com
- **Ports:** www.bolnews.com:8443, www.bolnews.com:80, www.bolnews.com:8443/tcp open, www.bolnews.com:80/tcp open, www.bolnews.com:80/tcp http     Cloudflare http proxy, www.bolnews.com:8443/tcp ssl/http Cloudflare http proxy
- **Technologies:** SUCCESS
- **Tags:** naabu, tls

##### www.server.bolnews.com

##### www.staging.bolnews.com

### Sister / Associated Domains
#### avads.live _sister_
##### avads.live
- **Tags:** domain_hunter, sister_domain

#### google.com _sister_
##### google.com
- **Tags:** domain_hunter, scrape_noise, sister_domain, unverified_affiliate

#### 1bottiglia.com _sister_
##### 1bottiglia.com
- **Tags:** domain_hunter, sister_domain

#### 1fodiscount.com _sister_
##### 1fodiscount.com
- **Tags:** domain_hunter, sister_domain

#### 3cad.it _sister_
##### 3cad.it
- **Tags:** domain_hunter, sister_domain

#### 7money.co _sister_
##### 7money.co
- **Tags:** domain_hunter, sister_domain

#### accelerateplus.net _sister_
##### accelerateplus.net
- **Tags:** domain_hunter, sister_domain

#### advision-ecommerce.com _sister_
##### advision-ecommerce.com
- **Tags:** domain_hunter, sister_domain

#### aequitasresource.org _sister_
##### aequitasresource.org
- **Tags:** domain_hunter, sister_domain

#### agripick.com _sister_
##### agripick.com
- **Tags:** domain_hunter, sister_domain

#### aikitech.ca _sister_
##### aikitech.ca
- **Tags:** domain_hunter, sister_domain

#### airplantshopzakelijk.nl _sister_
##### airplantshopzakelijk.nl
- **Tags:** domain_hunter, sister_domain

#### ajvinc.com _sister_
##### ajvinc.com
- **Tags:** domain_hunter, sister_domain

#### alokozayshop.com _sister_
##### alokozayshop.com
- **Tags:** domain_hunter, sister_domain

#### americansupplyandairproducts.com _sister_
##### americansupplyandairproducts.com
- **Tags:** domain_hunter, sister_domain

#### amurfinancial.group _sister_
##### amurfinancial.group
- **Tags:** domain_hunter, sister_domain

#### android-user.de _sister_
##### android-user.de
- **Tags:** domain_hunter, sister_domain

#### anthonydmays.com _sister_
##### anthonydmays.com
- **Tags:** domain_hunter, sister_domain

#### ap-sdk.com _sister_
##### ap-sdk.com
- **Tags:** domain_hunter, sister_domain

#### appinstallus.com _sister_
##### appinstallus.com
- **Tags:** domain_hunter, sister_domain

#### argosinsight.ai _sister_
##### argosinsight.ai
- **Tags:** domain_hunter, sister_domain

#### armytech.com.ar _sister_
##### armytech.com.ar
- **Tags:** domain_hunter, sister_domain

#### aromawest.com _sister_
##### aromawest.com
- **Tags:** domain_hunter, sister_domain

#### athena-videncia.com _sister_
##### athena-videncia.com
- **Tags:** domain_hunter, sister_domain

#### atudotvatikamaasikim.co.il _sister_
##### atudotvatikamaasikim.co.il
- **Tags:** domain_hunter, sister_domain

#### azizanosman.com _sister_
##### azizanosman.com
- **Tags:** domain_hunter, sister_domain

#### baltz.de _sister_
##### baltz.de
- **Tags:** domain_hunter, sister_domain

#### bayfields.com.au _sister_
##### bayfields.com.au
- **Tags:** domain_hunter, sister_domain

#### betbus.mx _sister_
##### betbus.mx
- **Tags:** domain_hunter, sister_domain

#### bettersworthlaw.com _sister_
##### bettersworthlaw.com
- **Tags:** domain_hunter, sister_domain

#### bigbag.energy _sister_
##### bigbag.energy
- **Tags:** domain_hunter, sister_domain

#### bjjheroes.com _sister_
##### bjjheroes.com
- **Tags:** domain_hunter, sister_domain

#### blablachat.it _sister_
##### blablachat.it
- **Tags:** domain_hunter, sister_domain

#### bloxd.io _sister_
##### bloxd.io
- **Tags:** domain_hunter, sister_domain

#### bookmaker-ratings-az.com _sister_
##### bookmaker-ratings-az.com
- **Tags:** domain_hunter, sister_domain

#### bostonind.com _sister_
##### bostonind.com
- **Tags:** domain_hunter, sister_domain

#### brooksuspension.com _sister_
##### brooksuspension.com
- **Tags:** domain_hunter, sister_domain

#### cacttus.cl _sister_
##### cacttus.cl
- **Tags:** domain_hunter, sister_domain

#### cadillacpartspros.com _sister_
##### cadillacpartspros.com
- **Tags:** domain_hunter, sister_domain

#### car-canada.ca _sister_
##### car-canada.ca
- **Tags:** domain_hunter, sister_domain

#### cartobike.com _sister_
##### cartobike.com
- **Tags:** domain_hunter, sister_domain

#### cbmex8wvs.com _sister_
##### cbmex8wvs.com
- **Tags:** domain_hunter, sister_domain

#### chasedex.com _sister_
##### chasedex.com
- **Tags:** domain_hunter, sister_domain

#### chilevalora.gob.cl _sister_
##### chilevalora.gob.cl
- **Tags:** domain_hunter, sister_domain

#### cipacks.com _sister_
##### cipacks.com
- **Tags:** domain_hunter, sister_domain

#### clnk.in _sister_
##### clnk.in
- **Tags:** domain_hunter, sister_domain

#### collectrea.com _sister_
##### collectrea.com
- **Tags:** domain_hunter, sister_domain

#### digital-eat.com _sister_
##### digital-eat.com
- **Tags:** domain_hunter, sister_domain

#### dongzong.my _sister_
##### dongzong.my
- **Tags:** domain_hunter, sister_domain

#### draftsharks.com _sister_
##### draftsharks.com
- **Tags:** domain_hunter, sister_domain

#### eosmith.org _sister_
##### eosmith.org
- **Tags:** domain_hunter, sister_domain

#### fuelster.co _sister_
##### fuelster.co
- **Tags:** domain_hunter, sister_domain

#### g5-technologies.com _sister_
##### g5-technologies.com
- **Tags:** domain_hunter, sister_domain

#### getflitch.com _sister_
##### getflitch.com
- **Tags:** domain_hunter, sister_domain

#### gheeraert.be _sister_
##### gheeraert.be
- **Tags:** domain_hunter, sister_domain

#### glaze.app _sister_
##### glaze.app
- **Tags:** domain_hunter, sister_domain

#### gratapayments.com _sister_
##### gratapayments.com
- **Tags:** domain_hunter, sister_domain

#### greenpro.co.uk _sister_
##### greenpro.co.uk
- **Tags:** domain_hunter, sister_domain

#### hfhr.pl _sister_
##### hfhr.pl
- **Tags:** domain_hunter, sister_domain

#### i7dc.com _sister_
##### i7dc.com
- **Tags:** domain_hunter, sister_domain

#### internpro.ai _sister_
##### internpro.ai
- **Tags:** domain_hunter, sister_domain

#### jakmedytowac.pl _sister_
##### jakmedytowac.pl
- **Tags:** domain_hunter, sister_domain

#### jakodirect.nl _sister_
##### jakodirect.nl
- **Tags:** domain_hunter, sister_domain

#### jptravel-reserve.com _sister_
##### jptravel-reserve.com
- **Tags:** domain_hunter, sister_domain

#### kingandqueenlimo.com _sister_
##### kingandqueenlimo.com
- **Tags:** domain_hunter, sister_domain

#### kupat.co.il _sister_
##### kupat.co.il
- **Tags:** domain_hunter, sister_domain

#### lallemandspecialtycultures.com _sister_
##### lallemandspecialtycultures.com
- **Tags:** domain_hunter, sister_domain

#### manavate.com _sister_
##### manavate.com
- **Tags:** domain_hunter, sister_domain

#### millie-staging.com _sister_
##### millie-staging.com
- **Tags:** domain_hunter, sister_domain

#### mirrorsphere.com _sister_
##### mirrorsphere.com
- **Tags:** domain_hunter, sister_domain

#### mixclx.net _sister_
##### mixclx.net
- **Tags:** domain_hunter, sister_domain

#### nachtzug.net _sister_
##### nachtzug.net
- **Tags:** domain_hunter, sister_domain

#### ohmyfi.com _sister_
##### ohmyfi.com
- **Tags:** domain_hunter, sister_domain

#### pikkufabric.dev _sister_
##### pikkufabric.dev
- **Tags:** domain_hunter, sister_domain

#### polyguard.ai _sister_
##### polyguard.ai
- **Tags:** domain_hunter, sister_domain

#### privatewealth.academy _sister_
##### privatewealth.academy
- **Tags:** domain_hunter, sister_domain

#### re-cap.com _sister_
##### re-cap.com
- **Tags:** domain_hunter, sister_domain

#### roadtestedparts.com _sister_
##### roadtestedparts.com
- **Tags:** domain_hunter, sister_domain

#### roofmarketplace.com _sister_
##### roofmarketplace.com
- **Tags:** domain_hunter, sister_domain

#### seminarhof-drawehn.de _sister_
##### seminarhof-drawehn.de
- **Tags:** domain_hunter, sister_domain

#### seorav.com _sister_
##### seorav.com
- **Tags:** domain_hunter, sister_domain

#### sistemafb.com _sister_
##### sistemafb.com
- **Tags:** domain_hunter, sister_domain

#### snp1344.com _sister_
##### snp1344.com
- **Tags:** domain_hunter, sister_domain

#### sonjj.com _sister_
##### sonjj.com
- **Tags:** domain_hunter, sister_domain

#### spinzel.com _sister_
##### spinzel.com
- **Tags:** domain_hunter, sister_domain

#### tagginghippo.app _sister_
##### tagginghippo.app
- **Tags:** domain_hunter, sister_domain

#### tails.id _sister_
##### tails.id
- **Tags:** domain_hunter, sister_domain

#### tarta.ai _sister_
##### tarta.ai
- **Tags:** domain_hunter, sister_domain

#### tealyra.com _sister_
##### tealyra.com
- **Tags:** domain_hunter, sister_domain

#### tepavi.de _sister_
##### tepavi.de
- **Tags:** domain_hunter, sister_domain

#### theimmersivecompany.com _sister_
##### theimmersivecompany.com
- **Tags:** domain_hunter, sister_domain

#### tiendasantaclara.com _sister_
##### tiendasantaclara.com
- **Tags:** domain_hunter, sister_domain

#### toodledo.com _sister_
##### toodledo.com
- **Tags:** domain_hunter, sister_domain

#### tora-ks.com _sister_
##### tora-ks.com
- **Tags:** domain_hunter, sister_domain

#### tresor.one _sister_
##### tresor.one
- **Tags:** domain_hunter, sister_domain

#### tripix.app _sister_
##### tripix.app
- **Tags:** domain_hunter, sister_domain

#### uptv.co.il _sister_
##### uptv.co.il
- **Tags:** domain_hunter, sister_domain

#### vapeandeliquid.co.uk _sister_
##### vapeandeliquid.co.uk
- **Tags:** domain_hunter, sister_domain

#### veracruz.edu.br _sister_
##### veracruz.edu.br
- **Tags:** domain_hunter, sister_domain

#### viact.ai _sister_
##### viact.ai
- **Tags:** domain_hunter, sister_domain

#### witec.com.br _sister_
##### witec.com.br
- **Tags:** domain_hunter, sister_domain

#### xdflo.com _sister_
##### xdflo.com
- **Tags:** domain_hunter, sister_domain

#### xremit.io _sister_
##### xremit.io
- **Tags:** domain_hunter, sister_domain

#### belugahospitality.co.za _sister_
##### belugahospitality.co.za
- **Tags:** domain_hunter, sister_domain

#### bugherd-staging.com _sister_
##### bugherd-staging.com
- **Tags:** domain_hunter, sister_domain

#### pokshin.com _sister_
##### pokshin.com
- **Tags:** domain_hunter, sister_domain

#### thehandy.com _sister_
##### thehandy.com
- **Tags:** domain_hunter, sister_domain

#### vs-test.info _sister_
##### vs-test.info
- **Tags:** domain_hunter, sister_domain

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

#### 221.132.113.226
- **IPs:** 221.132.113.226
- **Tags:** dns_resolve

#### arnold.ns.cloudflare.com

#### bolnetwork.com
- **Tags:** tls_san

#### cecelia.ns.cloudflare.com

#### d2xibwot1uc8oa.cloudfront.net

#### d3nyy49x3l71qg.cloudfront.net

#### mail.bolnetwork.com
- **IPs:** 221.132.113.226
- **Tags:** ptr, reverse_dns

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

### amass_scan (25 finding(s) across 25 target(s))
**ads.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**api.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**apiv2.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**bolnewswp-api.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**bolnewswp-app.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**cdn.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**cdnurdu.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**cruiseway.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**datav1.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**forum.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**live.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**m.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**mail.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**newspaperadmin.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**ns1.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**ns3.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**pakistan.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**pop.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**server2.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**server4.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**staging.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**textwp.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**v2.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**vdo2.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

**www.bolnews.com**
- Output from amass_scan
  ```
  Session Scope
  ```

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

### crt_sh_query (14 finding(s) across 13 target(s))
**apiv2.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**bolnews.com**
- Output from crt_sh_query
  ```
  [{"issuer_ca_id":432952,"issuer_name":"C=US, O=Let's Encrypt, CN=YE1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925475296,"entry_timestamp":"2026-07-14T12:08:19.1","not_before":"2026-07-14T11:09:47","not_after":"2026-10-12T11:09:46","serial_number":"05e3a32fa27096fe00ecf39b8077799f4b5e","result_count":3},{"issuer_ca_id":432952,"issuer_name":"C=US, O=Let's Encrypt, CN=YE1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925458968,"entry_timestamp":"2026-07-14T12:08:16.621","not_before":"2026-07-14T11:09:47","not_after":"2026-10-12T11:09:46","serial_number":"05e3a32fa27096fe00ecf39b8077799f4b5e","result_count":3},{"issuer_ca_id":432476,"issuer_name":"C=US, O=Let's Encrypt, CN=YR1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925475254,"entry_timestamp":"2026-07-14T12:08:14.881","not_before":"2026-07-14T11:09:43","not_after":"2026-10-12T11:09:42","serial_number":"053f8d77bf308f7b7620fad8e5a3f7deeff8","result_count":3},{"issuer_ca_id":432476,"issuer_name":"C=US, O=Let's Encrypt, CN=YR1","common_name":"bolnews.com","name_value":"*.bolnews.com\nbolnews.com","id":27925457646,"entry_timestamp":"2026-07-14T12:08:12.566","not_before":"2026-07-14T11:09:43","not_after":"2026-10-12T11:09:42","serial_number":"053f8d77bf308f7b7620fad8e5a3f7deeff8","result_count":3},{"issuer_ca_id":286236,"issuer_name":"C=US, O=Google Trust Services, CN=WE1","common_name":"bolnews.com","name_value":"*.bolnews.com\
  ```

**bolnewswp-api.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**bolnewswp-app.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**cdn.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**cruiseway.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**forum.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>502 Bad Gateway</title></head>
  <body>
  <center><h1>502 Bad Gateway</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  []
  ```

**mail.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**ns1.bolnews.com**
- Output from crt_sh_query
  ```
  <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
  <html><head>
  <title>404 Not Found</title>
  </head><body>
  <h1>Not Found</h1>
  <p>The requested URL was not found on this server.</p>
  <hr>
  <address>Apache Server at crt.sh Port 443</address>
  </body></html>
  ```
- SPA/HTML shell body — do not treat path as open API without JSON proof
  ```
  <!DOCTYPE HTML
  ```

**pop.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**server2.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**server4.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

**v2.bolnews.com**
- Output from crt_sh_query
  ```
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  <html>
  <head><title>429 Too Many Requests</title></head>
  <body>
  <center><h1>429 Too Many Requests</h1></center>
  <hr><center>nginx</center>
  </body>
  </html>
  ```

### dnsx_resolve (7 finding(s) across 4 target(s))
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

**cdn.bolnews.com**
- cdn.bolnews.com CNAME -> d3nyy49x3l71qg.cloudfront.net
  ```
  cdn.bolnews.com CNAME d3nyy49x3l71qg.cloudfront.net
  ```

**cdnurdu.bolnews.com**
- cdnurdu.bolnews.com CNAME -> d2xibwot1uc8oa.cloudfront.net
  ```
  cdnurdu.bolnews.com CNAME d2xibwot1uc8oa.cloudfront.net
  ```

**mail.bolnews.com**
- 221.132.113.226
  ```
  mail.bolnews.com -> 221.132.113.226
  ```

### dnsx_reverse (1 finding(s) across 1 target(s))
**221.132.113.226**
- mail.bolnetwork.com
  ```
  221.132.113.226 PTR mail.bolnetwork.com
  ```

### domain_hunter (108 finding(s) across 2 target(s))
**bolnews.com**
- avads.live
  ```
  method=site_scrape; live_probe confidence=low live=yes
  ```
- google.com
  ```
  method=site_scrape; live_probe confidence=low live=yes
  ```

**cruiseway.bolnews.com**
- 1bottiglia.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- 1fodiscount.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- 3cad.it
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- 7money.co
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- accelerateplus.net
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- advision-ecommerce.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- aequitasresource.org
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- agripick.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- aikitech.ca
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- airplantshopzakelijk.nl
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- ajvinc.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- alokozayshop.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- americansupplyandairproducts.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- amurfinancial.group
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- android-user.de
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- anthonydmays.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- ap-sdk.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- appinstallus.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- argosinsight.ai
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- armytech.com.ar
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- aromawest.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- athena-videncia.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- atudotvatikamaasikim.co.il
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- azizanosman.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- baltz.de
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bayfields.com.au
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- betbus.mx
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bettersworthlaw.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bigbag.energy
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bjjheroes.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- blablachat.it
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bloxd.io
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bookmaker-ratings-az.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- bostonind.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- brooksuspension.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- cacttus.cl
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- cadillacpartspros.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- car-canada.ca
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- cartobike.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- cbmex8wvs.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- chasedex.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- chilevalora.gob.cl
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- cipacks.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- clnk.in
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- collectrea.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- digital-eat.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- dongzong.my
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- draftsharks.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- eosmith.org
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- fuelster.co
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- g5-technologies.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- getflitch.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- gheeraert.be
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- glaze.app
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- gratapayments.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- greenpro.co.uk
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- hfhr.pl
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- i7dc.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- internpro.ai
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- jakmedytowac.pl
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- jakodirect.nl
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- jptravel-reserve.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- kingandqueenlimo.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- kupat.co.il
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- lallemandspecialtycultures.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- manavate.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- millie-staging.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- mirrorsphere.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- mixclx.net
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- nachtzug.net
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- ohmyfi.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- pikkufabric.dev
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- polyguard.ai
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- privatewealth.academy
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- re-cap.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- roadtestedparts.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- roofmarketplace.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- seminarhof-drawehn.de
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- seorav.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- sistemafb.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- snp1344.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- sonjj.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- spinzel.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tagginghippo.app
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tails.id
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tarta.ai
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tealyra.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tepavi.de
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- theimmersivecompany.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tiendasantaclara.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- toodledo.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tora-ks.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tresor.one
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- tripix.app
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- uptv.co.il
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- vapeandeliquid.co.uk
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- veracruz.edu.br
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- viact.ai
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- witec.com.br
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- xdflo.com
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- xremit.io
  ```
  method=asn; live_probe confidence=low live=yes
  ```
- belugahospitality.co.za
  ```
  method=asn confidence=low live=no
  ```
- bugherd-staging.com
  ```
  method=asn confidence=low live=no
  ```
- pokshin.com
  ```
  method=asn confidence=low live=no
  ```
- thehandy.com
  ```
  method=asn confidence=low live=no
  ```
- vs-test.info
  ```
  method=asn confidence=low live=no
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

### gau_discovery (81 finding(s) across 19 target(s))
**ads.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:35:38Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**api.bolnews.com**
- https://api.bolnews.com/
- https://api.bolnews.com/api
- https://api.bolnews.com/api/cachepurge/ImmediateCachePurge
- https://api.bolnews.com/api/DataPortal/Business?Api=featured&Language=en&Device=web&IsDropDown=true&IsFuel=true&IsGold=true&IsForex=true&IsCrypto=true&Currency=&coin=
- https://api.bolnews.com/api/dataportal/Business?Api=fuel_prices&Language=en&Currency=PKR&Type=NoSelected
- https://api.bolnews.com/api/dataportal/Business?Api=precious_metals&Language=en&Currency=PKR&Category=GOLD
- https://api.bolnews.com/api/DataPortal/Weather?Api=all_cities&Language=en&CountryCode=PK
- https://api.bolnews.com/api/DataPortal/Weather?Api=all_cities&Language=en&CountryCode=US
- https://api.bolnews.com/api/DataPortal/Weather?Api=all_cities&Language=urdu&CountryCode=US
- https://api.bolnews.com/api/DataPortal/Weather?Api=by_city&Language=en&CityId=1
- https://api.bolnews.com/api/DataPortal/Weather?Api=by_city&Language=en&CityId=42
- https://api.bolnews.com/api/DataPortal/Weather?Api=by_city&Language=urdu&CityId=42
- https://api.bolnews.com/api/DataPortal/Weather?Api=by_city&Language=en&CityId=null
- https://api.bolnews.com/api/DetailPage/GetLiveBlogDetails
- https://api.bolnews.com/api/NewsConfiguration/GetExtendedMenu?Slug=home&Language=urdu&Edition=PK
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=132&languageId=2&topicid=246407&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=133&languageId=2&topicid=419767&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=133&languageId=2&topicid=478931&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=133&languageId=2&topicid=478959&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=133&languageId=2&topicid=479101&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=142&languageId=2&topicid=137102&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=148&languageId=2&topicid=365402&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=189&languageId=2&topicid=195721&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=471512&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=474626&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=475387&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=476095&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=476115&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=477030&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=477042&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=478347&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=272&languageId=2&topicid=478400&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=510&languageId=2&topicid=99294&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=513&languageId=2&topicid=470433&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=513&languageId=2&topicid=476996&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=74&languageId=2&topicid=476705&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=8&languageId=2&topicid=470972&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=8&languageId=2&topicid=478104&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=8&languageId=2&topicid=478198&regionId&deviceId
- https://api.bolnews.com/api/Topics/GetLatestArticles?categoryId=923&languageId=2&regionId&deviceId
- https://api.bolnews.com/api/Viewership/AddView
- https://api.bolnews.com/api/Viewership/AddViewById?postid=147449&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=331750&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=333367&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=339102&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=343050&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=347216&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=349696&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=360883&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=378369&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=380170&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=382585&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=388643&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=404224&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=406876&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=408121&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=421184&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=437769&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/Viewership/AddViewById?postid=470042&cookie=-&userAgent=&created_ip=-
- https://api.bolnews.com/api/widget
- https://api.bolnews.com/favicon.ico
- https://api.bolnews.com/robots.txt
- https://api.bolnews.com/sitemap.xml

**apiv2.bolnews.com**
- http://apiv2.bolnews.com/

**bolnewswp-app.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:43:09Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**cruiseway.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:34:25Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**forum.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:32:38Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**live.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:41:19Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**m.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:43:35Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**mail.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:42:23Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**newspaperadmin.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:42:41Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**ns1.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:33:20Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**ns3.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:33:41Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**pop.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:34:45Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**server2.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:40:02Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**server4.bolnews.com**
- https://server4.bolnews.com/

**staging.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:40:30Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**textwp.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:41:46Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**v2.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:38:48Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
  ```

**vdo2.bolnews.com**
- gau_discovery raw output (ok)
  ```
  time="2026-08-16T04:40:51Z" level=warning msg="error reading config: Config file /home/mcpuser/.gau.toml not found, using default config"
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

### naabu_port_scan (6 finding(s) across 2 target(s))
**datav1.bolnews.com**
- datav1.bolnews.com:443/tcp open
  ```
  datav1.bolnews.com:443
  ```
- datav1.bolnews.com:8443/tcp open
  ```
  datav1.bolnews.com:8443
  ```
- datav1.bolnews.com:80/tcp open
  ```
  datav1.bolnews.com:80
  ```
- datav1.bolnews.com:8080/tcp open
  ```
  datav1.bolnews.com:8080
  ```

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

### nmap_service_scan (3 finding(s) across 2 target(s))
**datav1.bolnews.com**
- Output from nmap_service_scan
  ```
  Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 04:45 +0000
  Nmap scan report for datav1.bolnews.com (172.67.68.39)
  Host is up.
  Other addresses for datav1.bolnews.com (not scanned): 2606:4700:20::681a:a42 2606:4700:20::681a:b42 2606:4700:20::ac43:4427 104.26.10.66 104.26.11.66
  
  PORT     STATE    SERVICE    VERSION
  80/tcp   filtered http
  443/tcp  filtered https
  8080/tcp filtered http-proxy
  8443/tcp filtered https-alt
  
  Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
  Nmap done: 1 IP address (1 host up) scanned in 8.95 seconds
  ```

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

### subfinder_scan (44 finding(s) across 2 target(s))
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

**staging.bolnews.com**
- www.staging.bolnews.com
- cpanel.staging.bolnews.com
- cpcalendars.staging.bolnews.com
- cpcontacts.staging.bolnews.com
- mail.staging.bolnews.com
- webdisk.staging.bolnews.com
- webmail.staging.bolnews.com

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

### tlsx_inspect (8 finding(s) across 6 target(s))
**bolnews.com**
- TLS bolnews.com:443
  ```
  {"timestamp":"2026-08-16T03:35:54.695858027Z","host":"bolnews.com","ip":"104.26.11.66","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-06-29T15:45:25Z","not_after":"2026-09-27T16:45:08Z","subject_dn":"CN=bolnews.com","subject_cn":"bolnews.com","subject_an":["bolnews.com","*.bolnews.com"],"serial":"EB:1B:6F:08:19:65:C7:EC:0E:4C:67:D9:DE:96:95:F4","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"febe6edf84d4081320bde4c69565c4a0","sha1":"8465dea84d3f469350c980c074a48648bbd90475","sha256":"36191a71c6b241e9562ab38fb5ced500b2d4af6dd36de76999efb60ede702040"},"wildcard_certificate":true,"tls_connection":"ctls","sni":"boln
  ```
- bolnews.com

**datav1.bolnews.com**
- TLS datav1.bolnews.com:443
  ```
  {"timestamp":"2026-08-16T04:38:03.001258243Z","host":"datav1.bolnews.com","ip":"104.26.10.66","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-06-29T15:45:25Z","not_after":"2026-09-27T16:45:08Z","subject_dn":"CN=bolnews.com","subject_cn":"bolnews.com","subject_an":["bolnews.com","*.bolnews.com"],"serial":"EB:1B:6F:08:19:65:C7:EC:0E:4C:67:D9:DE:96:95:F4","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"febe6edf84d4081320bde4c69565c4a0","sha1":"8465dea84d3f469350c980c074a48648bbd90475","sha256":"36191a71c6b241e9562ab38fb5ced500b2d4af6dd36de76999efb60ede702040"},"wildcard_certificate":true,"tls_connection":"ctls","sni
  ```

**mail.bolnews.com**
- TLS mail.bolnews.com:443
  ```
  {"timestamp":"2026-08-16T04:42:26.50066644Z","host":"mail.bolnews.com","ip":"221.132.113.226","port":"443","probe_status":true,"tls_version":"tls12","cipher":"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","key_exchange":"CurveP256","mismatched":true,"not_before":"2025-09-29T00:00:00Z","not_after":"2026-10-30T23:59:59Z","subject_dn":"CN=*.bolnetwork.com","subject_cn":"*.bolnetwork.com","subject_an":["*.bolnetwork.com","bolnetwork.com"],"serial":"E6:34:39:1D:66:55:91:56:08:ED:E2:27:BF:9C:67:DE","issuer_dn":"CN=Sectigo Public Server Authentication CA DV R36, O=Sectigo Limited, C=GB","issuer_cn":"Sectigo Public Server Authentication CA DV R36","issuer_org":["Sectigo Limited"],"fingerprint_hash":{"md5":"c1ca34513e559a4c2277aa7d397f61a1","sha1":"22a92879f2bab0319667c6e25c010b4e33ed00dc","sha256":"3d2e5
  ```
- bolnetwork.com

**server4.bolnews.com**
- TLS server4.bolnews.com:443
  ```
  {"timestamp":"2026-08-16T04:44:14.018197296Z","host":"server4.bolnews.com","ip":"104.26.10.66","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-06-29T15:45:25Z","not_after":"2026-09-27T16:45:08Z","subject_dn":"CN=bolnews.com","subject_cn":"bolnews.com","subject_an":["bolnews.com","*.bolnews.com"],"serial":"EB:1B:6F:08:19:65:C7:EC:0E:4C:67:D9:DE:96:95:F4","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"febe6edf84d4081320bde4c69565c4a0","sha1":"8465dea84d3f469350c980c074a48648bbd90475","sha256":"36191a71c6b241e9562ab38fb5ced500b2d4af6dd36de76999efb60ede702040"},"wildcard_certificate":true,"tls_connection":"ctls","sn
  ```

**staging.bolnews.com**
- TLS staging.bolnews.com:443
  ```
  {"timestamp":"2026-08-16T04:40:36.406227725Z","host":"staging.bolnews.com","ip":"104.26.11.66","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-06-29T15:45:25Z","not_after":"2026-09-27T16:45:08Z","subject_dn":"CN=bolnews.com","subject_cn":"bolnews.com","subject_an":["bolnews.com","*.bolnews.com"],"serial":"EB:1B:6F:08:19:65:C7:EC:0E:4C:67:D9:DE:96:95:F4","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"febe6edf84d4081320bde4c69565c4a0","sha1":"8465dea84d3f469350c980c074a48648bbd90475","sha256":"36191a71c6b241e9562ab38fb5ced500b2d4af6dd36de76999efb60ede702040"},"wildcard_certificate":true,"tls_connection":"ctls","sn
  ```

**www.bolnews.com**
- TLS www.bolnews.com:443
  ```
  {"timestamp":"2026-08-16T04:32:09.890818999Z","host":"www.bolnews.com","ip":"104.26.11.66","port":"443","probe_status":true,"tls_version":"tls13","cipher":"TLS_AES_128_GCM_SHA256","key_exchange":"X25519MLKEM768","not_before":"2026-06-29T15:45:25Z","not_after":"2026-09-27T16:45:08Z","subject_dn":"CN=bolnews.com","subject_cn":"bolnews.com","subject_an":["bolnews.com","*.bolnews.com"],"serial":"EB:1B:6F:08:19:65:C7:EC:0E:4C:67:D9:DE:96:95:F4","issuer_dn":"CN=WE1, O=Google Trust Services, C=US","issuer_cn":"WE1","issuer_org":["Google Trust Services"],"fingerprint_hash":{"md5":"febe6edf84d4081320bde4c69565c4a0","sha1":"8465dea84d3f469350c980c074a48648bbd90475","sha256":"36191a71c6b241e9562ab38fb5ced500b2d4af6dd36de76999efb60ede702040"},"wildcard_certificate":true,"tls_connection":"ctls","sni":"
  ```

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

### waybackurls_discovery (619 finding(s) across 8 target(s))
**bolnewswp-api.bolnews.com**
- http://bolnewswp-api.bolnews.com/

**bolnewswp-app.bolnews.com**
- http://bolnewswp-app.bolnews.com/

**datav1.bolnews.com**
- http://datav1.bolnews.com/
- https://datav1.bolnews.com/index.html

**live.bolnews.com**
- http://live.bolnews.com:80/
- http://live.bolnews.com/assets/css/style.css
- http://live.bolnews.com/assets/images/headerBg.jpg
- http://live.bolnews.com/assets/images/logo.png
- http://live.bolnews.com/assets/images/sharelink.jpg
- http://live.bolnews.com/assets/images/sprite.png
- http://live.bolnews.com/assets/js/html5.js
- http://live.bolnews.com/assets/js/jquery.js
- http://live.bolnews.com/favicon.ico
- http://live.bolnews.com:80/RiNSZ
- http://live.bolnews.com/robots.txt

**m.bolnews.com**
- https://m.bolnews.com/astrology/relationship-marriage/2022/05/462317/
- https://m.bolnews.com/astrology/relationship-marriage/2022/05/watch-fatima-effendi-in-turkey/
- https://m.bolnews.com/entertainment/2022/05/netizens-are-not-buying-in-on-hiba-bukharis-pashtoon-accent/
- https://m.bolnews.com/favicon.ico
- https://m.bolnews.com/international/2022/05/shoes-made-of-mushroom-leather-balenciaga-hermes-gucci-and-others-investing-in-animal-free-leather/
- https://m.bolnews.com/latest/2022/05/462317/
- https://m.bolnews.com/latest/2022/05/netizens-are-not-buying-in-on-hiba-bukharis-pashtoon-accent/
- https://m.bolnews.com/latest/2022/05/watch-fatima-effendi-in-turkey/
- https://m.bolnews.com/lifestyle/fashion/2022/05/shoes-made-of-mushroom-leather-balenciaga-hermes-gucci-and-others-investing-in-animal-free-leather/
- https://m.bolnews.com/robots.txt
- https://m.bolnews.com/sitemap.xml
- https://m.bolnews.com/urdu/
- https://m.bolnews.com/urdu/%D8%B9%D8%AF%D8%A7%D9%84%D8%AA/2022/08/819387/
- https://m.bolnews.com/urdu/%D9%88%D8%B1%D9%84%DA%88/2022/09/125794/
- https://m.bolnews.com/urdu/amazing/2022/03/466355/
- https://m.bolnews.com/urdu/amazing/2022/05/150690/
- https://m.bolnews.com/urdu/amazing/2022/05/168283/
- https://m.bolnews.com/urdu/amazing/2022/05/172378/
- https://m.bolnews.com/urdu/amazing/2022/05/393144/
- https://m.bolnews.com/urdu/amazing/2022/05/417679/
- https://m.bolnews.com/urdu/amazing/2022/05/497618/
- https://m.bolnews.com/urdu/amazing/2022/05/522196/
- https://m.bolnews.com/urdu/amazing/2022/05/595314/
- https://m.bolnews.com/urdu/amazing/2022/05/735841/
- https://m.bolnews.com/urdu/amazing/2022/05/755400/
- https://m.bolnews.com/urdu/amazing/2022/06/144827/
- https://m.bolnews.com/urdu/amazing/2022/06/211673/
- https://m.bolnews.com/urdu/amazing/2022/06/317643/
- https://m.bolnews.com/urdu/amazing/2022/06/467959/
- https://m.bolnews.com/urdu/amazing/2022/06/560352/
- https://m.bolnews.com/urdu/amazing/2022/06/692355/
- https://m.bolnews.com/urdu/amazing/2022/06/908433/
- https://m.bolnews.com/urdu/amazing/2022/06/955111/
- https://m.bolnews.com/urdu/amazing/2022/08/102389/
- https://m.bolnews.com/urdu/amazing/2022/08/121321/
- https://m.bolnews.com/urdu/amazing/2022/08/122593/
- https://m.bolnews.com/urdu/amazing/2022/08/139385/
- https://m.bolnews.com/urdu/amazing/2022/08/150350/
- https://m.bolnews.com/urdu/amazing/2022/08/154344/
- https://m.bolnews.com/urdu/amazing/2022/08/161849/
- https://m.bolnews.com/urdu/amazing/2022/08/178460/
- https://m.bolnews.com/urdu/amazing/2022/08/194205/
- https://m.bolnews.com/urdu/amazing/2022/08/196211/
- https://m.bolnews.com/urdu/amazing/2022/08/230631/
- https://m.bolnews.com/urdu/amazing/2022/08/244380/
- https://m.bolnews.com/urdu/amazing/2022/08/259502/
- https://m.bolnews.com/urdu/amazing/2022/08/285480/
- https://m.bolnews.com/urdu/amazing/2022/08/292871/
- https://m.bolnews.com/urdu/amazing/2022/08/293239/
- https://m.bolnews.com/urdu/amazing/2022/08/301768/
- https://m.bolnews.com/urdu/amazing/2022/08/310642/
- https://m.bolnews.com/urdu/amazing/2022/08/319935/
- https://m.bolnews.com/urdu/amazing/2022/08/404622/
- https://m.bolnews.com/urdu/amazing/2022/08/405274/
- https://m.bolnews.com/urdu/amazing/2022/08/412373/
- https://m.bolnews.com/urdu/amazing/2022/08/416855/
- https://m.bolnews.com/urdu/amazing/2022/08/418263/
- https://m.bolnews.com/urdu/amazing/2022/08/442934/
- https://m.bolnews.com/urdu/amazing/2022/08/456314/
- https://m.bolnews.com/urdu/amazing/2022/08/483897/
- https://m.bolnews.com/urdu/amazing/2022/08/490608/
- https://m.bolnews.com/urdu/amazing/2022/08/494861/
- https://m.bolnews.com/urdu/amazing/2022/08/509901/
- https://m.bolnews.com/urdu/amazing/2022/08/524308/
- https://m.bolnews.com/urdu/amazing/2022/08/532453/
- https://m.bolnews.com/urdu/amazing/2022/08/536384/
- https://m.bolnews.com/urdu/amazing/2022/08/551861/
- https://m.bolnews.com/urdu/amazing/2022/08/555412/
- https://m.bolnews.com/urdu/amazing/2022/08/560848/
- https://m.bolnews.com/urdu/amazing/2022/08/565926/
- https://m.bolnews.com/urdu/amazing/2022/08/589580/
- https://m.bolnews.com/urdu/amazing/2022/08/595663/
- https://m.bolnews.com/urdu/amazing/2022/08/596562/
- https://m.bolnews.com/urdu/amazing/2022/08/596781/
- https://m.bolnews.com/urdu/amazing/2022/08/599104/
- https://m.bolnews.com/urdu/amazing/2022/08/602665/
- https://m.bolnews.com/urdu/amazing/2022/08/605922/
- https://m.bolnews.com/urdu/amazing/2022/08/621043/
- https://m.bolnews.com/urdu/amazing/2022/08/629192/
- https://m.bolnews.com/urdu/amazing/2022/08/631538/
- https://m.bolnews.com/urdu/amazing/2022/08/643670/
- https://m.bolnews.com/urdu/amazing/2022/08/658365/
- https://m.bolnews.com/urdu/amazing/2022/08/679696/
- https://m.bolnews.com/urdu/amazing/2022/08/681197/
- https://m.bolnews.com/urdu/amazing/2022/08/736133/
- https://m.bolnews.com/urdu/amazing/2022/08/759116/
- https://m.bolnews.com/urdu/amazing/2022/08/773585/
- https://m.bolnews.com/urdu/amazing/2022/08/848881/
- https://m.bolnews.com/urdu/amazing/2022/08/863104/
- https://m.bolnews.com/urdu/amazing/2022/08/889506/
- https://m.bolnews.com/urdu/amazing/2022/08/900698/
- https://m.bolnews.com/urdu/amazing/2022/08/913663/
- https://m.bolnews.com/urdu/amazing/2022/08/916900/
- https://m.bolnews.com/urdu/amazing/2022/08/940349/
- https://m.bolnews.com/urdu/amazing/2022/08/950045/
- https://m.bolnews.com/urdu/amazing/2022/08/967114/
- https://m.bolnews.com/urdu/amazing/2022/08/972275/
- https://m.bolnews.com/urdu/amazing/2022/08/977706/
- https://m.bolnews.com/urdu/amazing/2022/08/987258/
- https://m.bolnews.com/urdu/amazing/2022/09/100573/
- https://m.bolnews.com/urdu/amazing/2022/09/103536/
- https://m.bolnews.com/urdu/amazing/2022/09/103892/
- https://m.bolnews.com/urdu/amazing/2022/09/104067/
- https://m.bolnews.com/urdu/amazing/2022/09/119159/
- https://m.bolnews.com/urdu/amazing/2022/09/137905/
- https://m.bolnews.com/urdu/amazing/2022/09/138615/
- https://m.bolnews.com/urdu/amazing/2022/09/138781/
- https://m.bolnews.com/urdu/amazing/2022/09/138982/
- https://m.bolnews.com/urdu/amazing/2022/09/150377/
- https://m.bolnews.com/urdu/amazing/2022/09/159451/
- https://m.bolnews.com/urdu/amazing/2022/09/172558/
- https://m.bolnews.com/urdu/amazing/2022/09/182698/
- https://m.bolnews.com/urdu/amazing/2022/09/187172/
- https://m.bolnews.com/urdu/amazing/2022/09/193451/
- https://m.bolnews.com/urdu/amazing/2022/09/195990/
- https://m.bolnews.com/urdu/amazing/2022/09/206808/
- https://m.bolnews.com/urdu/amazing/2022/09/209268/
- https://m.bolnews.com/urdu/amazing/2022/09/210040/
- https://m.bolnews.com/urdu/amazing/2022/09/213380/
- https://m.bolnews.com/urdu/amazing/2022/09/226789/
- https://m.bolnews.com/urdu/amazing/2022/09/230200/
- https://m.bolnews.com/urdu/amazing/2022/09/240755/
- https://m.bolnews.com/urdu/amazing/2022/09/246757/
- https://m.bolnews.com/urdu/amazing/2022/09/250719/
- https://m.bolnews.com/urdu/amazing/2022/09/254241/
- https://m.bolnews.com/urdu/amazing/2022/09/259015/
- https://m.bolnews.com/urdu/amazing/2022/09/260162/
- https://m.bolnews.com/urdu/amazing/2022/09/269369/
- https://m.bolnews.com/urdu/amazing/2022/09/270312/
- https://m.bolnews.com/urdu/amazing/2022/09/273448/
- https://m.bolnews.com/urdu/amazing/2022/09/280087/
- https://m.bolnews.com/urdu/amazing/2022/09/281666/
- https://m.bolnews.com/urdu/amazing/2022/09/293910/
- https://m.bolnews.com/urdu/amazing/2022/09/303973/
- https://m.bolnews.com/urdu/amazing/2022/09/310579/
- https://m.bolnews.com/urdu/amazing/2022/09/327362/
- https://m.bolnews.com/urdu/amazing/2022/09/332440/
- https://m.bolnews.com/urdu/amazing/2022/09/332502/
- https://m.bolnews.com/urdu/amazing/2022/09/335248/
- https://m.bolnews.com/urdu/amazing/2022/09/340063/
- https://m.bolnews.com/urdu/amazing/2022/09/345606/
- https://m.bolnews.com/urdu/amazing/2022/09/348178/
- https://m.bolnews.com/urdu/amazing/2022/09/352029/
- https://m.bolnews.com/urdu/amazing/2022/09/355574/
- https://m.bolnews.com/urdu/amazing/2022/09/363216/
- https://m.bolnews.com/urdu/amazing/2022/09/367034/
- https://m.bolnews.com/urdu/amazing/2022/09/378740/
- https://m.bolnews.com/urdu/amazing/2022/09/382144/
- https://m.bolnews.com/urdu/amazing/2022/09/387670/
- https://m.bolnews.com/urdu/amazing/2022/09/389153/
- https://m.bolnews.com/urdu/amazing/2022/09/399444/
- https://m.bolnews.com/urdu/amazing/2022/09/399803/
- https://m.bolnews.com/urdu/amazing/2022/09/402415/
- https://m.bolnews.com/urdu/amazing/2022/09/408663/
- https://m.bolnews.com/urdu/amazing/2022/09/409337/
- https://m.bolnews.com/urdu/amazing/2022/09/412760/
- https://m.bolnews.com/urdu/amazing/2022/09/418148/
- https://m.bolnews.com/urdu/amazing/2022/09/420856/
- https://m.bolnews.com/urdu/amazing/2022/09/422525/
- https://m.bolnews.com/urdu/amazing/2022/09/426689/
- https://m.bolnews.com/urdu/amazing/2022/09/436872/
- https://m.bolnews.com/urdu/amazing/2022/09/444037/
- https://m.bolnews.com/urdu/amazing/2022/09/447247/
- https://m.bolnews.com/urdu/amazing/2022/09/457061/
- https://m.bolnews.com/urdu/amazing/2022/09/470302/
- https://m.bolnews.com/urdu/amazing/2022/09/475177/
- https://m.bolnews.com/urdu/amazing/2022/09/478426/
- https://m.bolnews.com/urdu/amazing/2022/09/482492/
- https://m.bolnews.com/urdu/amazing/2022/09/503837/
- https://m.bolnews.com/urdu/amazing/2022/09/517669/
- https://m.bolnews.com/urdu/amazing/2022/09/522991/
- https://m.bolnews.com/urdu/amazing/2022/09/538440/
- https://m.bolnews.com/urdu/amazing/2022/09/538691/
- https://m.bolnews.com/urdu/amazing/2022/09/545670/
- https://m.bolnews.com/urdu/amazing/2022/09/548703/
- https://m.bolnews.com/urdu/amazing/2022/09/557629/
- https://m.bolnews.com/urdu/amazing/2022/09/559425/
- https://m.bolnews.com/urdu/amazing/2022/09/572046/
- https://m.bolnews.com/urdu/amazing/2022/09/576704/
- https://m.bolnews.com/urdu/amazing/2022/09/583022/
- https://m.bolnews.com/urdu/amazing/2022/09/583668/
- https://m.bolnews.com/urdu/amazing/2022/09/590051/
- https://m.bolnews.com/urdu/amazing/2022/09/599462/
- https://m.bolnews.com/urdu/amazing/2022/09/608322/
- https://m.bolnews.com/urdu/amazing/2022/09/609121/
- https://m.bolnews.com/urdu/amazing/2022/09/611360/
- https://m.bolnews.com/urdu/amazing/2022/09/614508/
- https://m.bolnews.com/urdu/amazing/2022/09/617862/
- https://m.bolnews.com/urdu/amazing/2022/09/627850/
- https://m.bolnews.com/urdu/amazing/2022/09/630152/
- https://m.bolnews.com/urdu/amazing/2022/09/634662/
- https://m.bolnews.com/urdu/amazing/2022/09/638333/
- https://m.bolnews.com/urdu/amazing/2022/09/656848/
- https://m.bolnews.com/urdu/amazing/2022/09/658558/
- https://m.bolnews.com/urdu/amazing/2022/09/667058/
- https://m.bolnews.com/urdu/amazing/2022/09/674456/
- https://m.bolnews.com/urdu/amazing/2022/09/689986/
- https://m.bolnews.com/urdu/amazing/2022/09/690228/
- https://m.bolnews.com/urdu/amazing/2022/09/695694/
- https://m.bolnews.com/urdu/amazing/2022/09/696283/
- https://m.bolnews.com/urdu/amazing/2022/09/703598/
- https://m.bolnews.com/urdu/amazing/2022/09/705802/
- https://m.bolnews.com/urdu/amazing/2022/09/708411/
- https://m.bolnews.com/urdu/amazing/2022/09/712050/
- https://m.bolnews.com/urdu/amazing/2022/09/713968/
- https://m.bolnews.com/urdu/amazing/2022/09/715578/
- https://m.bolnews.com/urdu/amazing/2022/09/716764/
- https://m.bolnews.com/urdu/amazing/2022/09/721305/
- https://m.bolnews.com/urdu/amazing/2022/09/723050/
- https://m.bolnews.com/urdu/amazing/2022/09/724227/
- https://m.bolnews.com/urdu/amazing/2022/09/729469/
- https://m.bolnews.com/urdu/amazing/2022/09/731369/
- https://m.bolnews.com/urdu/amazing/2022/09/735056/
- https://m.bolnews.com/urdu/amazing/2022/09/750219/
- https://m.bolnews.com/urdu/amazing/2022/09/750955/
- https://m.bolnews.com/urdu/amazing/2022/09/761305/
- https://m.bolnews.com/urdu/amazing/2022/09/764475/
- https://m.bolnews.com/urdu/amazing/2022/09/768573/
- https://m.bolnews.com/urdu/amazing/2022/09/771187/
- https://m.bolnews.com/urdu/amazing/2022/09/771711/
- https://m.bolnews.com/urdu/amazing/2022/09/787092/
- https://m.bolnews.com/urdu/amazing/2022/09/788444/
- https://m.bolnews.com/urdu/amazing/2022/09/794935/
- https://m.bolnews.com/urdu/amazing/2022/09/798922/
- https://m.bolnews.com/urdu/amazing/2022/09/799108/
- https://m.bolnews.com/urdu/amazing/2022/09/814621/
- https://m.bolnews.com/urdu/amazing/2022/09/816994/
- https://m.bolnews.com/urdu/amazing/2022/09/818219/
- https://m.bolnews.com/urdu/amazing/2022/09/823363/
- https://m.bolnews.com/urdu/amazing/2022/09/827294/
- https://m.bolnews.com/urdu/amazing/2022/09/829579/
- https://m.bolnews.com/urdu/amazing/2022/09/840766/
- https://m.bolnews.com/urdu/amazing/2022/09/840962/
- https://m.bolnews.com/urdu/amazing/2022/09/847477/
- https://m.bolnews.com/urdu/amazing/2022/09/861637/
- https://m.bolnews.com/urdu/amazing/2022/09/864129/
- https://m.bolnews.com/urdu/amazing/2022/09/865276/
- https://m.bolnews.com/urdu/amazing/2022/09/870855/
- https://m.bolnews.com/urdu/amazing/2022/09/874741/
- https://m.bolnews.com/urdu/amazing/2022/09/897693/
- https://m.bolnews.com/urdu/amazing/2022/09/898298/
- https://m.bolnews.com/urdu/amazing/2022/09/917678/
- https://m.bolnews.com/urdu/amazing/2022/09/926072/
- https://m.bolnews.com/urdu/amazing/2022/09/931644/
- https://m.bolnews.com/urdu/amazing/2022/09/941548/
- https://m.bolnews.com/urdu/amazing/2022/09/948470/
- https://m.bolnews.com/urdu/amazing/2022/09/949181/
- https://m.bolnews.com/urdu/amazing/2022/09/953020/
- https://m.bolnews.com/urdu/amazing/2022/09/956270/
- https://m.bolnews.com/urdu/amazing/2022/09/966723/
- https://m.bolnews.com/urdu/amazing/2022/09/971678/
- https://m.bolnews.com/urdu/amazing/2022/09/972224/
- https://m.bolnews.com/urdu/amazing/2022/09/978646/
- https://m.bolnews.com/urdu/amazing/2022/09/980054/
- https://m.bolnews.com/urdu/amazing/2022/09/984066/
- https://m.bolnews.com/urdu/amazing/2022/09/995832/
- https://m.bolnews.com/urdu/amazing/2022/09/996646/
- https://m.bolnews.com/urdu/amazing/2022/09/997537/
- https://m.bolnews.com/urdu/amazing/2022/09/998566/
- https://m.bolnews.com/urdu/amazing/2022/10/100901/
- https://m.bolnews.com/urdu/amazing/2022/10/101643/
- https://m.bolnews.com/urdu/amazing/2022/10/108944/
- https://m.bolnews.com/urdu/amazing/2022/10/120800/
- https://m.bolnews.com/urdu/amazing/2022/10/124343/
- https://m.bolnews.com/urdu/amazing/2022/10/125115/
- https://m.bolnews.com/urdu/amazing/2022/10/125442/
- https://m.bolnews.com/urdu/amazing/2022/10/128325/
- https://m.bolnews.com/urdu/amazing/2022/10/133404/
- https://m.bolnews.com/urdu/amazing/2022/10/134481/
- https://m.bolnews.com/urdu/amazing/2022/10/134653/
- https://m.bolnews.com/urdu/amazing/2022/10/140446/
- https://m.bolnews.com/urdu/amazing/2022/10/145178/
- https://m.bolnews.com/urdu/amazing/2022/10/161874/
- https://m.bolnews.com/urdu/amazing/2022/10/164136/
- https://m.bolnews.com/urdu/amazing/2022/10/167161/
- https://m.bolnews.com/urdu/amazing/2022/10/170395/
- https://m.bolnews.com/urdu/amazing/2022/10/196380/
- https://m.bolnews.com/urdu/amazing/2022/10/198530/
- https://m.bolnews.com/urdu/amazing/2022/10/198764/
- https://m.bolnews.com/urdu/amazing/2022/10/213527/
- https://m.bolnews.com/urdu/amazing/2022/10/217585/
- https://m.bolnews.com/urdu/amazing/2022/10/219350/
- https://m.bolnews.com/urdu/amazing/2022/10/220264/
- https://m.bolnews.com/urdu/amazing/2022/10/221373/
- https://m.bolnews.com/urdu/amazing/2022/10/221784/
- https://m.bolnews.com/urdu/amazing/2022/10/226832/
- https://m.bolnews.com/urdu/amazing/2022/10/231457/
- https://m.bolnews.com/urdu/amazing/2022/10/232755/
- https://m.bolnews.com/urdu/amazing/2022/10/233604/
- https://m.bolnews.com/urdu/amazing/2022/10/235474/
- https://m.bolnews.com/urdu/amazing/2022/10/240956/
- https://m.bolnews.com/urdu/amazing/2022/10/244552/
- https://m.bolnews.com/urdu/amazing/2022/10/246058/
- https://m.bolnews.com/urdu/amazing/2022/10/247282/
- https://m.bolnews.com/urdu/amazing/2022/10/248241/
- https://m.bolnews.com/urdu/amazing/2022/10/253126/
- https://m.bolnews.com/urdu/amazing/2022/10/255420/
- https://m.bolnews.com/urdu/amazing/2022/10/258398/
- https://m.bolnews.com/urdu/amazing/2022/10/258974/
- https://m.bolnews.com/urdu/amazing/2022/10/272418/
- waybackurls_discovery: 660 additional URL(s) not stored individually
  ```
  total=960 stored=300 excluded=660
  ```

**newspaperadmin.bolnews.com**
- http://newspaperadmin.bolnews.com/

**server2.bolnews.com**
- http://server2.bolnews.com/

**staging.bolnews.com**
- https://staging.bolnews.com/
- https://staging.bolnews.com/%region%/latest/afghanistan-first-cricket-test-approved-by-taliban-since-the-takeover.html/
- https://staging.bolnews.com/%region%/latest/asim-azhar-is-trending-on-twitter-for-all-the-right-the-reason.html/
- https://staging.bolnews.com/%region%/latest/dont-even-think-about-it-global-warming-is-a-hoax.html/
- https://staging.bolnews.com/%region%/latest/finally-48-years-old-jia-ali-got-married-with-this-famous-pti-member.html/
- https://staging.bolnews.com/%region%/latest/indian-tv-actor-sidharth-shukla-passes-away-fans-mourn-his-sudden-demise.html/
- https://staging.bolnews.com/%region%/latest/sidharth-shukla-death-did-you-know-his-co-actor-commit-suicide.html/
- https://staging.bolnews.com/%region%/latest/sidharth-shukla-death-shehnaaz-gill-not-fine-indian-celebs-left-void-heartbroken.html/
- https://staging.bolnews.com/%region%/trending/ertugrul-esra-leaves-fans-swooning-with-first-trailer-of-kanunsuz-topraklar.html/
- https://staging.bolnews.com/+response.Data[index][image_url]+
- https://staging.bolnews.com/+response.Data[index][permalink]+
- https://staging.bolnews.com/21836501584/BOL_News_160X600
- https://staging.bolnews.com/21836501584/BOL_News_300_250_ADX
- https://staging.bolnews.com/21836501584/BOL_News_300X100
- https://staging.bolnews.com/21836501584/BOL_News_Home_Page_TopBanner
- https://staging.bolnews.com/21836501584/BOL_News_Urdu_728X90
- https://staging.bolnews.com/?p=101259
- https://staging.bolnews.com/?p=101412
- https://staging.bolnews.com/?p=101615
- https://staging.bolnews.com/?p=107284
- https://staging.bolnews.com/?p=109065
- https://staging.bolnews.com/?p=109662
- https://staging.bolnews.com/?p=117461
- https://staging.bolnews.com/?p=117850
- https://staging.bolnews.com/?p=121918
- https://staging.bolnews.com/?p=127935
- https://staging.bolnews.com/?p=127941
- https://staging.bolnews.com/?p=127944
- https://staging.bolnews.com/?p=128028
- https://staging.bolnews.com/?p=128360
- https://staging.bolnews.com/?p=139105
- https://staging.bolnews.com/?p=147568
- https://staging.bolnews.com/?p=150377
- https://staging.bolnews.com/?p=157219
- https://staging.bolnews.com/?p=157247
- https://staging.bolnews.com/?p=176777
- https://staging.bolnews.com/?p=182274
- https://staging.bolnews.com/?p=183061
- https://staging.bolnews.com/?p=183070
- https://staging.bolnews.com/?p=183368
- https://staging.bolnews.com/?p=183503
- https://staging.bolnews.com/?p=185608
- https://staging.bolnews.com/?p=185671
- https://staging.bolnews.com/?p=185971
- https://staging.bolnews.com/?p=186872
- https://staging.bolnews.com/?p=188177
- https://staging.bolnews.com/?p=188260
- https://staging.bolnews.com/?p=188436
- https://staging.bolnews.com/?p=188516
- https://staging.bolnews.com/?p=188784
- https://staging.bolnews.com/?p=189844
- https://staging.bolnews.com/?p=191146
- https://staging.bolnews.com/?p=191679
- https://staging.bolnews.com/?p=192200
- https://staging.bolnews.com/?p=192251
- https://staging.bolnews.com/?p=192519
- https://staging.bolnews.com/?p=192583
- https://staging.bolnews.com/?p=194448
- https://staging.bolnews.com/?p=194546
- https://staging.bolnews.com/?p=194582
- https://staging.bolnews.com/?p=194789
- https://staging.bolnews.com/?p=197023
- https://staging.bolnews.com/?p=197113
- https://staging.bolnews.com/?p=197235
- https://staging.bolnews.com/?p=197455
- https://staging.bolnews.com/?p=200037
- https://staging.bolnews.com/?p=200116
- https://staging.bolnews.com/?p=200362
- https://staging.bolnews.com/?p=200434
- https://staging.bolnews.com/?p=202227
- https://staging.bolnews.com/?p=203095
- https://staging.bolnews.com/?p=203125
- https://staging.bolnews.com/?p=203196
- https://staging.bolnews.com/?p=206366
- https://staging.bolnews.com/?p=206522
- https://staging.bolnews.com/?p=206988
- https://staging.bolnews.com/?p=207105
- https://staging.bolnews.com/?p=207642
- https://staging.bolnews.com/?p=208296
- https://staging.bolnews.com/?p=208778
- https://staging.bolnews.com/?p=209314
- https://staging.bolnews.com/?p=209681
- https://staging.bolnews.com/?p=209746
- https://staging.bolnews.com/?p=209778
- https://staging.bolnews.com/?p=209996
- https://staging.bolnews.com/?p=210034
- https://staging.bolnews.com/?p=210674
- https://staging.bolnews.com/?p=212410
- https://staging.bolnews.com/?p=213156
- https://staging.bolnews.com/?p=213179
- https://staging.bolnews.com/?p=213274
- https://staging.bolnews.com/?p=214527
- https://staging.bolnews.com/?p=214701
- https://staging.bolnews.com/?p=214957
- https://staging.bolnews.com/?p=215005
- https://staging.bolnews.com/?p=215094
- https://staging.bolnews.com/?p=215378
- https://staging.bolnews.com/?p=215648
- https://staging.bolnews.com/?p=216319
- https://staging.bolnews.com/?p=216589
- https://staging.bolnews.com/?p=217190
- https://staging.bolnews.com/?p=221135
- https://staging.bolnews.com/?p=221195
- https://staging.bolnews.com/?p=221330
- https://staging.bolnews.com/?p=221597
- https://staging.bolnews.com/?p=221719
- https://staging.bolnews.com/?p=221753
- https://staging.bolnews.com/?p=222058
- https://staging.bolnews.com/?p=222213
- https://staging.bolnews.com/?p=223593
- https://staging.bolnews.com/?p=223713
- https://staging.bolnews.com/?p=224268
- https://staging.bolnews.com/?p=224647
- https://staging.bolnews.com/?p=224739
- https://staging.bolnews.com/?p=224914
- https://staging.bolnews.com/?p=225020
- https://staging.bolnews.com/?p=225840
- https://staging.bolnews.com/?p=225972
- https://staging.bolnews.com/?p=226302
- https://staging.bolnews.com/?p=226399
- https://staging.bolnews.com/?p=226424
- https://staging.bolnews.com/?p=229382
- https://staging.bolnews.com/?p=229448
- https://staging.bolnews.com/?p=229812
- https://staging.bolnews.com/?p=230109
- https://staging.bolnews.com/?p=230369
- https://staging.bolnews.com/?p=230673
- https://staging.bolnews.com/?p=231567
- https://staging.bolnews.com/?p=231672
- https://staging.bolnews.com/?p=232162
- https://staging.bolnews.com/?p=232331
- https://staging.bolnews.com/?p=232767
- https://staging.bolnews.com/?p=232871
- https://staging.bolnews.com/?p=233920
- https://staging.bolnews.com/?p=234889
- https://staging.bolnews.com/?p=235047
- https://staging.bolnews.com/?p=235593
- https://staging.bolnews.com/?p=236114
- https://staging.bolnews.com/?p=238304
- https://staging.bolnews.com/?p=239629
- https://staging.bolnews.com/?p=239669
- https://staging.bolnews.com/?p=239684
- https://staging.bolnews.com/?p=239828
- https://staging.bolnews.com/?p=240271
- https://staging.bolnews.com/?p=240925
- https://staging.bolnews.com/?p=241195
- https://staging.bolnews.com/?p=241302
- https://staging.bolnews.com/?p=241397
- https://staging.bolnews.com/?p=241403
- https://staging.bolnews.com/?p=241821
- https://staging.bolnews.com/?p=242101
- https://staging.bolnews.com/?p=242107
- https://staging.bolnews.com/?p=242118
- https://staging.bolnews.com/?p=242200
- https://staging.bolnews.com/?p=242203
- https://staging.bolnews.com/?p=242246
- https://staging.bolnews.com/?p=242791
- https://staging.bolnews.com/?p=243067
- https://staging.bolnews.com/?p=243182
- https://staging.bolnews.com/?p=243198
- https://staging.bolnews.com/?p=243218
- https://staging.bolnews.com/?p=243359
- https://staging.bolnews.com/?p=243378
- https://staging.bolnews.com/?p=243495
- https://staging.bolnews.com/?p=243496
- https://staging.bolnews.com/?p=243539
- https://staging.bolnews.com/?p=243541
- https://staging.bolnews.com/?p=243784
- https://staging.bolnews.com/?p=244031
- https://staging.bolnews.com/?p=244034
- https://staging.bolnews.com/?p=244105
- https://staging.bolnews.com/?p=244181
- https://staging.bolnews.com/?p=244225
- https://staging.bolnews.com/?p=244300
- https://staging.bolnews.com/?p=244307
- https://staging.bolnews.com/?p=244314
- https://staging.bolnews.com/?p=244341
- https://staging.bolnews.com/?p=244358
- https://staging.bolnews.com/?p=244387
- https://staging.bolnews.com/?p=244415
- https://staging.bolnews.com/?p=244554
- https://staging.bolnews.com/?p=244568
- https://staging.bolnews.com/?p=244576
- https://staging.bolnews.com/?p=244610
- https://staging.bolnews.com/?p=244656
- https://staging.bolnews.com/?p=244872
- https://staging.bolnews.com/?p=245114
- https://staging.bolnews.com/?p=245150
- https://staging.bolnews.com/?p=245287
- https://staging.bolnews.com/?p=245295
- https://staging.bolnews.com/?p=245310
- https://staging.bolnews.com/?p=245351
- https://staging.bolnews.com/?p=245373
- https://staging.bolnews.com/?p=245561
- https://staging.bolnews.com/?p=245736
- https://staging.bolnews.com/?p=245767
- https://staging.bolnews.com/?p=245804
- https://staging.bolnews.com/?p=245833
- https://staging.bolnews.com/?p=246101
- https://staging.bolnews.com/?p=246108
- https://staging.bolnews.com/?p=246155
- https://staging.bolnews.com/?p=246161
- https://staging.bolnews.com/?p=246194
- https://staging.bolnews.com/?p=246277
- https://staging.bolnews.com/?p=246298
- https://staging.bolnews.com/?p=246380
- https://staging.bolnews.com/?p=246535
- https://staging.bolnews.com/?p=246556
- https://staging.bolnews.com/?p=246597
- https://staging.bolnews.com/?p=246641
- https://staging.bolnews.com/?p=246761
- https://staging.bolnews.com/?p=246819
- https://staging.bolnews.com/?p=246881
- https://staging.bolnews.com/?p=246943
- https://staging.bolnews.com/?p=246979
- https://staging.bolnews.com/?p=246997
- https://staging.bolnews.com/?p=247118
- https://staging.bolnews.com/?p=247257
- https://staging.bolnews.com/?p=247301
- https://staging.bolnews.com/?p=247407
- https://staging.bolnews.com/?p=247411
- https://staging.bolnews.com/?p=247417
- https://staging.bolnews.com/?p=247420
- https://staging.bolnews.com/?p=247446
- https://staging.bolnews.com/?p=247487
- https://staging.bolnews.com/?p=247489
- https://staging.bolnews.com/?p=247493
- https://staging.bolnews.com/?p=247495
- https://staging.bolnews.com/?p=247561
- https://staging.bolnews.com/?p=247562
- https://staging.bolnews.com/?p=247566
- https://staging.bolnews.com/?p=247710
- https://staging.bolnews.com/?p=247717
- https://staging.bolnews.com/?p=247718
- https://staging.bolnews.com/?p=247719
- https://staging.bolnews.com/?p=247763
- https://staging.bolnews.com/?p=247802
- https://staging.bolnews.com/?p=247825
- https://staging.bolnews.com/?p=247859
- https://staging.bolnews.com/?p=247873
- https://staging.bolnews.com/?p=247883
- https://staging.bolnews.com/?p=247924
- https://staging.bolnews.com/?p=247925
- https://staging.bolnews.com/?p=247931
- https://staging.bolnews.com/?p=247945
- https://staging.bolnews.com/?p=247946
- https://staging.bolnews.com/?p=247949
- https://staging.bolnews.com/?p=247951
- https://staging.bolnews.com/?p=247952
- https://staging.bolnews.com/?p=247959
- https://staging.bolnews.com/?p=247964
- https://staging.bolnews.com/?p=247969
- https://staging.bolnews.com/?p=247976
- https://staging.bolnews.com/?p=247982
- https://staging.bolnews.com/?p=247983
- https://staging.bolnews.com/?p=247984
- https://staging.bolnews.com/?p=247988
- https://staging.bolnews.com/?p=248003
- https://staging.bolnews.com/?p=248013
- https://staging.bolnews.com/?p=248014
- https://staging.bolnews.com/?p=248040
- https://staging.bolnews.com/?p=248045
- https://staging.bolnews.com/?p=248058
- https://staging.bolnews.com/?p=248079
- https://staging.bolnews.com/?p=248083
- https://staging.bolnews.com/?p=248087
- https://staging.bolnews.com/?p=248145
- https://staging.bolnews.com/?p=248196
- https://staging.bolnews.com/?p=248197
- https://staging.bolnews.com/?p=248198
- https://staging.bolnews.com/?p=248199
- https://staging.bolnews.com/?p=248204
- https://staging.bolnews.com/?p=248710
- https://staging.bolnews.com/?p=249053
- https://staging.bolnews.com/?p=249065
- https://staging.bolnews.com/?p=249070
- https://staging.bolnews.com/?p=249195
- https://staging.bolnews.com/?p=249197
- https://staging.bolnews.com/?p=249201
- https://staging.bolnews.com/?p=249945
- https://staging.bolnews.com/?p=249947
- https://staging.bolnews.com/?p=249949
- https://staging.bolnews.com/?p=249951
- https://staging.bolnews.com/?p=249960
- https://staging.bolnews.com/?p=249964
- https://staging.bolnews.com/?p=249968
- https://staging.bolnews.com/?p=249971
- https://staging.bolnews.com/?p=249975
- https://staging.bolnews.com/?p=249978
- https://staging.bolnews.com/?p=250101
- https://staging.bolnews.com/?p=250108
- https://staging.bolnews.com/?p=250113
- https://staging.bolnews.com/?p=250116
- https://staging.bolnews.com/?p=250122
- https://staging.bolnews.com/?p=250174
- https://staging.bolnews.com/?p=250497
- https://staging.bolnews.com/?p=250525
- https://staging.bolnews.com/?p=250539
- https://staging.bolnews.com/?p=250542
- https://staging.bolnews.com/?p=250547
- waybackurls_discovery: 385 additional URL(s) not stored individually
  ```
  total=685 stored=300 excluded=385
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
