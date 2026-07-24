# Finding Confidence

- **High / confirmed:** Parser extracted structured finding with clear evidence in stdout
- **Medium / likely:** Strong signal (e.g. takeover fingerprint body match) — still confirm impact
- **Low / hypothesis:** Inferred from partial, passive, or ambiguous output — verify before acting

## Evidence honesty (recon/network)

- Shodan ports/CVE tags = passive leads → verify live before HIGH/CRITICAL
- Takeover `vulnerable` fingerprint = observed signal → confirm claimability before severity inflation
- Takeover `potential` / empty 404 on SaaS CNAME = hypothesis until proven
- SPA HTTP 200 on arbitrary paths ≠ open API or confirmed vuln
- Port floods ≠ verified services — version/banner before strong claims

Do not treat low-confidence items as confirmed vulnerabilities.
