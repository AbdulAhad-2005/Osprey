# TLS/SSL configuration testing (WSTG-CRYP)

`sslyze_scan` (target= host or host:port) probes the real TLS handshake surface — the crypto
layer `tlsx_inspect` can't reach (tlsx only reads SANs/issuer). Run it on every HTTPS host that
matters; it's passive (no exploitation) and fast.

## What it finds → severity

- **Weak protocols enabled** — SSLv2/SSLv3 (HIGH, broken), TLS 1.0/1.1 (MEDIUM, deprecated /
  PCI-DSS fail). Modern servers should accept only TLS 1.2+.
- **Weak cipher suites** — NULL/EXPORT/anon (HIGH), RC4/DES/3DES/RC2 (MEDIUM), MD5 MAC (LOW).
- **TLS CVEs** — Heartbleed (CRITICAL, key/memory disclosure), CCS injection (HIGH), ROBOT RSA
  padding oracle (HIGH).
- **Certificate deployment** — hostname mismatch (MEDIUM), untrusted/self-signed/expired chain
  (LOW). These are OBSERVED from the served cert.

## When to run

- On any live HTTPS host, especially crown jewels and anything handling auth/payment/PII.
- After `tlsx_inspect` flags a host — tlsx tells you a cert exists; sslyze tells you if the
  config is weak.
- It is one of the few *always-safe* vuln-phase actions — no payloads, just handshake probing.

## Reading results

- Weak protocol/cipher findings are OBSERVED (the server negotiated them) — the severity is
  real and reportable as a compliance/crypto finding, but note the *exploitability* context
  (e.g. TLS 1.0 is a finding, but exploiting it needs a MITM position).
- A cert **hostname mismatch** on a CDN/multi-tenant edge can be expected (SNI) — confirm you
  hit the right vhost before rating it.
- Heartbleed/ROBOT/CCS positives are high-value — corroborate with a second check before
  claiming CRITICAL, but these are strong signals.

## Do not

- Rate TLS 1.0 as CRITICAL — it's a MEDIUM config weakness, not RCE.
- Skip it on "it's behind Cloudflare" — test the origin too if you've attributed it.
- Treat a self-signed cert on an internal-looking host as CRITICAL by itself — it's a LOW/
  MEDIUM trust issue; the value is what it fronts.
