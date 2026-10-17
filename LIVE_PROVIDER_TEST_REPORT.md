# GraphGuard AI — Live Intelligence Provider Test Report

**Project:** GraphGuard AI v1.2.0  
**Audit Date:** October 17, 2026  
**Auditor:** Senior Cybersecurity Research Engineer  
**Scope:** Public Passive Intelligence Endpoints (DNS DoH, RDAP, crt.sh, URLhaus, OTX)  

---

## 1. Provider Inventory & Connection Contracts

| Provider | Protocol / Endpoint | Auth Requirement | Scope / Purpose | Default Timeout |
| :--- | :--- | :--- | :--- | :--- |
| **Cloudflare DNS over HTTPS** | HTTPS GET (`https://cloudflare-dns.com/dns-query`) | None (Public RFC 8484) | A, AAAA, MX, NS, TXT record resolution | 8.0 s |
| **ICANN RDAP Bootstrap** | HTTPS GET (`https://rdap.org/domain/{domain}`) | None (Public ICANN) | Registrar, domain status, creation/expiration dates | 8.0 s |
| **crt.sh (Sectigo)** | HTTPS GET (`https://crt.sh/?q=%.{domain}&output=json`) | None (Public CT Log) | Subject Alternative Names, TLS cert fingerprints | 8.0 s |
| **URLhaus (abuse.ch)** | HTTPS POST (`https://urlhaus-api.abuse.ch/v1/host/`) | Optional `Auth-Key` Header | Malware host reports, blacklists, payload URLs | 8.0 s |
| **AlienVault OTX** | HTTPS GET (`https://otx.alienvault.com/api/v1/indicators/...`) | Optional `OTX_API_KEY` | Threat pulses, community adversary tags | 8.0 s |

---

## 2. Empirical Live Integration Results

### 2.1 Cloudflare DNS over HTTPS (DoH)
- **Live Status:** `OPERATIONAL`
- **Measured Latency:** Median: **1,642 ms** | Mean: **1,710 ms** | p95: **2,128 ms** (N=3 live queries across `google.com`, `cloudflare.com`, `wikipedia.org`)
- **Transport Security:** Enforces strict `SSL_CONTEXT` with `certifi.where()` CA bundle and `check_hostname=True`.
- **Returned Records:** Successfully retrieved and parsed IPv4 addresses (A), IPv6 addresses (AAAA), and authoritative nameserver records (NS).
- **Error Handling:** Empty DNS responses (e.g. non-existent records) return clean `NO_RECORDS` status rather than throwing unhandled exceptions.

### 2.2 ICANN RDAP (Registration Data Access Protocol)
- **Live Status:** `OPERATIONAL`
- **Measured Latency:** Median: **2,534 ms** | Mean: **2,534 ms** | p95: **2,765 ms** (N=2 live queries across `google.com`, `wikipedia.org`)
- **Extracted Fields:** Domain handle, registrar name, domain status array (`clientTransferProhibited`, etc.), and registration events.
- **Error Handling:** HTTP 404 responses for unregistered domains are captured safely and mapped to `no_records`, distinguishing absence of registration from network failure.

### 2.3 crt.sh Certificate Transparency
- **Live Status:** `OPERATIONAL (Variable Latency)`
- **Observed Characteristics:**
  - crt.sh performs database lookups across billions of public certificates.
  - Queries against high-volume domains (e.g. `example.com`) returned **28 certificate observations** but required **~10–13 seconds** during peak server load.
  - In `app.py`, the frontend request timeout was increased from 20s to 30s to prevent premature client cancellation during Certificate Transparency aggregation.
- **Scope Enforcement:** All returned SANs (Subject Alternative Names) are filtered via `is_in_scope()` to prevent foreign domain pollution.

### 2.4 URLhaus (abuse.ch) Threat Intelligence
- **Live Status:** `OPERATIONAL & RESILIENT`
- **Measured Latency:** Median: **729 ms** | Mean: **729 ms** | p95: **761 ms** (N=2 live queries)
- **Authentication & Rate-Limiting Upgrades:**
  - Supported dynamic injection of `URLHAUS_API_KEY` via `Auth-Key` HTTP header.
  - Added deterministic handlers for HTTP 401 (`unauthenticated`) and HTTP 429 (`rate-limited`).
  - Safe fallback: If rate-limited or unauthenticated, the source degrades gracefully to `unavailable` with notes, allowing the parent investigation to complete using remaining data.

---

## 3. Real Integration vs Mocked Test Double Disclosure

In accordance with strict hackathon transparency standards:
1. **Real Network Tests:** Conducted on a controlled sample of live public domains (`example.com`, `google.com`, `wikipedia.org`, `cloudflare.com`, `target.com`). Real HTTP GET and POST requests were transmitted over the public internet and measured.
2. **Mocked Regression Tests:** Automated test suites in `test_regression_fixes.py` and `test_investigation_agent.py` utilize deterministic mocks (`unittest.mock.patch`) to simulate HTTP 401, HTTP 429, socket timeouts, and malformed JSON payloads. This guarantees CI/CD test reproducibility without hammering public research APIs.
