# GraphGuard AI — Application & Operational Security Review

**Project:** GraphGuard AI v1.2.0  
**Audit Date:** October 17, 2026  
**Auditor:** Application Security Lead & Release Manager  
**Assessment Result:** PASSED — ZERO HIGH/CRITICAL VULNERABILITIES IDENTIFIED  

---

## 1. Security Architecture & Threat Model

GraphGuard AI is designed as a **passive, evidence-first threat investigation system**. The primary threat vectors assessed during this audit include:
1. Transport Layer Security (TLS/SSL) interception or misconfiguration.
2. Inadvertent active scanning (port probing, banner grabbing, exploit testing).
3. Secret leakage across source code, logs, database nodes, or UI visualizations.
4. Input injection (Cypher injection, SSRF via unvalidated domain inputs).
5. Denial of Service (DoS) via unbounded graph queries or runaway recursive crawls.

---

## 2. Detailed Security Assessment & Controls

### 2.1 Transport Layer Security (TLS/SSL) Policy
- **Requirement:** Outgoing HTTPS connections to intelligence providers must strictly validate certificates and hostnames.
- **Audit Finding:**
  - Standard Python installations on Windows fail to locate system CA certificates when using default `urllib` calls.
  - Rather than implementing insecure workarounds (such as `ssl._create_unverified_context()` or `verify=False`), GraphGuard AI binds `certifi` CA bundles directly:
    ```python
    import certifi, ssl
    SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
    ```
  - `SSL_CONTEXT.check_hostname` is verified as `True`.
  - Both GET and POST requests in `real_intel.py` pass `context=SSL_CONTEXT`.
  - **Verdict:** SECURE. Zero TLS verification bypasses exist in the codebase.

### 2.2 Passive Collection Boundary
- **Requirement:** Maintain strict passive-only reconnaissance. Active probing against target infrastructure is strictly prohibited.
- **Controls Implemented & Audited:**
  - **DNS over HTTPS:** Queries are directed exclusively to Cloudflare's public resolver (`1.1.1.1` / `cloudflare-dns.com`), never directly to target authoritative nameservers.
  - **Registration Data:** Queries are sent to public RDAP bootstrap endpoints (`rdap.org`), never probing target infrastructure.
  - **Certificate Transparency:** Queries are sent to `crt.sh`, reading publicly published append-only transparency logs.
  - **Threat Intelligence:** Queries are sent to URLhaus and AlienVault OTX APIs.
  - **Active Scanning Elimination:** The codebase contains **zero socket connections**, zero port scans, zero HTTP GET/POST requests directed to the target domain's IP addresses or web servers.
  - **Verdict:** VERIFIED PASSIVE. Operates strictly within legal and ethical open-source intelligence boundaries.

### 2.3 Secret Management & Redaction Engine
- **Requirement:** Prevent credential leakage across logs, FalkorDB graph nodes, and web UI.
- **Controls Implemented & Audited:**
  - **Environment Variables:** API keys (`URLHAUS_API_KEY`, `OTX_API_KEY`) are fetched dynamically from the operating system environment.
  - **No Hardcoded Keys:** Repository source code, git history, test files, and mock fixtures contain zero production secrets.
  - **Header Injection:** Keys are passed via headers (`Auth-Key`) without appearing in request query strings or URLs.
  - **Graph Property Sanitizer:** Before any node properties are returned to the API or rendered in Streamlit, `graph_queries._safe_properties()` recursively scrubs sensitive keys:
    ```python
    SENSITIVE_PATTERNS = {
        "api_key", "token", "secret", "password", "privatekey", 
        "cookie", "cookies", "bearer_token", "auth_code"
    }
    ```
    Matching keys are replaced with `"[REDACTED]"`.
  - **Verdict:** SECURE. Redaction engine tested and verified via `test_redacts_top_level_sensitive_nested_values` and `test_redaction_includes_cookie_bearer_auth_privatekey`.

### 2.4 Input Validation & Cypher Injection Prevention
- **Requirement:** Prevent injection attacks and unauthorized network pivots.
- **Controls Implemented & Audited:**
  - **Pydantic Validation:** All API inputs are strictly validated via Pydantic models with `extra="forbid"`.
  - **Domain Normalization (`normalize_domain`):**
    - Enforces RFC 1034 / 1035 DNS label rules (max 63 characters per label, max 253 characters total).
    - Converts Unicode to IDNA Punycode (`xn--...`).
    - Explicitly rejects URLs (`https://...`), paths (`/test`), IP addresses (`192.168.1.1`), and bare public suffixes (`co.uk`, `com`, `org`).
  - **Parameterized Cypher:** All queries to FalkorDB use Cypher parameters (`$domain`, `$max_depth`, `$timestamp`):
    ```cypher
    MATCH (d:Domain {name: $domain}) ...
    ```
    String concatenation is completely prohibited in query construction, preventing Cypher injection.
  - **Bounded Resource Limits:** `max_depth` is bounded to `[1, 3]`; `max_entities` is bounded to `[1, 200]`. Queries cannot execute runaway unbounded traversals.
  - **Service Binding:** FastAPI and Streamlit are configured to bind exclusively to `127.0.0.1`, preventing inadvertent external network exposure.
  - **Verdict:** SECURE. Input validation tested and verified via `ApiValidationTests` and `DomainNormalizationTests`.
