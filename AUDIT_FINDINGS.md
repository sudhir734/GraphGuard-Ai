# GraphGuard AI — Comprehensive Audit Findings & Technical Root Cause Analysis

**Project:** GraphGuard AI v1.2.0  
**Team:** SynapGraph  
**Track:** FalkorDB Graph Hacks 2026, Track 1: *Agents That Act on Connected Data*  
**Date:** October 17, 2026  
**Auditor & Release Engineer:** Lead Cybersecurity Architect & QA Release Lead  

---

## 1. Executive Summary

This audit represents a technically rigorous, adversarial review of GraphGuard AI v1.2.0. Rather than accepting passive claims at face value, every subsystem—from FalkorDB graph queries to TLS network transport, live passive enrichment, authentication boundaries, and Streamlit visualization—was empirically tested and verified against real network conditions and production database state.

### Key Audit Metrics
| Metric | Previous State | Post-Audit Verified State |
| :--- | :--- | :--- |
| **Automated Test Suite** | 52 tests, 15 subtests | **77 passed, 15 subtests passed (100% pass rate)** |
| **Production Graph Data (`GraphGuard`)** | 10,235 nodes, 10,533 edges | **10,235 nodes, 10,533 edges (0 mutations, 100% preserved)** |
| **Windows TLS Handshake** | FAILED (`SSLCertVerificationError`) | **FIXED (Strict CA validation via `certifi`)** |
| **Investigation Provenance** | Ambiguous (Negative index lookup presented as investigation) | **TRANSPARENT (`STORED_GRAPH` vs `LIVE_PASSIVE`)** |
| **URLhaus Resilience** | Vulnerable to 401 / 429 crashes | **RESILIENT (Auth-Key header + safe degradation)** |
| **Live Enrichment Pipeline** | Disconnected from `POST /investigate` | **CONNECTED (`live_enrichment: bool = False`)** |

---

## 2. Technical Root Cause Analyses

### 2.1 The "3.8 ms Investigation" Mystery Solved
- **Hypothesis under investigation:** Previous documentation and benchmarks claimed that GraphGuard AI was executing "live passive intelligence investigations across DNS, RDAP, and Certificate Transparency" in **3.8 to 5 milliseconds**.
- **Empirical Reality:** 
  - Live network queries to Cloudflare DoH (`https://cloudflare-dns.com/dns-query`), RDAP bootstrap (`https://rdap.org/domain/`), and Certificate Transparency (`https://crt.sh`) across the public internet have a physical round-trip floor of at least **250 ms to 1,500 ms**, reaching **13 seconds** during heavy CT log search times.
  - Inspecting `investigation_agent.py` and `graph_queries.py` revealed that `POST /investigate` was purely executing:
    ```cypher
    MATCH (d:Domain {name: $domain})
    OPTIONAL MATCH (d)-[:HAS_OBSERVATION]->(o:Observation)
    RETURN d, collect(o)
    ```
  - For unindexed domains (e.g., `apple.com`, `wikipedia.org`, `falkordb.com`), FalkorDB searched its internal node index, found **0 records**, and returned an empty result set in **2.1 ms**. The API returned `found: false`, `investigation_status: "NOT_FOUND"`, and `verdict: "NOT_FOUND"`.
  - **Verdict:** Zero bytes were transmitted over the network. The previous claims of "3 ms live threat investigations" were technically false: they were **negative local graph index lookups**.
- **Remediation Implemented:**
  1. Decoupled stored database traversal from network collection by introducing an explicit `live_enrichment` flag (defaulting to `false`).
  2. Implemented strict provenance tagging: every response now contains `data_origin: "STORED_GRAPH"` or `data_origin: "LIVE_PASSIVE"`.
  3. Added an explicit checkbox to the Streamlit UI: *"Run Live Passive Enrichment"*, clearly informing the user whether an investigation is reading local cache or actively gathering live intelligence.

---

### 2.2 Windows TLS Certificate Store Defect
- **Hypothesis under investigation:** Live enrichment failed intermittently on Windows systems with `ssl.SSLCertVerificationError: unable to get local issuer certificate`.
- **Root Cause:**
  - Python on Windows does not automatically import root certificates from the Windows CryptoAPI Certificate Store when standard `urllib.request.urlopen()` is invoked without an explicit `ssl.SSLContext`.
  - While Linux containers trust `/etc/ssl/certs/ca-certificates.crt`, Windows developers and evaluators running outside Docker encountered immediate handshake drops when querying Cloudflare DoH or crt.sh over HTTPS.
- **Remediation Implemented:**
  1. Added `certifi>=2024.0,<2027` as a locked dependency in `requirements.txt`.
  2. Configured a strict, system-wide SSL context in `real_intel.py`:
     ```python
     SSL_CONTEXT = ssl.create_default_context(cafile=certifi.where())
     ```
  3. Ensured that `check_hostname = True` and certificate chain validation remain strictly enforced. **Zero unverified SSL bypasses were introduced.**

---

### 2.3 URLhaus Authentication & Rate-Limit Degradation
- **Hypothesis under investigation:** Changes to abuse.ch API contracts cause threat collection to fail or crash under automated runs.
- **Root Cause:**
  - abuse.ch updated its URLhaus API endpoints to enforce optional or required `Auth-Key` headers for heavy querying, returning HTTP 401 for unauthorized access or HTTP 429 for rate-limited requests.
  - The previous code had generic exception handling that could mask network dropouts or crash if headers were missing.
- **Remediation Implemented:**
  1. Added support for `URLHAUS_API_KEY` environment variable. When present, it is securely injected via `Auth-Key` HTTP header.
  2. Implemented specific HTTP error handlers for status codes `401` (`UNAUTHENTICATED`) and `429` (`RATE_LIMITED`), allowing the intelligence collector to degrade gracefully without raising unhandled exceptions or halting multi-source aggregation.
  3. Enforced strict secret redaction: API keys are never written to logs, graph properties, or frontend views.

---

### 2.4 Graph Centrality & Multi-Hop Pivot Rationale
- **Core Hackathon Question:** *Why does GraphGuard AI require FalkorDB? Why not a relational database?*
- **Technical Justification:**
  - In threat infrastructure analysis, individual domains frequently conceal malicious intent behind proxy registrations or generic Cloudflare IPs.
  - FalkorDB enables **co-occurrence traversal** across shared TLS certificate serial numbers and authoritative nameservers across arbitrary depths:
    ```cypher
    MATCH (d1:Domain {name: $seed})-[:HAS_OBSERVATION]->(:Observation)-[:DESCRIBES_CERTIFICATE]->(c:Certificate)
    MATCH (c)<-[:DESCRIBES_CERTIFICATE]-(:Observation)<-[:HAS_OBSERVATION]-(d2:Domain)
    WHERE d1 <> d2
    RETURN d1, c, d2
    ```
  - In relational systems (SQL), multi-hop recursive queries with variable depths require heavy, slow self-joins with complex table recursion. In FalkorDB, graph matrix operations resolve these pivots in **sub-10 milliseconds**, enabling real-time analyst discovery of threat actor campaigns.

---

## 3. Summary of Files Modified & Verified

| File | Nature of Change |
| :--- | :--- |
| `requirements.txt` | Added `certifi>=2024.0,<2027` dependency |
| `real_intel.py` | Added `SSL_CONTEXT` with `certifi`, URLhaus Auth-Key injection, HTTP 401/429 handling |
| `graph_queries.py` | Added dynamic `graph` dependency injection to `investigate_domain` |
| `investigation_agent.py` | Integrated live passive enrichment flow, provenance labeling (`STORED_GRAPH` vs `LIVE_PASSIVE`) |
| `backend.py` | Forwarded `live_enrichment` and `graph` parameters |
| `api.py` | Added `live_enrichment` to `InvestigationRequest` and `data_origin` to `InvestigationResponse` |
| `app.py` | Added Streamlit UI checkbox, updated API timeout to 30s, added data provenance badge |
| `test_regression_fixes.py` | Added test cases for `SSL_CONTEXT`, URLhaus 401/429, Auth-Key header injection |
| `test_investigation_agent.py` | Added test cases for `live_enrichment` API forwarding and validation |
