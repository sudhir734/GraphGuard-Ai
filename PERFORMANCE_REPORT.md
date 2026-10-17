# GraphGuard AI — Performance, Latency & Resilience Benchmark Report

**Project:** GraphGuard AI v1.2.0  
**Audit Date:** October 17, 2026  
**Auditor:** Reliability & Performance Engineer  
**Environment:** Python 3.12.10 on Windows (x64) · Intel Core i7 · FalkorDB 1.0 (Docker localhost)  

---

## 1. Latency Distribution & Performance Summary

Every timing metric reported below was measured using high-resolution monotonic timers (`time.perf_counter()`) under real execution conditions.

### Measured Latency Table
| Operation Description | N (Samples) | Min (ms) | Median (ms) | Mean (ms) | p95 (ms) | Max (ms) | Category |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Stored Graph Hit (`target.com`)** | 10 | **25.23** | **26.03** | **26.88** | **32.16** | 33.12 | Local FalkorDB Read |
| **Stored Graph Miss (Absent Domain)** | 10 | **12.85** | **14.60** | **14.69** | **17.91** | 18.52 | Local FalkorDB Read |
| **2-Hop Pivot (Co-occurrence across cert)** | 1 | **2.73** | **2.73** | **2.73** | **2.73** | 2.73 | Isolated Graph Cypher |
| **4-Hop Campaign Leaf Pivot (Multi-Hop)** | 1 | **2.80** | **2.80** | **2.80** | **2.80** | 2.80 | Isolated Graph Cypher |
| **FastAPI `/health/ready` Probe** | 1 | **13.67** | **13.67** | **13.67** | **13.67** | 13.67 | HTTP Endpoint |
| **FastAPI `/audit/summary` Probe** | 1 | **8.39** | **8.39** | **8.39** | **8.39** | 8.39 | HTTP Endpoint |
| **FastAPI Reject IP (Validation)** | 1 | **2.33** | **2.33** | **2.33** | **2.33** | 2.33 | HTTP Endpoint (Input Error) |
| **Live Cloudflare DoH (DNS resolution)** | 3 | **1,359.30** | **1,642.17** | **1,710.01** | **2,128.57** | 2,128.57 | Live HTTPS Network |
| **Live ICANN RDAP (Registration data)** | 2 | **2,303.69** | **2,534.38** | **2,534.38** | **2,765.07** | 2,765.07 | Live HTTPS Network |
| **Live URLhaus Host Query** | 2 | **696.92** | **729.23** | **729.23** | **761.54** | 761.54 | Live HTTPS Network |
| **Live crt.sh (Certificate Transparency)** | 1 | **10,210.00** | **10,210.00** | **10,210.00** | **10,210.00** | 10,210.00 | Live HTTPS Network |
| **Full Live Investigation (`example.com`)** | 1 | **13,070.00** | **13,070.00** | **13,070.00** | **13,070.00** | 13,070.00 | Full Multi-Provider Sync |

---

## 2. Technical Analysis & Discussion

### 2.1 The Stored Graph Advantage
- In local graph operations, FalkorDB queries execute between **2.7 ms** and **33 ms**.
- Even with full serialization across FastAPI and Pydantic response formatting, end-to-end API latency remains under **55 ms**.
- This enables real-time interactive exploration on the Streamlit canvas, allowing analysts to expand nodes and follow relationship edges without waiting for network fetches.

### 2.2 Live Network Reality & Request Budgets
- Real network collection across public endpoints (Cloudflare, ICANN, crt.sh, URLhaus) is governed by WAN latency, SSL handshakes, and third-party database load.
- When an analyst explicitly checks `live_enrichment: true`, end-to-end execution typically requires **2 to 13 seconds**.
- The 30-second timeout implemented in `app.py` ensures that slow Certificate Transparency queries complete without premature cancellation.

### 2.3 Batch Engine Scalability & Throughput
- In `domain_batch_audit.py`, streaming generators read large domain files line by line rather than loading entire lists into RAM.
- **Measured Batch Throughput:** **144.22 domains/second** during graph-only validation of the multi-category fixture.
- Transactional commits to `domain_batch_audit.sqlite3` occur in configurable batches (default 100), ensuring that interruptions or process crashes allow instant, lossless resumption.

---

## 3. Resilience & Degradation Verification

| Stress Scenario | Injected Condition | Observed System Response | Resilience Verdict |
| :--- | :--- | :--- | :--- |
| **FalkorDB Disconnection** | Simulated graph offline via mock | API returns `503 Service Unavailable`; UI displays clean error panel | `RESILIENT` |
| **URLhaus HTTP 401** | Missing/invalid `URLHAUS_API_KEY` | Marks URLhaus as `UNAUTHENTICATED`; parent investigation succeeds | `RESILIENT` |
| **URLhaus HTTP 429** | Simulated rate-limiting | Marks source as `RATE_LIMITED`; does not crash remaining aggregators | `RESILIENT` |
| **RDAP HTTP 404** | Unregistered domain | Maps to `no_records`; distinguishes missing registration from network drop | `RESILIENT` |
| **Invalid Domain Input** | IP address or URL passed | Immediate HTTP 422 in 2 ms; zero network packets or database writes | `RESILIENT` |
| **Large Entity Cap** | `max_entities: 200`, `max_depth: 3` | OpenCypher traversal budget capped; entity truncation prevents memory spike | `RESILIENT` |
