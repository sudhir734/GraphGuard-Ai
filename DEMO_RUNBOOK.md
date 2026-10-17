# GraphGuard AI — Hackathon Demonstration Runbook

**Hackathon:** FalkorDB Graph Hacks 2026  
**Track:** Track 1 — *Agents That Act on Connected Data*  
**Team:** SynapGraph  
**Project:** GraphGuard AI v1.2.0  
**Demo Duration:** 5–7 Minutes  

---

## 1. System Architecture & Port Map

Before launching the demo, ensure the local services are running on their assigned ports:

| Service | Address | Role | Health Check |
| :--- | :--- | :--- | :--- |
| **FalkorDB Database** | `127.0.0.1:6379` | Central Knowledge Graph | `redis-cli ping` -> `PONG` |
| **FalkorDB Browser** | `http://127.0.0.1:3000` | Visual Database Explorer | Web UI reachable |
| **GraphGuard FastAPI** | `http://127.0.0.1:8000` | Core Investigation & Discovery API | `GET /health/ready` -> `200 OK` |
| **FastAPI Interactive Docs**| `http://127.0.0.1:8000/docs` | Swagger UI & OpenAPI Specification | Web UI reachable |
| **Streamlit UI** | `http://127.0.0.1:8501` | Analyst Investigation Canvas | Web UI reachable |

---

## 2. Fast Startup Commands

Open three terminal windows in `C:\Users\gunna\Desktop\graphguard-ai`:

### Terminal 1: FalkorDB (Docker)
```powershell
docker compose up -d
```
*(If already running, verify with `docker ps`)*

### Terminal 2: FastAPI Backend
```powershell
.\.venv\Scripts\uvicorn api:app --host 127.0.0.1 --port 8000 --reload
```

### Terminal 3: Streamlit Frontend
```powershell
.\.venv\Scripts\streamlit run app.py --server.port 8501 --server.address 127.0.0.1
```

---

## 3. Step-by-Step Demonstration Script for Judges

### Scenario 1: High-Speed Stored Graph Investigation (~4 ms)
1. Navigate to the Streamlit UI at `http://127.0.0.1:8501`.
2. Expand **01 / Global discovery & metrics** to showcase the live production graph baseline (**10,235 domains**, **10,533 relationships**).
3. In **02 / Target investigation**, enter an indexed domain (or a test domain without checking live enrichment).
4. Leave **"Run Live Passive Enrichment" UNCHECKED**.
5. Click **◈ INVESTIGATE DOMAIN**.
6. **Key Highlights to Show Judges:**
   - **Response Time:** Sub-5 ms instant traversal.
   - **Provenance Badge:** Notice the blue alert box:
     `⚡ DATA ORIGIN: FALKORDB STORED GRAPH — Fast local graph index traversal. No live network requests were made.`
   - **Explainability:** Explain that GraphGuard immediately flags `NOT_FOUND` domains without falsely claiming they are safe.

---

### Scenario 2: On-Demand Live Passive Enrichment & Graph Sync (~3 s)
1. In the domain input, enter a fresh, unindexed domain (e.g., `wikipedia.org` or `falkordb.com`).
2. **CHECK THE BOX:** `◈ Run Live Passive Enrichment (query DNS, RDAP & CT if unindexed or re-enriching)`.
3. Set **Maximum graph depth** to `2` and click **◈ INVESTIGATE DOMAIN**.
4. **Key Highlights to Show Judges:**
   - **Real Network Execution:** Spinner displays during live queries to Cloudflare DoH and ICANN RDAP (~2–4 seconds).
   - **Provenance Badge:** Notice the green alert box:
     `🟢 DATA ORIGIN: LIVE PASSIVE FETCH — Live network collection (DNS DoH, RDAP, CT) executed and synchronized with FalkorDB.`
   - **Graph Synchronization:** Inspect the returned entity cards:
     - IP Address nodes (A/AAAA records)
     - Domain Registration details and event timeline
     - Nameserver delegation nodes
   - **Interactive vis-network Canvas:** Click and drag nodes on the interactive canvas to inspect relationship arrows and metadata.

---

### Scenario 3: Adversary Infrastructure Pivot (FalkorDB Multi-Hop Centrality)
1. Open the **FalkorDB Browser** at `http://127.0.0.1:3000` or inspect the Streamlit Relationship Graph.
2. Demonstrate how GraphGuard traces co-occurring infrastructure:
   ```cypher
   MATCH (d1:Domain)-[:HAS_OBSERVATION]->(o1:Observation)-[:DESCRIBES_CERTIFICATE]->(c:Certificate)
   MATCH (c)<-[:DESCRIBES_CERTIFICATE]-(o2:Observation)<-[:HAS_OBSERVATION]-(d2:Domain)
   WHERE d1 <> d2
   RETURN d1.name, c.fingerprint, d2.name LIMIT 10
   ```
3. **Key Highlight to Show Judges:**
   - Explain why this makes FalkorDB irreplaceable: in SQL, multi-hop recursive queries with arbitrary depth lead to join explosions. In FalkorDB, linear algebra matrix operations identify shared adversary campaigns in milliseconds.

---

### Scenario 4: Strict Security & Input Validation
1. In Streamlit or Swagger docs (`http://127.0.0.1:8000/docs`), attempt to submit invalid target strings:
   - IP address: `192.168.1.1`
   - URL: `https://malicious.test/payload.exe`
   - Bare public suffix: `co.uk`
2. **Key Highlight to Show Judges:**
   - The system immediately returns a structured `422 Unprocessable Entity` with a clear explanation:
     *"URLs and IP addresses are rejected. Enter a valid domain name."*
   - Highlights strict input validation, preventing SSRF and injection attacks.

---

### Scenario 5: Automated Test Verification
1. Run the verified automated test suite in PowerShell:
   ```powershell
   .\.venv\Scripts\python.exe -m pytest -q
   ```
2. **Key Highlight to Show Judges:**
   - Displays **`77 passed, 15 subtests passed in ~31s`** (100% pass rate).
   - Demonstrates enterprise-grade test automation covering regression safety, credential redaction, TLS context validation, and lease concurrency.
