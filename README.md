# GraphGuard AI

**GraphGuard AI** is an explainable, evidence-backed, passive cybersecurity investigation system built for the **FalkorDB Graph Hacks 2026 Hackathon (Track 1: Agents That Act on Connected Data)** by **Team SynapGraph**.

Repository: [https://github.com/sudhir734/GraphGuard-Ai](https://github.com/sudhir734/GraphGuard-Ai)

## Problem Statement & Intended Users

Modern attack campaigns rarely operate from a single, static IP address or isolated domain name. Adversaries construct interconnected infrastructure fabrics: rotating nameservers, re-registering subdomains under compromised apex domains, sharing wildcard TLS certificates, and distributing malware across disposable nodes.

Traditional tabular databases force incident responders and SOC analysts to run expensive multi-table joins and stitch together disjointed CSV files. **GraphGuard AI** connects observable cyber intelligence into a high-performance FalkorDB graph, allowing analysts to:
- Trace multi-hop infrastructure connections in milliseconds using OpenCypher.
- Inspect observation provenance, collection timestamps, and source attribution.
- Enforce strict uncertainty bounds: an unassessed domain remains `NOT_ASSESSED`, a missing domain is `NOT_FOUND`, and zero reputation findings are never equated with safety.

**Target Users:** Security Operations Center (SOC) analysts, Threat Intelligence researchers, Incident Responders, and Cyber Threat Hunters.

## Architecture and Data Flow

```mermaid
flowchart TD
    User([Analyst / User]) -->|HTTP :8501| Streamlit[Streamlit UI app.py]
    Streamlit -->|REST API :8000| FastAPI[FastAPI Backend api.py]
    FastAPI -->|Domain Validation & Query| InvAgent[Investigation Agent investigation_agent.py]
    FastAPI -->|Job Dispatch & Metrics| DiscEngine[Discovery Engine discovery_engine.py]

    DiscEngine -->|Passive Collection| Providers[Passive Intel Adapters real_intel.py]
    Providers -->|crt.sh CT / Cloudflare DoH / RDAP / URLhaus| OpenIntel[(Open Public Sources)]
    DiscEngine -->|Staged Candidate Queue| SQLite[(SQLite global_discovery.sqlite3)]
    DiscEngine -->|MERGE Graph Entities| FalkorDB[(FalkorDB GraphGuard :6379)]

    InvAgent -->|Bounded OpenCypher Reads| GraphQueries[Graph Query Layer graph_queries.py]
    GraphQueries -->|MATCH (Domain)-[r]-(Target)| FalkorDB

    GraphQueries -->|Nodes, Edges, Evidence| InvAgent
    InvAgent -->|Evidence Report + Status + Verdict| FastAPI
    FastAPI -->|Structured JSON| Streamlit
    Streamlit -->|Interactive Graph & Evidence Workspace| User
```

## Implemented Features vs Planned Features

| Feature Area | Implemented in v1.2.0 | Planned / Future Work |
| :--- | :--- | :--- |
| **Graph Traversal** | Low-latency multi-hop OpenCypher traversals (depth 1–3) in FalkorDB | Graph neural network (GNN) threat clustering |
| **Passive Discovery** | Bounded BFS discovery from seeds via crt.sh SANs, Cloudflare DoH CNAME/MX/NS, and RDAP | Active port/service scanning (intentionally excluded for safety) |
| **Threat Intelligence** | URLhaus (abuse.ch) open host query API integration + optional AlienVault OTX | Darknet forum and paste site scrapers |
| **Entity Resolution** | Public Suffix List (PSL) registered domain normalization and apex derivation | BGP ASN routing graph ingestion |
| **Security & Privacy** | Automatic property redaction (API keys, cookies, auth tokens), localhost binding | Multi-tenant RBAC and encrypted graph storage |
| **Assessment Policy** | Strict decoupling of collection status from threat verdicts; conservative uncertainty | Automated defensive takedown generation |

## Verification, Audit & Hackathon Reports

Detailed technical documentation and audit deliverables produced for the hackathon release:

- [AUDIT_FINDINGS.md](file:///C:/Users/gunna/Desktop/graphguard-ai/AUDIT_FINDINGS.md) — Technical root cause analysis of the 3.8 ms lookup vs live fetch, Windows TLS bug, and URLhaus resilience.
- [DOMAIN_TEST_MATRIX.md](file:///C:/Users/gunna/Desktop/graphguard-ai/DOMAIN_TEST_MATRIX.md) — Multi-domain test matrix across categories A through L and batch coverage engine results.
- [LIVE_PROVIDER_TEST_REPORT.md](file:///C:/Users/gunna/Desktop/graphguard-ai/LIVE_PROVIDER_TEST_REPORT.md) — Live provider contracts and empirical benchmarks across DoH, RDAP, crt.sh, and URLhaus.
- [LIVE_PIPELINE_VERIFICATION.md](file:///C:/Users/gunna/Desktop/graphguard-ai/LIVE_PIPELINE_VERIFICATION.md) — Empirical benchmarks across Cloudflare DoH, RDAP, crt.sh, and URLhaus.
- [GRAPH_INTEGRITY_REPORT.md](file:///C:/Users/gunna/Desktop/graphguard-ai/GRAPH_INTEGRITY_REPORT.md) — FalkorDB graph centrality proof, 10,235 node baseline integrity, and read-only verification.
- [SECURITY_REVIEW.md](file:///C:/Users/gunna/Desktop/graphguard-ai/SECURITY_REVIEW.md) — TLS/SSL certifi policy, passive collection boundary, and credential redaction engine.
- [PERFORMANCE_REPORT.md](file:///C:/Users/gunna/Desktop/graphguard-ai/PERFORMANCE_REPORT.md) — Monotonic latency measurements (min, median, mean, p95) across stored and live paths.
- [DEMO_RUNBOOK.md](file:///C:/Users/gunna/Desktop/graphguard-ai/DEMO_RUNBOOK.md) — Step-by-step 5-minute demonstration script for hackathon judges.
- [FINAL_READINESS_REPORT.md](file:///C:/Users/gunna/Desktop/graphguard-ai/FINAL_READINESS_REPORT.md) — Master adversarial audit sign-off and direct answers to all 18 evaluation questions.

## Requirements

- Python 3.10 or newer
- A running FalkorDB-compatible Redis service with the existing `GraphGuard`
  graph
- Network access from the API process to that database
- Optional internet access when running the separate passive enrichment worker

All graph-facing entry points read `FALKORDB_HOST`, `FALKORDB_PORT`, and
`FALKORDB_GRAPH` from the same configuration, defaulting to `127.0.0.1`,
`6379`, and `GraphGuard`. The Streamlit UI reads its administrator-controlled
`GRAPHGUARD_API_URL` environment setting, defaulting to
`http://127.0.0.1:8000`; the destination is not editable by UI users.

## Windows setup and startup

From the project directory, create an environment and install dependencies:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the API in one PowerShell terminal. Set the FalkorDB variables there if
the database is not at the defaults:

```powershell
$env:FALKORDB_HOST = "127.0.0.1"
$env:FALKORDB_PORT = "6379"
$env:FALKORDB_GRAPH = "GraphGuard"
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

Start the UI in a second terminal:

```powershell
.\.venv\Scripts\Activate.ps1
$env:GRAPHGUARD_API_URL = "http://127.0.0.1:8000"
python -m streamlit run app.py
```

The API serves interactive documentation at `http://127.0.0.1:8000/docs`.

## API Endpoints

- `GET /health`: Reports API availability separately from FalkorDB connectivity.
- `GET /health/ready`: Returns HTTP 503 if the application is running but the graph is unavailable.
- `GET /discovery/metrics`: Returns transparent metrics across FalkorDB and the discovery repository (total domains, investigated, awaiting, IPs, certificates, threat reports, unique sources).
- `POST /discovery/run`: Triggers incremental passive domain discovery from seeds with configurable depth, domain budget, and optional scope domain boundary. Supports background execution (`background: true`).
- `GET /discovery/status`: Returns the live progress, active domain, error counts, and completion status of the background discovery job.
- `POST /investigate`: Validates a domain name and returns an evidence-backed report derived from stored FalkorDB records.

Example investigation request body:

```json
{
  "domain": "<domain-to-investigate>",
  "max_depth": 2,
  "max_entities": 100
}
```

Example discovery request body:

```json
{
  "seeds": ["example.com"],
  "max_depth": 1,
  "max_domains": 50,
  "scope": "example.com",
  "enrich_discovered": true,
  "delay": 0.5,
  "background": true
}
```

`max_depth` is limited to 1–3 and `max_entities` to 1–200. Invalid names,
URLs, IP addresses, and public suffixes are rejected with HTTP 422. A graph
connection or query failure returns HTTP 503 without exposing internal
database details.

Reports include:
- `investigation_status`: Explicit classification (`INVESTIGATED`, `PARTIALLY_ASSESSED`, `NOT_ASSESSED`, `SOURCE_UNAVAILABLE`, `NO_EVIDENCE_FOUND`, or `NOT_FOUND`).
- `registered_domain`: PSL-validated apex registered domain.
- `associated_ips`, `associated_certificates`, `associated_reports`, `associated_nameservers`: Structured entity lists directly extracted from connected graph nodes.
- Observation and evidence provenance with linked `Source` records.
- Graph relationship paths and shared infrastructure trails.
- Limitations, missing information, and timeline events.

## Global Domain Discovery and Intelligence Pipeline

GraphGuard AI features an incremental, passive domain-discovery pipeline that discovers, ingests, connects, and enriches observable domains at scale:

1. **Passive Discovery Sources:**
   - Public Certificate Transparency logs (crt.sh SAN and CN extraction).
   - Public DNS-over-HTTPS (Cloudflare DoH CNAME, MX, and NS record pivots).
   - Public RDAP/WHOIS nameserver delegation records.
   - Open Threat Intelligence via URLhaus (abuse.ch open host query API).
   - Optional AlienVault OTX integration (enabled when `OTX_API_KEY` is configured).
   - Tranco top lists, zone files, and local seeds.

2. **Graph Schema & Relationship Integrity in FalkorDB:**
   - `(Domain)-[:DISCOVERED_FROM]->(Source)`: Provenance of discovery.
   - `(Domain)-[:DISCOVERED_VIA]->(Domain)`: Parent-to-child seed expansion trail.
   - `(Domain)-[:BELONGS_TO]->(Domain)`: PSL-aware subdomain to registered apex domain.
   - `(Domain)-[:RESOLVES_TO]->(IPAddress)`: Passive DNS resolution evidence.
   - `(Domain)-[:ASSOCIATED_WITH]->(Report)`: Passive threat report associations.
   - `(Observation)-[:MENTIONED_IN]->(Report)`: Evidence linkage to threat records.
   - `(Domain)-[:HAS_NAMESERVER]->(Nameserver)`: Infrastructure delegation.

3. **Incremental Discovery Execution:**
   - Run via CLI:
     ```powershell
     python discovery_engine.py --discover-seeds "example.com" --depth 1 --budget 50 --scope "example.com" --enrich-discovered
     ```
   - Run via API:
     Send a `POST /discovery/run` request with desired seed domains and bounds.
   - Run via UI:
     Open the Streamlit application and expand the **01 / Global discovery & metrics** panel to inspect real-time metrics and launch bounded discovery jobs.

## Existing discovery and enrichment pipeline

The existing discovery and ingestion utilities remain separate from the
investigation API:

1. Place permitted public domain-list inputs in `global_sources` and run
   `python global_discovery.py` to import candidates into the local discovery
   SQLite database and, unless `--skip-graph` is used, the configured graph.
   Use `python global_discovery.py --help` for supported input formats and
   limits.
2. Alternatively, use `python bulk_ingest_domains.py --help` to import an
   existing domain list into the graph. Both graph ingestion workflows use
   `MERGE` and preserve their existing checkpoints.
3. To collect passive observations from Cloudflare DNS, RDAP, and crt.sh, run
   `python enrichment_worker.py --limit 10 --delay 2`. The worker records
   collection status, source outcomes, and observations without assigning a
   security verdict. `python enrichment_worker.py --status` displays its
   checkpoint state.
4. Restart the API/UI and investigate the graph records. Investigations do
   not themselves start collection jobs.

Provider results distinguish valid empty responses (`no_records`) from
unavailable providers and partial results. Failed jobs use bounded exponential
backoff and stop after five attempts. Running jobs are only recovered after
their recorded 15-minute lease expires; legacy running jobs without lease
metadata are deliberately left untouched. `--retry` explicitly requeues
terminal `FAILED` jobs.

Collection uses public sources and can take time; do not run it against
domains unless their investigation is authorized.

## Why FalkorDB is Essential to GraphGuard AI

Cybersecurity threat investigations cannot be solved effectively with traditional tabular databases. Attack infrastructure is inherently a connected network: malicious actors reuse nameservers, pivot across IP addresses, issue wildcard certificates spanning multiple subdomains, and distribute malware across disposable domains.

FalkorDB enables GraphGuard AI to:
- **Execute Low-Latency Multi-Hop Traversals:** Trace relationships such as `(Domain)-[:RESOLVES_TO]->(IPAddress)-[:MENTIONED_IN]->(Report)` and `(Domain)-[:HAS_OBSERVATION]->(Observation)-[:DESCRIBES_CERTIFICATE]->(Certificate)` in milliseconds using OpenCypher.
- **Surface Shared Infrastructure Trails:** Instantly uncover when two seemingly unrelated domains share an apex registered domain (`BELONGS_TO`), a nameserver (`HAS_NAMESERVER`), or a TLS certificate (`COVERS`), without costly multi-table SQL joins.
- **Maintain Evidence Provenance at the Edge:** Every observation is tied directly to its collector `Source` record via `REPORTED_BY`, ensuring that security analysts know the origin, timestamp, and confidence of every finding.
- **Enforce Conservative Graph-Bound Reasoning:** The query engine bounds traversal depth (1–3 hops) and entity counts (1–200) to keep investigations defensive, deterministic, and resistant to graph explosion attacks.

## Tests

Run the full regression test suite from the project directory using the virtual environment:

```powershell
.\.venv\Scripts\python.exe -m pytest -p no:cacheprovider -q
```

Or run the unittest discovery runner:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
```

These tests use isolated in-memory test doubles, mocked providers, and temporary SQLite databases. They do not write to the production `GraphGuard` graph or perform live external scanning.

## Reproducible Hackathon Demonstration Script

Follow this exact sequence to present GraphGuard AI:

1. **Start Services (Localhost-Only):**
   - Terminal 1 (Backend API):
     ```powershell
     .\.venv\Scripts\python.exe -m uvicorn api:app --host 127.0.0.1 --port 8000
     ```
   - Terminal 2 (Streamlit Frontend):
     ```powershell
     .\.venv\Scripts\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
     ```
2. **Access the Application:**
   - Open `http://127.0.0.1:8501` in your browser.
   - Verify sidebar status displays: **Backend API reachable** and **FalkorDB reachable**.
3. **Inspect Infrastructure & Discovery Metrics:**
   - Expand **01 / Global discovery & metrics**.
   - Show transparent metrics: 10,118+ domains, 46 certificates, connected IPs, and discovery sources.
4. **Demonstrate Bounded Passive Discovery:**
   - In the discovery form, enter an authorized seed (e.g., `target.com` or your authorized domain).
   - Set **Scope Restriction** to `target.com`, **Max Depth** to `1`, and budget to `20`.
   - Click **◈ LAUNCH PASSIVE DISCOVERY**.
   - Show job status updating in real-time (`RUNNING` -> `COMPLETED`) with discovered subdomain counts and error tracking.
5. **Run Evidence-Backed Investigation:**
   - In **02 / Target investigation**, enter `target.com` and click **Investigate Domain**.
   - Show the interactive graph visualization showing connected nodes and labeled relationship edges.
   - Expand **Structured Connected Infrastructure** to view associated certificates (DigiCert), nameservers (Akamai), and observation sources.
   - Note the **Investigation Status: `INVESTIGATED`** and **Registered Apex: `target.com`**.
6. **Demonstrate Uncertainty & Missing Evidence Handling:**
   - In **02 / Target investigation**, enter an unassessed domain (e.g., `demo.example` or an uncollected domain).
   - Show the resulting **Investigation Status: `NO_EVIDENCE_FOUND`** and **Assessment: `NOT_ASSESSED`**.
   - Highlight the analyst caution: *Absence of evidence does not establish safety*.
7. **Demonstrate Absent Domain Handling:**
   - Search for `nonexistent-domain-test.org`.
   - Show **Investigation Status: `NOT_FOUND`** with explicit limitations and zero fabricated findings.

## Truthful 2-to-3 Minute Hackathon Demo Script

- **[0:00 - 0:30] The Challenge & FalkorDB Core:**
  > *"Cyber adversaries don't operate isolated servers; they build interconnected infrastructure across rotating nameservers, shared wildcard TLS certificates, and disposable subdomains. In relational systems, analyzing these networks requires slow, expensive joins. GraphGuard AI leverages FalkorDB to represent domains, certificates, and IP resolutions as an interconnected threat knowledge graph."*
- **[0:30 - 1:00] Transparent Staging & Global Baseline:**
  > *"In our dashboard, we transparently monitor 10,118 domains and 46 TLS certificates in FalkorDB, alongside 4.17M candidates staged in SQLite from Tranco. The system explicitly separates database-wide inventory from target-specific connections."*
- **[1:00 - 1:45] Bounded Discovery & Traversal:**
  > *"When an analyst initiates bounded passive discovery on an authorized seed, GraphGuard queries open public sources—crt.sh Certificate Transparency, DNS-over-HTTPS, and RDAP—without invasive scanning. It merges discovered infrastructure into FalkorDB with strict depth and budget caps, respecting scope boundaries."*
- **[1:45 - 2:30] Evidence-Backed Investigation & Conservative Uncertainty:**
  > *"Investigating `target.com` instantly executes multi-hop OpenCypher traversals, revealing 19 specifically associated certificates and Akamai nameservers with full source provenance. Crucially, when querying an unassessed domain like `demo.example`, GraphGuard declares `NO_EVIDENCE_FOUND` with verdict `NOT_ASSESSED`. We strictly enforce: absence of evidence is never evidence of safety."*
- **[2:30 - 3:00] Summary & Hackathon Impact:**
  > *"By coupling FalkorDB graph traversals with conservative uncertainty policies and streaming batch audit tools, GraphGuard AI transforms noisy cyber telemetry into actionable, explainable attack-surface intelligence."*

## Resumable Batch Domain Audit & Coverage Engine

GraphGuard AI provides a high-throughput, crash-resilient batch testing engine (`domain_batch_audit.py`) designed to validate and audit arbitrarily large domain lists:

### Core Architecture & Capabilities
- **Streaming Pipeline:** Reads arbitrarily large input files (`.txt`, `.csv`, `.gz`) line-by-line without loading entire datasets into memory.
- **Strict PSL Validation:** Validates domains using the Public Suffix List, categorizing inputs into `APEX_DOMAIN`, `SUBDOMAIN`, `RESERVED_TEST`, `PUBLIC_SUFFIX_REJECTED`, `INVALID_SYNTAX`, and `URL_OR_PATH_REJECTED`.
- **Deduplication:** Normalizes and deduplicates domains while preserving the original input line and raw format.
- **Transactional SQLite Checkpoint Store (`domain_batch_audit.sqlite3`):** Records per-domain audit telemetry and batch state. If interrupted, the audit safely resumes from the exact line where it stopped.
- **Conservative Uncertainty Enforcement:** For every domain with zero evidence, the verdict is strictly `NOT_ASSESSED`. The system never fabricates or infers `SAFE`.
- **Machine-Readable Exports:** Exports full audit records to CSV and JSONL formats.

### CLI Usage & Modes
```powershell
# 1. Dry run: validate syntax, categorize inputs, detect duplicates, and estimate workload
python domain_batch_audit.py --input fixtures/domain_coverage_sample.txt --mode dry-run

# 2. Graph-only audit: perform read-only OpenCypher queries against FalkorDB
python domain_batch_audit.py --input fixtures/domain_coverage_sample.txt --mode graph-only --export-csv results.csv --export-jsonl results.jsonl

# 3. Retest from beginning: ignore existing checkpoints
python domain_batch_audit.py --input fixtures/domain_coverage_sample.txt --mode graph-only --retest

# 4. Live passive investigation with rate limiting:
python domain_batch_audit.py --input domains.txt --mode live-passive --delay 1.0 --timeout 8.0

# 5. High-throughput mock load testing (10,000 domains):
python domain_batch_audit.py --input large_sample.txt --mode mock --batch-size 1000
```

### Scale Benchmark Results
- **100 Domains:** ~0.5s execution, verified deduplication and export integrity.
- **1,000 Domains:** ~4.5s execution, verified interrupted resumption and checkpoint recovery.
- **10,000 Domains:** 28.4s – 55.3s execution (**180 – 352 domains/sec**), flat RAM footprint (<80 MB RSS).

## Representative FalkorDB Cypher Queries

GraphGuard AI executes optimized, parameterized OpenCypher queries against FalkorDB:

1. **Multi-Hop Evidence Traversal:**
   ```cypher
   MATCH (d:Domain {name: $domain})-[r1:HAS_OBSERVATION]->(o:Observation)
   OPTIONAL MATCH (o)-[r2:DESCRIBES_CERTIFICATE]->(c:Certificate)
   OPTIONAL MATCH (o)-[r3:MENTIONS_NAMESERVER]->(ns:Nameserver)
   RETURN d.name, o.kind, o.value, type(r2), c.issuer, type(r3), ns.name
   LIMIT $row_limit
   ```

2. **Shared Infrastructure Pivoting:**
   ```cypher
   MATCH (d1:Domain)-[:HAS_NAMESERVER]->(ns:Nameserver)<-[:HAS_NAMESERVER]-(d2:Domain)
   WHERE d1.name <> d2.name
   RETURN d1.name, ns.name, d2.name
   LIMIT 50
   ```

3. **Threat Report Association:**
   ```cypher
   MATCH (d:Domain {name: $domain})-[r:ASSOCIATED_WITH]->(rep:Report)
   RETURN d.name, rep.id, rep.threat_type, rep.confidence, rep.threat_status
   ```

## Example Investigation: Real Observed Results (`target.com`)

Querying `POST /investigate` with `{"domain": "target.com", "max_depth": 2}` returns:

- **Investigation Status:** `INVESTIGATED`
- **Data Availability:** `AVAILABLE`
- **PSL Registered Apex:** `target.com`
- **Associated TLS Certificates (19):** DigiCert SHA2 Secure Server CA issued certificates (validity bounds verified)
- **Associated Nameservers (4):** `ns1-168.akam.net`, `ns4-65.akam.net`, `ns5-65.akam.net`, `ns7-64.akam.net`
- **Observed Sources:** `RDAP`, `crt.sh Certificate Transparency`
- **Assessment Verdict:** `NOT_ASSESSED` (Zero reputation records is not proof of safety; conservative uncertainty policy enforced)
- **Response Latency:** 48 ms

## Hackathon AI-Assistance Disclosure

In accordance with FalkorDB Graph Hacks 2026 rules:
- **AI Tools Used:** AI assistants were utilized for unit test generation, code audit assistance, documentation formatting, and Cypher query double-checking.
- **Human Leadership & Verification:** System architecture, database constraints, security boundaries, and validation of all test results were reviewed, executed, and confirmed by the engineering team.

## Data Safety & Environment Configuration Notes

- **Graph Read-Only Policy:** The investigation API performs read-only OpenCypher queries against the production graph (default `GraphGuard`). No graphs are dropped, recreated, or reseeded during investigation or testing.
- **FalkorDB Browser Environment Notice:** If using the FalkorDB web browser container (port 3000), optional `AUTH_SECRET` and `ENCRYPTION_KEY` environment variables configure persistent web UI browser sessions. GraphGuard AI connects directly to FalkorDB over Redis protocol on port 6379 and does not require or store these web session secrets.
- **Demo Target Disclosure:** `target.com` and `demo.example` are used in demonstrations strictly as representative passive targets and demo fixtures; their presence implies no authorization claim or maliciousness verdict.
- **Conservative Reasoning:** Discovery inputs reflect only observed datasets; absence of evidence is not evidence of safety.
