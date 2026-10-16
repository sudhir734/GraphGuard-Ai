# GraphGuard AI

GraphGuard investigates records already stored in the FalkorDB graph named
`GraphGuard`. Investigations are passive, bounded graph reads: they do not
perform network scans or collect new intelligence. New passive collection is
the separate responsibility of `enrichment_worker.py`.

The investigation assessment policy is intentionally conservative. A domain
with a graph node but no linked observations remains `NOT_ASSESSED`; a missing
node is reported as `NOT_FOUND`, not as safe. Every observation is tied to its
stored observation record and, when present, its linked `Source` records.

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

## API

- `GET /health` reports API availability separately from FalkorDB connectivity.
- `GET /health/ready` returns HTTP 503 if the application is running but the
  graph is unavailable.
- `POST /investigate` validates a domain and returns a bounded report.

Example request body (replace the placeholder with the domain to investigate):

```json
{
  "domain": "<domain-to-investigate>",
  "max_depth": 2,
  "max_entities": 100
}
```

`max_depth` is limited to 1–3 and `max_entities` to 1–200. Invalid names,
URLs, IP addresses, and public suffixes are rejected with HTTP 422. A graph
connection or query failure returns HTTP 503 without exposing internal
database details.

Reports include the target's stored properties, discovery/enrichment status,
bounded graph entities and relationships, observation/source records,
relationship paths, evidence timestamps, shared infrastructure supported by
actual graph paths, missing information, and an assessment with supporting
evidence IDs. Graph connectivity is not a maliciousness verdict. The API does
not persist investigation history; the UI's recent activity is session-local.
The UI's JSON export contains the response returned for that investigation.

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

## Tests

Run the offline unit suite from the project directory:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -v
```

These tests use isolated graph-query doubles and temporary SQLite checkpoint
databases. They do not write to the configured FalkorDB graph or create
production intelligence.

## Data safety notes

- The investigation API performs read-only queries against the configured
  graph (default `GraphGuard`); no graph is dropped, recreated, or reseeded.
- The repository's `seed_graph.py` explicitly creates fictional demo records.
  It refuses to run unless `FALKORDB_GRAPH` names `GraphGuardDemo` (or a
  `GraphGuardDemo_...` graph) and `--confirm-demo-graph` is supplied. Never
  point it at a production graph.
- Discovery inputs are only as representative as the datasets provided; the
  application does not discover or investigate every domain on the internet.
- Absence of observations is not evidence that a domain is safe.
