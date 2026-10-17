"""
GraphGuard AI — Scalable Incremental Domain Discovery Engine.

Features:
- Passive recursive discovery from seed domains and graph entities.
- Public Certificate Transparency (crt.sh), DNS DoH, and RDAP pivot extraction.
- Public Suffix List (PSL) awareness to distinguish subdomains from apex domains.
- Controlled batching, configurable depth, budget caps, and scope restrictions.
- FalkorDB relationship integration:
    (Domain)-[:DISCOVERED_FROM]->(Source)
    (Domain)-[:DISCOVERED_VIA]->(Domain)
    (Domain)-[:BELONGS_TO]->(RegisteredDomain)
    (Domain)-[:RESOLVES_TO]->(IPAddress)
    (Domain)-[:ASSOCIATED_WITH]->(Report)
- Thread-safe background execution and transparent discovery metrics.
- Preserves offline file ingestion for Tranco, plain text, and zone files.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import re
import sqlite3
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import graph_config
from psl_utils import (
    is_public_suffix,
    normalize_name as psl_normalize,
    registrable_domain,
)

BASE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = BASE_DIR / "global_sources"
STATE_DB = BASE_DIR / "global_discovery.sqlite3"
DOMAIN_RE = re.compile(r"^[a-z0-9-]+$")

# ---------------------------------------------------------------------------
# Global In-Memory Job & Metrics State (Thread-Safe)
# ---------------------------------------------------------------------------
_STATE_LOCK = threading.Lock()

_DISCOVERY_STATS = {
    "domains_discovered_this_run": 0,
    "last_discovery_time": None,
    "provider_errors": [],
    "recent_sources": set(),
}

_ACTIVE_JOB: dict[str, Any] = {
    "job_id": None,
    "status": "IDLE",  # IDLE, RUNNING, COMPLETED, FAILED
    "started_at": None,
    "completed_at": None,
    "seeds": [],
    "max_depth": 1,
    "max_domains": 50,
    "scope": None,
    "discovered_count": 0,
    "enriched_count": 0,
    "current_domain": None,
    "errors": [],
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize(value: Any) -> str | None:
    """Normalize a DNS name using PSL awareness and strict validation."""
    if not value or not isinstance(value, str):
        return None

    value = value.strip().lower().rstrip(".")
    if not value or value.startswith(("#", ";", "//")):
        return None

    if value.startswith("*."):
        value = value[2:]

    if any(char in value for char in ("/", "\\", ":", "@", "*", " ")):
        return None

    try:
        norm = psl_normalize(value)
    except (ValueError, UnicodeError):
        return None

    if len(norm) > 253 or "." not in norm:
        return None

    try:
        ipaddress.ip_address(norm)
        return None
    except ValueError:
        pass

    labels = norm.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or not DOMAIN_RE.fullmatch(label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            return None

    if is_public_suffix(norm) or registrable_domain(norm) is None:
        return None

    return norm


def open_text(path: Path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def extract_domain(line: str, fmt: str) -> str | None:
    line = line.strip()
    if not line or line.startswith(("#", ";", "//")):
        return None

    if fmt == "domains":
        return normalize(line.split()[0])

    if fmt == "tranco":
        try:
            fields = next(csv.reader([line]))
            if len(fields) < 2:
                return None
            return normalize(fields[1])
        except Exception:
            return None

    if fmt == "zone":
        owner = line.split()[0]
        if owner == "@":
            return None
        return normalize(owner)

    raise ValueError(f"Unsupported format: {fmt}")


def init_db(conn: sqlite3.Connection):
    """Initialize canonical discovery database schema."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            domain TEXT PRIMARY KEY,
            source_file TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            graph_imported INTEGER NOT NULL DEFAULT 0,
            enriched INTEGER NOT NULL DEFAULT 0,
            last_error TEXT
        )
    """)
    columns = {
        row[1] for row in conn.execute("PRAGMA table_info(domains)")
    }
    if "source_file" not in columns:
        conn.execute("ALTER TABLE domains ADD COLUMN source_file TEXT")
        if "source" in columns:
            conn.execute(
                "UPDATE domains SET source_file = source "
                "WHERE source_file IS NULL"
            )
    if "enriched" not in columns:
        conn.execute(
            "ALTER TABLE domains ADD COLUMN enriched "
            "INTEGER NOT NULL DEFAULT 0"
        )
    if "last_error" not in columns:
        conn.execute("ALTER TABLE domains ADD COLUMN last_error TEXT")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS files (
            path TEXT PRIMARY KEY,
            size INTEGER NOT NULL,
            mtime_ns INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0,
            valid_rows INTEGER NOT NULL DEFAULT 0,
            invalid_rows INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.commit()


def import_source_file(conn: sqlite3.Connection, path: Path, fmt: str):
    stat = path.stat()
    signature = (stat.st_size, stat.st_mtime_ns)
    old = conn.execute(
        "SELECT size, mtime_ns, completed FROM files WHERE path=?",
        (str(path.resolve()),),
    ).fetchone()

    if old and old[:2] == signature and old[2] == 1:
        print(f"Already imported: {path.name}")
        return

    conn.execute("""
        INSERT INTO files(path, size, mtime_ns, completed)
        VALUES (?, ?, ?, 0)
        ON CONFLICT(path) DO UPDATE SET
            size=excluded.size,
            mtime_ns=excluded.mtime_ns,
            completed=0
    """, (str(path.resolve()), stat.st_size, stat.st_mtime_ns))
    conn.commit()

    valid = 0
    invalid = 0
    source = path.name

    with open_text(path) as handle:
        for line in handle:
            domain = extract_domain(line, fmt)
            if not domain:
                invalid += 1
                continue

            conn.execute("""
                INSERT OR IGNORE INTO domains
                    (domain, source_file, first_seen)
                VALUES (?, ?, ?)
            """, (domain, source, now()))
            valid += 1

            if (valid + invalid) % 5000 == 0:
                conn.commit()
                print(f"  Read {valid + invalid:,} rows from {path.name}")

    conn.commit()
    conn.execute("""
        UPDATE files
        SET completed=1, valid_rows=?, invalid_rows=?
        WHERE path=?
    """, (valid, invalid, str(path.resolve())))
    conn.commit()

    print(f"Finished {path.name}: {valid:,} valid rows, {invalid:,} rejected rows")


def import_to_graph(conn: sqlite3.Connection, graph: Any, batch_size: int) -> int:
    total = 0

    while True:
        rows = conn.execute("""
            SELECT domain, source_file, first_seen
            FROM domains
            WHERE graph_imported=0
            ORDER BY domain
            LIMIT ?
        """, (batch_size,)).fetchall()

        if not rows:
            break

        payload = [
            {"domain": d, "source": s, "seen": t}
            for d, s, t in rows
        ]

        graph.query("""
            UNWIND $rows AS row
            MERGE (d:Domain {name: row.domain})
            ON CREATE SET d.first_seen = row.seen, d.discovery_status = 'DISCOVERED'
            SET d.last_seen = row.seen
            MERGE (s:Source {name: row.source})
            MERGE (d)-[:DISCOVERED_FROM]->(s)
        """, {"rows": payload})

        conn.executemany(
            "UPDATE domains SET graph_imported=1 WHERE domain=?",
            [(row[0],) for row in rows],
        )
        conn.commit()

        total += len(rows)
        print(f"Graph-imported this run: {total:,}")

    return total


def enrich_domains(conn: sqlite3.Connection, graph: Any, limit: int, delay: float):
    if limit <= 0:
        return

    import injest_intel
    from real_intel import collect_intelligence

    rows = conn.execute("""
        SELECT domain FROM domains
        WHERE enriched=0
        ORDER BY domain
        LIMIT ?
    """, (limit,)).fetchall()

    for index, (domain,) in enumerate(rows, 1):
        print(f"Enrichment {index}/{len(rows)}: {domain}")

        try:
            result = collect_intelligence(domain)

            for item in result.get("observations", []):
                if isinstance(item, dict):
                    injest_intel.ingest_observation(graph, domain, item)

            conn.execute("""
                UPDATE domains
                SET enriched=1, last_error=NULL
                WHERE domain=?
            """, (domain,))
        except Exception as exc:
            conn.execute("""
                UPDATE domains SET last_error=? WHERE domain=?
            """, (str(exc)[:300], domain))
            print(f"  Failed: {str(exc)[:160]}")

        conn.commit()

        if index < len(rows) and delay:
            time.sleep(delay)


# ---------------------------------------------------------------------------
# Incremental Passive Discovery Engine
# ---------------------------------------------------------------------------

def discover_from_seeds(
    seeds: list[str],
    max_depth: int = 1,
    max_domains: int = 50,
    scope: str | None = None,
    enrich_discovered: bool = False,
    delay: float = 0.5,
    graph: Any = None,
    job_callback: Any = None,
) -> dict[str, Any]:
    """
    Incrementally discover domains starting from seed names.
    Expands up to max_depth and max_domains using passive CT, DNS, and RDAP.
    Idempotently registers discovered domains into FalkorDB and SQLite.
    """
    import injest_intel
    import real_intel

    if graph is None:
        graph = graph_config.connect_graph()

    valid_seeds = []
    for raw in seeds:
        norm = normalize(raw)
        if norm and norm not in valid_seeds:
            valid_seeds.append(norm)

    if not valid_seeds:
        return {
            "status": "FAILED",
            "error": "No valid seed domains provided.",
            "discovered_count": 0,
            "seeds": [],
        }

    max_depth = max(1, min(3, max_depth))
    max_domains = max(1, min(500, max_domains))
    scope_domain = normalize(scope) if scope else None

    # Ensure seeds exist in FalkorDB with 'SEED' status
    timestamp = now()
    for seed in valid_seeds:
        graph.query("""
            MERGE (d:Domain {name: $domain})
            ON CREATE SET d.first_seen = $timestamp, d.discovery_status = 'SEED'
            MERGE (s:Source {name: 'Manual Seed Input'})
            ON CREATE SET s.source_type = 'seed'
            MERGE (d)-[:DISCOVERED_FROM]->(s)
        """, {"domain": seed, "timestamp": timestamp})

    queue = deque([(seed, 0) for seed in valid_seeds])
    visited = set(valid_seeds)
    discovered_records: list[dict[str, Any]] = []
    errors: list[str] = []

    # Update in-memory job state if running as job
    with _STATE_LOCK:
        _DISCOVERY_STATS["recent_sources"].add("Manual Seed Input")
        _ACTIVE_JOB.update({
            "status": "RUNNING",
            "seeds": valid_seeds,
            "max_depth": max_depth,
            "max_domains": max_domains,
            "scope": scope_domain,
            "discovered_count": 0,
            "errors": [],
        })

    try:
        conn = sqlite3.connect(STATE_DB, timeout=30)
        init_db(conn)
        for s in valid_seeds:
            conn.execute("""
                INSERT OR IGNORE INTO domains
                    (domain, source_file, first_seen, graph_imported)
                VALUES (?, 'seed', ?, 1)
            """, (s, now()))
        conn.commit()
    except Exception as exc:
        conn = None
        errors.append(f"SQLite tracking unavailable: {exc}")

    while queue and len(discovered_records) < max_domains:
        current_domain, depth = queue.popleft()

        with _STATE_LOCK:
            _ACTIVE_JOB["current_domain"] = current_domain

        try:
            intel = real_intel.collect_intelligence(
                current_domain,
                scope_domain=scope_domain,
            )

            # Ingest observations if enrichment was requested
            if enrich_discovered:
                for item in intel.get("observations", []):
                    if isinstance(item, dict):
                        injest_intel.ingest_observation(graph, current_domain, item)

            # Extract newly observed candidate domains
            candidates = intel.get("discovered_candidates", [])
            for cand in candidates:
                cand_domain = cand["domain"]
                if cand_domain in visited:
                    continue

                visited.add(cand_domain)

                # Check scope restriction if configured
                if scope_domain:
                    if not (
                        cand_domain == scope_domain
                        or cand_domain.endswith("." + scope_domain)
                    ):
                        continue

                discovered_records.append(cand)
                src_name = cand.get("source", "Passive Discovery")

                with _STATE_LOCK:
                    _DISCOVERY_STATS["domains_discovered_this_run"] += 1
                    _DISCOVERY_STATS["recent_sources"].add(src_name)
                    _ACTIVE_JOB["discovered_count"] = len(discovered_records)

                # Write to FalkorDB
                cand_seen = cand.get("discovered_at") or now()
                graph.query("""
                    MERGE (d:Domain {name: $domain})
                    ON CREATE SET d.first_seen = $seen, d.discovery_status = 'DISCOVERED'
                    SET d.last_seen = $seen
                    MERGE (s:Source {name: $source})
                    MERGE (d)-[:DISCOVERED_FROM]->(s)
                    WITH d
                    MATCH (parent:Domain {name: $parent})
                    MERGE (d)-[:DISCOVERED_VIA]->(parent)
                """, {
                    "domain": cand_domain,
                    "seen": cand_seen,
                    "source": src_name,
                    "parent": current_domain,
                })

                # PSL Registered Domain association
                reg_dom = registrable_domain(cand_domain)
                if reg_dom and reg_dom != cand_domain:
                    graph.query("""
                        MERGE (rd:Domain {name: $reg_domain})
                        WITH rd
                        MATCH (d:Domain {name: $domain})
                        MERGE (d)-[:BELONGS_TO]->(rd)
                    """, {"reg_domain": reg_dom, "domain": cand_domain})

                # Checkpoint in SQLite
                if conn:
                    try:
                        conn.execute("""
                            INSERT OR IGNORE INTO domains
                                (domain, source_file, first_seen, graph_imported)
                            VALUES (?, ?, ?, 1)
                        """, (cand_domain, src_name, cand_seen))
                        conn.commit()
                    except Exception:
                        pass

                # If under max_depth, queue for next expansion
                if depth + 1 < max_depth and len(discovered_records) < max_domains:
                    queue.append((cand_domain, depth + 1))

                if len(discovered_records) >= max_domains:
                    break

        except Exception as exc:
            err_msg = f"{current_domain}: {type(exc).__name__}: {str(exc)[:120]}"
            errors.append(err_msg)
            with _STATE_LOCK:
                _DISCOVERY_STATS["provider_errors"].append(err_msg)
                _ACTIVE_JOB["errors"].append(err_msg)

        if delay > 0 and queue:
            time.sleep(delay)

        if job_callback:
            try:
                job_callback(len(discovered_records), max_domains)
            except Exception:
                pass

    if conn:
        conn.close()

    status_str = "COMPLETED" if not errors or discovered_records else "PARTIAL"
    with _STATE_LOCK:
        _DISCOVERY_STATS["last_discovery_time"] = now()
        _ACTIVE_JOB.update({
            "status": status_str,
            "completed_at": now(),
            "current_domain": None,
            "discovered_count": len(discovered_records),
        })

    return {
        "status": status_str,
        "seeds": valid_seeds,
        "scope": scope_domain,
        "max_depth": max_depth,
        "max_domains": max_domains,
        "discovered_count": len(discovered_records),
        "discovered_domains": discovered_records,
        "errors": errors,
        "timestamp": now(),
    }


def start_discovery_job(
    seeds: list[str],
    max_depth: int = 1,
    max_domains: int = 50,
    scope: str | None = None,
    enrich_discovered: bool = False,
    delay: float = 0.5,
    graph: Any = None,
) -> dict[str, Any]:
    """Launch an asynchronous background discovery job."""
    with _STATE_LOCK:
        if _ACTIVE_JOB["status"] == "RUNNING":
            raise RuntimeError("A discovery job is already running.")
        job_id = str(uuid.uuid4())
        _ACTIVE_JOB.update({
            "job_id": job_id,
            "status": "RUNNING",
            "started_at": now(),
            "completed_at": None,
            "seeds": seeds,
            "max_depth": max_depth,
            "max_domains": max_domains,
            "scope": scope,
            "discovered_count": 0,
            "enriched_count": 0,
            "current_domain": None,
            "errors": [],
        })

    def run_worker():
        try:
            discover_from_seeds(
                seeds=seeds,
                max_depth=max_depth,
                max_domains=max_domains,
                scope=scope,
                enrich_discovered=enrich_discovered,
                delay=delay,
                graph=graph,
            )
        except Exception as exc:
            with _STATE_LOCK:
                _ACTIVE_JOB["status"] = "FAILED"
                _ACTIVE_JOB["completed_at"] = now()
                _ACTIVE_JOB["errors"].append(str(exc))

    thread = threading.Thread(target=run_worker, daemon=True)
    thread.start()
    return {
        "job_id": job_id,
        "status": "RUNNING",
        "discovered": 0,
        "discovered_count": 0,
        "enriched": 0,
        "enriched_count": 0,
    }


def get_job_status() -> dict[str, Any]:
    """Return the current background discovery job status."""
    with _STATE_LOCK:
        job = dict(_ACTIVE_JOB)
        job["discovered"] = job.get("discovered_count", 0)
        job["enriched"] = job.get("enriched_count", 0)
        return job


def get_discovery_metrics(graph: Any = None) -> dict[str, Any]:
    """Return comprehensive transparent metrics for the discovery system."""
    if graph is None:
        try:
            graph = graph_config.connect_graph()
        except Exception:
            graph = None

    total_domains = 0
    investigated_domains = 0
    awaiting_investigation = 0
    unique_sources = 0
    ip_addresses = 0
    certificates = 0
    reports = 0

    if graph:
        try:
            total_domains = graph.query(
                "MATCH (d:Domain) RETURN count(d)"
            ).result_set[0][0]
            investigated_domains = graph.query(
                "MATCH (d:Domain) WHERE d.enrichment_status IS NOT NULL RETURN count(d)"
            ).result_set[0][0]
            awaiting_investigation = max(0, total_domains - investigated_domains)
            unique_sources = graph.query(
                "MATCH (s:Source) RETURN count(distinct s.name)"
            ).result_set[0][0]
            ip_addresses = graph.query(
                "MATCH (ip:IPAddress) RETURN count(ip)"
            ).result_set[0][0]
            certificates = graph.query(
                "MATCH (c:Certificate) RETURN count(c)"
            ).result_set[0][0]
            reports = graph.query(
                "MATCH (r:Report) RETURN count(r)"
            ).result_set[0][0]
        except Exception:
            pass

    staged_sqlite_domains = 0
    domains_imported_to_graph = 0
    domains_awaiting_import = 0
    try:
        conn = sqlite3.connect(STATE_DB, timeout=5)
        staged_sqlite_domains = conn.execute(
            "SELECT count(*) FROM domains"
        ).fetchone()[0]
        try:
            domains_imported_to_graph = conn.execute(
                "SELECT count(*) FROM domains WHERE graph_imported = 1"
            ).fetchone()[0]
            domains_awaiting_import = max(0, staged_sqlite_domains - domains_imported_to_graph)
        except Exception:
            pass
        conn.close()
    except Exception:
        pass

    enrichment_db = BASE_DIR / "enrichment_checkpoint.sqlite3"
    enrichment_jobs_total = 0
    enrichment_jobs_completed = 0
    enrichment_jobs_pending = 0
    enrichment_with_evidence = 0
    if enrichment_db.exists():
        try:
            e_conn = sqlite3.connect(enrichment_db, timeout=5)
            e_cursor = e_conn.cursor()
            enrichment_jobs_total = e_cursor.execute(
                "SELECT count(*) FROM enrichment_jobs"
            ).fetchone()[0]
            for row in e_cursor.execute(
                "SELECT status, count(*) FROM enrichment_jobs GROUP BY status"
            ).fetchall():
                if row[0] == "DONE":
                    enrichment_jobs_completed = row[1]
                elif row[0] == "PENDING":
                    enrichment_jobs_pending = row[1]
            enrichment_with_evidence = e_cursor.execute(
                "SELECT count(*) FROM enrichment_jobs WHERE observation_count > 0"
            ).fetchone()[0]
            e_conn.close()
        except Exception:
            pass

    with _STATE_LOCK:
        run_discovered = _DISCOVERY_STATS["domains_discovered_this_run"]
        last_time = _DISCOVERY_STATS["last_discovery_time"]
        errs = list(_DISCOVERY_STATS["provider_errors"][-10:])
        recent_srcs = sorted(_DISCOVERY_STATS["recent_sources"])
        job_info = dict(_ACTIVE_JOB)

    return {
        "dataset_scope_notice": (
            "Metrics reflect GraphGuard AI's locally stored and observed dataset; "
            "not a comprehensive census of all internet domains."
        ),
        "total_domains_in_graph": total_domains,
        "investigated_domains": investigated_domains,
        "awaiting_investigation": awaiting_investigation,
        "staged_in_sqlite": staged_sqlite_domains,
        "staged_domain_records": staged_sqlite_domains,
        "unique_staged_domains": staged_sqlite_domains,
        "staged_imported_to_graph": domains_imported_to_graph,
        "staged_awaiting_graph_import": domains_awaiting_import,
        "enrichment_jobs_total": enrichment_jobs_total,
        "enrichment_jobs_completed": enrichment_jobs_completed,
        "enrichment_jobs_pending": enrichment_jobs_pending,
        "enrichment_jobs_with_evidence": enrichment_with_evidence,
        "unique_sources_used": max(unique_sources, len(recent_srcs)),
        "associated_ip_addresses": ip_addresses,
        "associated_certificates": certificates,
        "associated_threat_reports": reports,
        "domains_discovered_this_run": run_discovered,
        "last_successful_discovery": last_time,
        "recent_provider_errors": errs,
        "active_job": job_info,
        "graph": {
            "total_domains": total_domains,
            "investigated_domains": investigated_domains,
            "awaiting_investigation": awaiting_investigation,
            "unique_sources": max(unique_sources, len(recent_srcs)),
            "total_ips": ip_addresses,
            "total_certificates": certificates,
            "total_reports": reports,
            "domains_with_evidence": investigated_domains,
        },
        "discovery_repository": {
            "total_discovered": staged_sqlite_domains,
            "staged_records": staged_sqlite_domains,
            "unique_staged_domains": staged_sqlite_domains,
            "imported_to_graph": domains_imported_to_graph,
            "awaiting_import": domains_awaiting_import,
            "awaiting_enrichment": awaiting_investigation,
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="GraphGuard AI Global Domain Discovery Engine"
    )
    parser.add_argument(
        "--format",
        choices=["domains", "tranco", "zone"],
        default="domains",
        help="Format of local dataset files in global_sources",
    )
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument(
        "--enrich",
        type=int,
        default=0,
        help="Enrich up to this many not-yet-enriched domains",
    )
    parser.add_argument("--delay", type=float, default=1.0)
    parser.add_argument(
        "--discover-seeds",
        type=str,
        help="Comma-separated seeds for passive recursive discovery",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        default=1,
        help="Maximum discovery traversal depth (1-3)",
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=50,
        help="Maximum domains to discover in this run (1-500)",
    )
    parser.add_argument(
        "--scope",
        type=str,
        help="Optional domain suffix scope constraint (e.g. example.com)",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Print discovery metrics and status",
    )

    args = parser.parse_args()

    if args.status:
        metrics = get_discovery_metrics()
        print(json.dumps(metrics, indent=2))
        return

    # Seed-driven discovery mode
    if args.discover_seeds:
        seeds = [s.strip() for s in args.discover_seeds.split(",") if s.strip()]
        print(f"Starting passive discovery for seeds: {seeds}")
        res = discover_from_seeds(
            seeds=seeds,
            max_depth=args.max_depth,
            max_domains=args.max_domains,
            scope=args.scope,
            enrich_discovered=bool(args.enrich > 0),
            delay=args.delay,
        )
        print(f"Discovery completed: {res['status']}")
        print(f"Discovered: {res['discovered_count']} domains")
        for item in res["discovered_domains"][:15]:
            print(f"  - {item['domain']} (via {item.get('source')})")
        return

    # File-based discovery mode (backward compatible)
    SOURCE_DIR.mkdir(exist_ok=True)
    files = sorted(
        path for path in SOURCE_DIR.rglob("*")
        if path.is_file()
        and (
            path.name.lower().endswith(".txt")
            or path.name.lower().endswith(".csv")
            or path.name.lower().endswith(".gz")
        )
    )

    if not files:
        print(
            f"No source files in {SOURCE_DIR.resolve()}. "
            "Use --discover-seeds to perform online passive discovery."
        )
        return

    conn = sqlite3.connect(STATE_DB)
    init_db(conn)

    try:
        for path in files:
            print(f"\nReading source: {path}")
            import_source_file(conn, path, args.format)

        graph = graph_config.connect_graph()
        imported = import_to_graph(conn, graph, args.batch_size)

        if args.enrich:
            enrich_domains(conn, graph, args.enrich, args.delay)

        metrics = get_discovery_metrics(graph)
        print("\nGLOBAL INGESTION SUMMARY")
        print(json.dumps(metrics, indent=2))

    finally:
        conn.close()


if __name__ == "__main__":
    main()
