
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from psl_utils import normalize_name, registrable_domain
import graph_config


BASE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = BASE_DIR / "global_sources"
DB_FILE = BASE_DIR / "global_discovery.sqlite3"

GRAPH_NAME = graph_config.get_graph_settings()[2]
DEFAULT_BATCH_SIZE = 500
DEFAULT_GRAPH_LIMIT = 10000


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def normalize_candidate(value):
    value = value.strip().strip('"').strip("'").rstrip(".")

    if not value or value.startswith("#") or value.startswith("//"):
        return None

    try:
        ipaddress.ip_address(value.strip("[]"))
        return None
    except ValueError:
        pass

    try:
        domain = normalize_name(value)

        if len(domain) > 253:
            return None

        if registrable_domain(domain) is None:
            return None

        return domain

    except (ValueError, UnicodeError):
        return None


def connect_db():
    conn = sqlite3.connect(DB_FILE, timeout=60)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            domain TEXT PRIMARY KEY,
            source_file TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            graph_imported INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS sources (
            source_file TEXT PRIMARY KEY,
            signature TEXT NOT NULL,
            last_line INTEGER NOT NULL DEFAULT 0,
            completed INTEGER NOT NULL DEFAULT 0
        )
    """)

    conn.commit()
    return conn


def open_source(path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(
            path,
            "rt",
            encoding="utf-8-sig",
            errors="replace",
        )

    return path.open(
        "r",
        encoding="utf-8-sig",
        errors="replace",
    )


def file_signature(path):
    stat = path.stat()

    raw = (
        f"{path.name}:"
        f"{stat.st_size}:"
        f"{stat.st_mtime_ns}"
    )

    return hashlib.sha256(raw.encode()).hexdigest()


def extract_domain(line, file_format):
    line = line.strip()

    if not line or line.startswith("#") or line.startswith("//"):
        return None

    if file_format == "domains":
        candidate = line.split()[0]

    elif file_format == "tranco":
        try:
            row = next(csv.reader([line]))
        except (csv.Error, StopIteration):
            return None

        if len(row) < 2:
            return None

        candidate = row[1].strip()

    else:
        return None

    return normalize_candidate(candidate)


def save_import_batch(
    conn,
    batch,
    source_name,
    line_number,
):
    before = conn.total_changes

    conn.executemany("""
        INSERT OR IGNORE INTO domains
            (domain, source_file, first_seen)
        VALUES (?, ?, ?)
    """, batch)

    added = conn.total_changes - before

    conn.execute("""
        UPDATE sources
        SET last_line = ?
        WHERE source_file = ?
    """, (line_number, source_name))

    conn.commit()

    return added


def import_source_file(
    conn,
    path,
    file_format,
    batch_size,
):
    source_name = path.name
    signature = file_signature(path)

    row = conn.execute("""
        SELECT signature, last_line, completed
        FROM sources
        WHERE source_file = ?
    """, (source_name,)).fetchone()

    if row and row[0] == signature and row[2]:
        print(f"[SKIP] Already completed: {source_name}")
        return

    if not row or row[0] != signature:
        conn.execute("""
            INSERT INTO sources
                (source_file, signature, last_line, completed)
            VALUES (?, ?, 0, 0)
            ON CONFLICT(source_file) DO UPDATE SET
                signature = excluded.signature,
                last_line = 0,
                completed = 0
        """, (source_name, signature))

        conn.commit()
        last_line = 0

    else:
        last_line = row[1]

    print(f"\n[IMPORT] {source_name}")
    print(f"[RESUME] Starting after line {last_line:,}")

    scanned = 0
    added = 0
    batch = []
    final_line = last_line

    with open_source(path) as handle:
        for line_number, line in enumerate(handle, start=1):
            if line_number <= last_line:
                continue

            final_line = line_number
            scanned += 1

            domain = extract_domain(line, file_format)

            if domain:
                batch.append((
                    domain,
                    source_name,
                    utc_now(),
                ))

            if scanned % batch_size == 0:
                added += save_import_batch(
                    conn,
                    batch,
                    source_name,
                    line_number,
                )

                batch.clear()

                print(
                    f"[PROGRESS] "
                    f"file_line={line_number:,} "
                    f"new_unique={added:,}"
                )

        if batch:
            added += save_import_batch(
                conn,
                batch,
                source_name,
                final_line,
            )

        conn.execute("""
            UPDATE sources
            SET last_line = ?, completed = 1
            WHERE source_file = ?
        """, (final_line, source_name))

        conn.commit()

    print(f"[DONE] New unique domains: {added:,}")


def connect_graph():
    return graph_config.connect_graph()


def import_to_graph(
    conn,
    batch_size,
    graph_limit,
):
    if graph_limit <= 0:
        print("[GRAPH] Limit is zero. Nothing to import.")
        return

    graph = connect_graph()

    total = 0

    print("\n[GRAPH] Starting controlled import")
    print(f"[GRAPH] Batch size: {batch_size:,}")
    print(f"[GRAPH] Run limit: {graph_limit:,}")

    while total < graph_limit:
        remaining = graph_limit - total

        rows = conn.execute("""
            SELECT domain, source_file, first_seen
            FROM domains
            WHERE graph_imported = 0
            ORDER BY domain
            LIMIT ?
        """, (min(batch_size, remaining),)).fetchall()

        if not rows:
            break

        payload = [
            {
                "domain": domain,
                "source": source,
                "first_seen": first_seen,
            }
            for domain, source, first_seen in rows
        ]

        # Execute graph write first. Only checkpoint SQLite
        # after FalkorDB confirms the query succeeded.
        graph.query("""
            UNWIND $rows AS row

            MERGE (d:Domain {name: row.domain})
            ON CREATE SET
                d.first_seen = row.first_seen,
                d.discovery_status = 'DISCOVERED'

            MERGE (s:Source {name: row.source})
            ON CREATE SET
                s.source_type = 'public_domain_dataset'

            MERGE (d)-[:DISCOVERED_FROM]->(s)
        """, {"rows": payload})

        conn.executemany("""
            UPDATE domains
            SET graph_imported = 1
            WHERE domain = ?
        """, [(domain,) for domain, _, _ in rows])

        conn.commit()

        total += len(rows)

        print(
            f"[GRAPH] Imported this run: "
            f"{total:,}/{graph_limit:,}"
        )

    pending = conn.execute("""
        SELECT COUNT(*)
        FROM domains
        WHERE graph_imported = 0
    """).fetchone()[0]

    print("\n[GRAPH] Import finished")
    print(f"Imported this run: {total:,}")
    print(f"Remaining in SQLite: {pending:,}")


def show_status(conn):
    total = conn.execute("""
        SELECT COUNT(*) FROM domains
    """).fetchone()[0]

    imported = conn.execute("""
        SELECT COUNT(*)
        FROM domains
        WHERE graph_imported = 1
    """).fetchone()[0]

    pending = total - imported

    print("\n========== GRAPHGUARD STATUS ==========")
    print(f"SQLite domains : {total:,}")
    print(f"Graph imported : {imported:,}")
    print(f"Graph pending  : {pending:,}")

    sources = conn.execute("""
        SELECT source_file, last_line, completed
        FROM sources
        ORDER BY source_file
    """).fetchall()

    for name, line, completed in sources:
        state = "COMPLETE" if completed else "INCOMPLETE"
        print(f"Source: {name}")
        print(f"  Checkpoint: {line:,}")
        print(f"  Status: {state}")

    print("=======================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="GraphGuard AI global domain discovery"
    )

    parser.add_argument(
        "--format",
        choices=("domains", "tranco"),
        default="tranco",
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
    )

    parser.add_argument(
        "--graph-limit",
        type=int,
        default=DEFAULT_GRAPH_LIMIT,
    )

    parser.add_argument(
        "--skip-graph",
        action="store_true",
    )

    parser.add_argument(
        "--graph-only",
        action="store_true",
        help="Import existing SQLite domains without reading CSV files",
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Display SQLite import progress only",
    )

    args = parser.parse_args()

    if args.batch_size < 1:
        parser.error("--batch-size must be at least 1")

    if args.graph_limit < 0:
        parser.error("--graph-limit cannot be negative")

    if args.graph_only and args.skip_graph:
        parser.error(
            "--graph-only and --skip-graph cannot be used together"
        )

    conn = connect_db()

    try:
        if args.status:
            show_status(conn)
            return

        if not args.graph_only:
            SOURCE_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            files = sorted(
                path
                for path in SOURCE_DIR.iterdir()
                if path.is_file()
                and path.name.lower().endswith((
                    ".txt",
                    ".csv",
                    ".txt.gz",
                    ".csv.gz",
                ))
            )

            if not files:
                print("[INFO] No source files found.")
            else:
                for path in files:
                    import_source_file(
                        conn,
                        path,
                        args.format,
                        args.batch_size,
                    )

        show_status(conn)

        if not args.skip_graph:
            import_to_graph(
                conn,
                args.batch_size,
                args.graph_limit,
            )

            show_status(conn)

    finally:
        conn.close()


if __name__ == "__main__":
    main()
