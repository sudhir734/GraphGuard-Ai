
import argparse
import csv
import gzip
import ipaddress
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import graph_config

GRAPH_NAME = graph_config.get_graph_settings()[2]
BASE_DIR = Path(__file__).resolve().parent
SOURCE_DIR = BASE_DIR / "global_sources"
STATE_DB = BASE_DIR / "global_discovery.sqlite3"
DOMAIN_RE = re.compile(r"^[a-z0-9-]+$")


def now():
    return datetime.now(timezone.utc).isoformat()


def normalize(value):
    value = value.strip().lower().rstrip(".")
    if not value or value.startswith("#"):
        return None

    if value.startswith("*."):
        value = value[2:]

    if any(char in value for char in ("/", "\\", ":", "@", "*", " ")):
        return None

    try:
        value = value.encode("idna").decode("ascii")
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass
    except UnicodeError:
        return None

    if len(value) > 253 or "." not in value:
        return None

    labels = value.split(".")
    for label in labels:
        if (
            not label
            or len(label) > 63
            or not DOMAIN_RE.fullmatch(label)
            or label.startswith("-")
            or label.endswith("-")
        ):
            return None

    return value


def open_text(path):
    if path.name.lower().endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def extract_domain(line, fmt):
    line = line.strip()
    if not line or line.startswith(("#", ";", "//")):
        return None

    if fmt == "domains":
        return normalize(line.split()[0])

    if fmt == "tranco":
        # Common ranked-list format: rank,domain
        fields = next(csv.reader([line]))
        if len(fields) < 2:
            return None
        return normalize(fields[1])

    if fmt == "zone":
        # DNS zone-file records start with an owner name.
        owner = line.split()[0]
        if owner == "@":
            return None
        return normalize(owner)

    raise ValueError(f"Unsupported format: {fmt}")


def init_db(conn):
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


def import_source_file(conn, path, fmt):
    stat = path.stat()
    signature = (stat.st_size, stat.st_mtime_ns)
    old = conn.execute(
        "SELECT size, mtime_ns, completed FROM files WHERE path=?",
        (str(path.resolve()),),
    ).fetchone()

    if old and old[:2] == signature and old[2] == 1:
        print(f"Already imported: {path.name}")
        return

    if old and old[:2] != signature:
        print(
            f"Source changed: {path.name}. "
            "Previously seen domains remain deduplicated."
        )

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
                print(
                    f"  Read {valid + invalid:,} rows from "
                    f"{path.name}"
                )

    conn.commit()
    conn.execute("""
        UPDATE files
        SET completed=1, valid_rows=?, invalid_rows=?
        WHERE path=?
    """, (valid, invalid, str(path.resolve())))
    conn.commit()

    print(
        f"Finished {path.name}: {valid:,} valid rows, "
        f"{invalid:,} rejected rows"
    )


def import_to_graph(conn, graph, batch_size):
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
            ON CREATE SET d.first_seen = row.seen
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


def enrich_domains(conn, graph, limit, delay):
    if limit <= 0:
        return

    # Import the existing collector only when enrichment is requested.
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
                    import injest_intel
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


def main():
    parser = argparse.ArgumentParser(
        description="Global, source-driven domain ingestion for GraphGuard"
    )
    parser.add_argument(
        "--format",
        choices=["domains", "tranco", "zone"],
        default="domains",
        help="Format shared by files in global_sources",
    )
    parser.add_argument("--batch-size", type=int, default=1000)
    parser.add_argument(
        "--enrich",
        type=int,
        default=0,
        help="Enrich up to this many not-yet-enriched domains",
    )
    parser.add_argument("--delay", type=float, default=2.0)
    args = parser.parse_args()

    if not 1 <= args.batch_size <= 5000:
        parser.error("--batch-size must be between 1 and 5000")
    if not 0 <= args.enrich <= 500:
        parser.error("--enrich must be between 0 and 500")
    if not 0 <= args.delay <= 60:
        parser.error("--delay must be between 0 and 60 seconds")

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
        raise SystemExit(
            f"No source files found. Add authorized datasets to "
            f"{SOURCE_DIR.resolve()}"
        )

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

        total = conn.execute(
            "SELECT COUNT(*) FROM domains"
        ).fetchone()[0]
        pending = conn.execute("""
            SELECT COUNT(*) FROM domains WHERE graph_imported=0
        """).fetchone()[0]
        enriched = conn.execute("""
            SELECT COUNT(*) FROM domains WHERE enriched=1
        """).fetchone()[0]

        print("\nGLOBAL INGESTION SUMMARY")
        print(f"Unique domains staged: {total:,}")
        print(f"Graph imports this run: {imported:,}")
        print(f"Domains pending graph import: {pending:,}")
        print(f"Domains enriched: {enriched:,}")
        print(f"State database: {STATE_DB.resolve()}")
        print("Assessment: NOT_ASSESSED")

    finally:
        conn.close()


if __name__ == "__main__":
    main()
