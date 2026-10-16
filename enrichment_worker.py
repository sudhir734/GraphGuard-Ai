
from __future__ import annotations

import argparse
import json
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import real_intel
import injest_intel
import graph_config


BASE_DIR = Path(__file__).resolve().parent
CHECKPOINT_DB = BASE_DIR / "enrichment_checkpoint.sqlite3"
GRAPH_NAME = graph_config.get_graph_settings()[2]

DEFAULT_LIMIT = 10
DEFAULT_DELAY = 2.0
MAX_ATTEMPTS = 5
LEASE_SECONDS = 15 * 60
RETRY_BASE_SECONDS = 60
RETRY_MAX_SECONDS = 60 * 60


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def connect_checkpoint():
    conn = sqlite3.connect(CHECKPOINT_DB, timeout=60)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS enrichment_jobs (
            domain TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'PENDING',
            attempts INTEGER NOT NULL DEFAULT 0,
            last_attempt TEXT,
            last_error TEXT,
            observation_count INTEGER NOT NULL DEFAULT 0,
            lease_expires_at TEXT,
            next_attempt_at TEXT
        )
    """)
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(enrichment_jobs)")
    }
    for column in ("lease_expires_at", "next_attempt_at"):
        if column not in columns:
            conn.execute(
                f"ALTER TABLE enrichment_jobs ADD COLUMN {column} TEXT"
            )

    conn.commit()
    return conn


def connect_graph():
    return graph_config.connect_graph()


def seed_queue(graph, checkpoint, limit):
    """Queue previously unenriched domains without repeating completed jobs."""

    query = """
    MATCH (d:Domain)
    WHERE d.name IS NOT NULL
      AND d.enrichment_status IS NULL
    RETURN d.name AS domain
    LIMIT $limit
    """

    result = graph.query(query, {"limit": int(limit)})
    queued = 0

    for row in result.result_set:
        domain = row[0]
        if not domain:
            continue

        cursor = checkpoint.execute(
            """
            INSERT OR IGNORE INTO enrichment_jobs (domain, status)
            VALUES (?, 'PENDING')
            """,
            (domain,)
        )
        queued += cursor.rowcount

    checkpoint.commit()
    print(f"[QUEUE] Newly queued domains: {queued}")
    return queued


def get_pending(checkpoint, limit):
    now = utc_now()
    lease_expiry = (
        datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)
    ).isoformat()
    checkpoint.execute("BEGIN IMMEDIATE")
    checkpoint.execute("""
        UPDATE enrichment_jobs
        SET status = 'FAILED',
            last_error = 'Maximum attempts reached before the job lease expired.',
            lease_expires_at = NULL,
            next_attempt_at = NULL
        WHERE status = 'RUNNING'
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at <= ?
          AND attempts >= ?
    """, (now, MAX_ATTEMPTS))
    checkpoint.execute("""
        UPDATE enrichment_jobs
        SET status = 'FAILED',
            last_error = 'Maximum attempts reached.',
            next_attempt_at = NULL
        WHERE status = 'RETRY'
          AND attempts >= ?
    """, (MAX_ATTEMPTS,))
    rows = checkpoint.execute("""
        SELECT domain
        FROM enrichment_jobs
        WHERE (
            status IN ('PENDING', 'RETRY')
            AND attempts < ?
            AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
        ) OR (
            status = 'RUNNING'
            AND lease_expires_at IS NOT NULL
            AND lease_expires_at <= ?
            AND attempts < ?
        )
        ORDER BY
            CASE WHEN status = 'RUNNING' THEN 0 ELSE 1 END,
            domain
        LIMIT ?
    """, (MAX_ATTEMPTS, now, now, MAX_ATTEMPTS, limit)).fetchall()

    claimed = []
    for (domain,) in rows:
        cursor = checkpoint.execute("""
            UPDATE enrichment_jobs
            SET status = 'RUNNING',
                attempts = attempts + 1,
                last_attempt = ?,
                last_error = NULL,
                lease_expires_at = ?,
                next_attempt_at = NULL
            WHERE domain = ?
              AND (
                  (status IN ('PENDING', 'RETRY') AND attempts < ?)
                  OR (
                      status = 'RUNNING'
                      AND lease_expires_at IS NOT NULL
                      AND lease_expires_at <= ?
                  )
              )
        """, (now, lease_expiry, domain, MAX_ATTEMPTS, now))
        if cursor.rowcount:
            claimed.append((domain,))

    checkpoint.commit()
    return claimed


def retry_delay(attempts):
    exponent = min(max(0, attempts - 1), 6)
    return min(RETRY_BASE_SECONDS * (2 ** exponent), RETRY_MAX_SECONDS)


def finish_retry(checkpoint, domain, message, observation_count=None):
    row = checkpoint.execute(
        "SELECT attempts FROM enrichment_jobs WHERE domain = ?",
        (domain,),
    ).fetchone()
    attempts = row[0] if row else MAX_ATTEMPTS
    retryable = attempts < MAX_ATTEMPTS
    next_attempt = (
        datetime.now(timezone.utc)
        + timedelta(seconds=retry_delay(attempts))
    ).isoformat() if retryable else None
    status = "RETRY" if retryable else "FAILED"
    checkpoint.execute("""
        UPDATE enrichment_jobs
        SET status = ?,
            last_error = ?,
            lease_expires_at = NULL,
            next_attempt_at = ?,
            observation_count = COALESCE(?, observation_count)
        WHERE domain = ?
    """, (status, message, next_attempt, observation_count, domain))
    checkpoint.commit()
    return status


def enrich_one(graph, checkpoint, domain, claimed=False):
    if not claimed:
        matching_claim = _claim_domain(checkpoint, domain)
        if not matching_claim:
            return {
                "domain": domain,
                "status": "NOT_CLAIMED",
            }

    try:
        data = real_intel.collect_intelligence(domain)

        if not isinstance(data, dict):
            raise TypeError("Intelligence collector did not return a dictionary")

        observations = data.get("observations", [])
        if not isinstance(observations, list):
            raise TypeError("Collector observations must be a list")

        sources = data.get("sources", [])
        if not isinstance(sources, list) or any(
            not isinstance(source, dict) for source in sources
        ):
            raise TypeError("Collector sources must be a list of dictionaries")

        source_statuses = [
            {
                "source": str(source.get("source", "Unknown source")),
                "status": str(source.get("status", "unknown")).lower(),
            }
            for source in sources
        ]
        unavailable_sources = [
            source for source in source_statuses
            if source["status"] not in {"success", "no_records"}
        ]

        # Preserve the project's established ingestion schema.
        ingested_observations = 0
        for item in observations:
            if not isinstance(item, dict):
                raise TypeError("Collector observations must contain dictionaries")
            injest_intel.ingest_observation(graph, domain, item)
            ingested_observations += 1

        if ingested_observations:
            enrichment_status = "PARTIAL" if unavailable_sources else "COLLECTED"
            outcome = enrichment_status
        elif not source_statuses or all(
            source["status"] == "unavailable"
            for source in source_statuses
        ):
            enrichment_status = "UNAVAILABLE"
            outcome = "UNAVAILABLE"
        elif unavailable_sources:
            enrichment_status = "PARTIAL"
            outcome = "PARTIAL_NO_OBSERVATIONS"
        else:
            enrichment_status = "NO_OBSERVATIONS"
            outcome = "NO_OBSERVATIONS"

        source_status_json = json.dumps(source_statuses, sort_keys=True)

        # Store the collection outcome on the root domain.
        graph.query("""
            MATCH (d:Domain {name: $domain})
            SET d.last_enriched_at = $timestamp,
                d.enrichment_status = $enrichment_status,
                d.enrichment_outcome = $enrichment_outcome,
                d.enrichment_sources_json = $source_status_json,
                d.enrichment_observation_count = $observation_count,
                d.enrichment_verdict = 'NOT_ASSESSED'
        """, {
            "domain": domain,
            "timestamp": utc_now(),
            "enrichment_status": enrichment_status,
            "enrichment_outcome": outcome,
            "source_status_json": source_status_json,
            "observation_count": ingested_observations,
        })

        retry_required = bool(unavailable_sources) or not source_statuses
        if retry_required:
            status = finish_retry(
                checkpoint,
                domain,
                "One or more collection providers were unavailable.",
                ingested_observations,
            )
        else:
            checkpoint.execute("""
                UPDATE enrichment_jobs
                SET status = 'DONE',
                    observation_count = ?,
                    last_error = NULL,
                    lease_expires_at = NULL,
                    next_attempt_at = NULL
                WHERE domain = ?
            """, (ingested_observations, domain))
            checkpoint.commit()
            status = "DONE"

        return {
            "domain": domain,
            "status": status,
            "enrichment_status": enrichment_status,
            "observations": ingested_observations,
            **(
                {"error": "One or more collection providers were unavailable."}
                if retry_required else {}
            ),
        }

    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"[:1000]
        status = finish_retry(checkpoint, domain, message)

        return {
            "domain": domain,
            "status": status,
            "error": message,
        }


def _claim_domain(checkpoint, domain):
    now = utc_now()
    lease_expiry = (
        datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)
    ).isoformat()
    checkpoint.execute("BEGIN IMMEDIATE")
    checkpoint.execute("""
        UPDATE enrichment_jobs
        SET status = 'FAILED',
            last_error = 'Maximum attempts reached before the job lease expired.',
            lease_expires_at = NULL,
            next_attempt_at = NULL
        WHERE domain = ?
          AND status = 'RUNNING'
          AND lease_expires_at IS NOT NULL
          AND lease_expires_at <= ?
          AND attempts >= ?
    """, (domain, now, MAX_ATTEMPTS))
    cursor = checkpoint.execute("""
        UPDATE enrichment_jobs
        SET status = 'RUNNING',
            attempts = attempts + 1,
            last_attempt = ?,
            last_error = NULL,
            lease_expires_at = ?,
            next_attempt_at = NULL
        WHERE domain = ?
          AND attempts < ?
          AND (
              (
                  status IN ('PENDING', 'RETRY')
                  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
              )
              OR (
                  status = 'RUNNING'
                  AND lease_expires_at IS NOT NULL
                  AND lease_expires_at <= ?
              )
          )
    """, (
        now,
        lease_expiry,
        domain,
        MAX_ATTEMPTS,
        now,
        now,
    ))
    checkpoint.commit()
    return cursor.rowcount > 0


def show_stats(checkpoint):
    rows = checkpoint.execute("""
        SELECT status, COUNT(*)
        FROM enrichment_jobs
        GROUP BY status
        ORDER BY status
    """).fetchall()

    print("\n========== ENRICHMENT STATUS ==========")

    if not rows:
        print("No domains have been queued yet.")
    else:
        for status, count in rows:
            print(f"{status:10} {count:,}")

    print("=======================================\n")


def main():
    parser = argparse.ArgumentParser(
        description="GraphGuard passive intelligence enrichment worker"
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help="Maximum domains to queue or process in this run",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY,
        help="Delay in seconds between domain collection attempts",
    )

    parser.add_argument(
        "--status",
        action="store_true",
        help="Show checkpoint statistics and exit",
    )

    parser.add_argument(
        "--retry",
        action="store_true",
        help="Retry previously failed domains",
    )

    args = parser.parse_args()

    if args.limit < 1:
        parser.error("--limit must be at least 1")

    if args.delay < 0:
        parser.error("--delay cannot be negative")

    checkpoint = connect_checkpoint()

    try:
        if args.status:
            show_stats(checkpoint)
            return

        graph = connect_graph()

        if args.retry:
            checkpoint.execute("""
                UPDATE enrichment_jobs
                SET status = 'RETRY',
                    attempts = 0,
                    next_attempt_at = NULL,
                    lease_expires_at = NULL
                WHERE status = 'FAILED'
            """)
            checkpoint.commit()

        queued = seed_queue(graph, checkpoint, args.limit)
        print(f"[QUEUE] Newly queued domains: {queued:,}")

        jobs = get_pending(checkpoint, args.limit)
        print(f"[START] Domains to enrich: {len(jobs):,}")

        for index, (domain,) in enumerate(jobs, start=1):
            result = enrich_one(graph, checkpoint, domain, claimed=True)

            print(
                f"[{index}/{len(jobs)}] "
                f"{result['domain']} -> {result['status']}"
            )

            if result["status"] == "DONE":
                print(
                    f"  observations={result['observations']}"
                )
            else:
                print(f"  error={result.get('error', result['status'])}")

            if index < len(jobs) and args.delay:
                time.sleep(args.delay)

        show_stats(checkpoint)

    finally:
        checkpoint.close()


if __name__ == "__main__":
    main()
