"""
GraphGuard AI — Resumable Batch Domain Testing and Coverage Engine.

Features:
- Memory-efficient streaming of arbitrarily large domain files (txt, csv, gz).
- Strict DNS normalization, IDNA/Punycode encoding, and Public Suffix List (PSL) validation.
- Preservation of original raw input alongside normalized domain records.
- Deduplication of normalized domains within and across batches.
- Isolated SQLite checkpoint store for crash-resilient, transactional resumption.
- Bounded execution modes:
    * dry-run: syntactic validation, categorization, duplicate detection, and ETA estimation.
    * graph-only: read-only FalkorDB entity & observation queries (zero production mutations).
    * live-passive: bounded DoH, RDAP, crt.sh, URLhaus lookups with strict rate limits.
    * mock: simulated high-throughput testing for 100, 1k, 10k+ scale verification.
- Enforces GraphGuard's conservative uncertainty contract (absence of evidence != safety).
- Machine-readable exports to CSV and JSONL.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Generator, Iterator

import graph_config
import graph_queries
from psl_utils import is_public_suffix, normalize_name, registrable_domain

logger = logging.getLogger("graphguard.domain_batch_audit")

# Defaults
DEFAULT_DB_PATH = Path(__file__).resolve().parent / "domain_batch_audit.sqlite3"
DEFAULT_BATCH_SIZE = 100
DEFAULT_DELAY_SECONDS = 0.5
DEFAULT_TIMEOUT_SECONDS = 8.0
DEFAULT_MAX_ENTITIES = 100
DEFAULT_MAX_DEPTH = 2

# Domain labels and RFC reserved TLDs
LABEL_REGEX = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
RESERVED_TLDS = frozenset({"invalid", "test", "example", "localhost", "local", "internal", "onion"})
DOCUMENTATION_APEXES = frozenset({"example.com", "example.net", "example.org"})


def utc_now() -> str:
    """Return ISO 8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DomainValidationResult:
    raw_input: str
    normalized_domain: str | None
    is_valid: bool
    domain_type: str  # APEX_DOMAIN, SUBDOMAIN, RESERVED_TEST, PUBLIC_SUFFIX_REJECTED, INVALID_SYNTAX, URL_OR_PATH_REJECTED, IP_ADDRESS_REJECTED
    error_message: str | None = None
    registrable_apex: str | None = None
    public_suffix: str | None = None


def validate_and_normalize_domain(raw_value: str) -> DomainValidationResult:
    """
    Validate and normalize a raw domain input string.
    Distinguishes bare public suffixes, URLs, IP addresses, reserved testing names, and subdomains.
    """
    if not isinstance(raw_value, str):
        return DomainValidationResult(
            raw_input=str(raw_value),
            normalized_domain=None,
            is_valid=False,
            domain_type="INVALID_SYNTAX",
            error_message="Expected string input.",
        )

    # Clean raw string
    cleaned = raw_value.strip().strip('"').strip("'")
    if not cleaned or cleaned.startswith(("#", "//", ";")):
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=None,
            is_valid=False,
            domain_type="INVALID_SYNTAX",
            error_message="Empty or commented line.",
        )

    # If format is rank,domain (e.g. Tranco CSV)
    if "," in cleaned:
        parts = cleaned.split(",", 1)
        if parts[0].strip().isdigit():
            cleaned = parts[1].strip().strip('"').strip("'")

    # Reject URLs, schemes, paths, ports
    if any(token in cleaned for token in ("/", "\\", ":", "@", "*", " ")):
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=None,
            is_valid=False,
            domain_type="URL_OR_PATH_REJECTED",
            error_message="Contains URL scheme, path, port, or whitespace.",
        )

    # Reject IP address literals
    try:
        ipaddress.ip_address(cleaned.strip("[]"))
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=None,
            is_valid=False,
            domain_type="IP_ADDRESS_REJECTED",
            error_message="IP address literals are not allowed; domain name expected.",
        )
    except ValueError:
        pass

    # Normalize name (IDNA, lower, strip trailing dot)
    try:
        normalized = normalize_name(cleaned)
    except (ValueError, UnicodeError) as exc:
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=None,
            is_valid=False,
            domain_type="INVALID_SYNTAX",
            error_message=f"Normalization failure: {exc}",
        )

    # Check overall length and bare suffixes
    if len(normalized) > 253 or "." not in normalized:
        if "." not in normalized and is_public_suffix(normalized):
            return DomainValidationResult(
                raw_input=raw_value,
                normalized_domain=normalized,
                is_valid=False,
                domain_type="PUBLIC_SUFFIX_REJECTED",
                error_message="Bare public suffix (TLD/registry suffix) rejected; registrable domain expected.",
            )
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=normalized,
            is_valid=False,
            domain_type="INVALID_SYNTAX",
            error_message="Domain must be between 1 and 253 characters and contain at least one dot.",
        )

    # Check labels
    labels = normalized.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return DomainValidationResult(
                raw_input=raw_value,
                normalized_domain=normalized,
                is_valid=False,
                domain_type="INVALID_SYNTAX",
                error_message="Domain label must be 1-63 characters.",
            )
        if not LABEL_REGEX.fullmatch(label):
            return DomainValidationResult(
                raw_input=raw_value,
                normalized_domain=normalized,
                is_valid=False,
                domain_type="INVALID_SYNTAX",
                error_message=f"Invalid label syntax: {label}",
            )

    # Check reserved / test TLDs
    tld = labels[-1]
    if tld in RESERVED_TLDS or normalized in DOCUMENTATION_APEXES:
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=normalized,
            is_valid=True,
            domain_type="RESERVED_TEST",
            error_message="RFC reserved or documentation name.",
            registrable_apex=registrable_domain(normalized) or normalized,
        )

    # Check Public Suffix List boundaries
    try:
        if is_public_suffix(normalized):
            return DomainValidationResult(
                raw_input=raw_value,
                normalized_domain=normalized,
                is_valid=False,
                domain_type="PUBLIC_SUFFIX_REJECTED",
                error_message="Bare public suffix (TLD/registry suffix) rejected; registrable domain expected.",
            )
        apex = registrable_domain(normalized)
        if apex is None:
            return DomainValidationResult(
                raw_input=raw_value,
                normalized_domain=normalized,
                is_valid=False,
                domain_type="PUBLIC_SUFFIX_REJECTED",
                error_message="Domain does not resolve to a registrable apex below a public suffix.",
            )
    except Exception as exc:
        return DomainValidationResult(
            raw_input=raw_value,
            normalized_domain=normalized,
            is_valid=False,
            domain_type="INVALID_SYNTAX",
            error_message=f"PSL validation error: {exc}",
        )

    # Distinguish apex from subdomain
    domain_type = "APEX_DOMAIN" if normalized == apex else "SUBDOMAIN"

    return DomainValidationResult(
        raw_input=raw_value,
        normalized_domain=normalized,
        is_valid=True,
        domain_type=domain_type,
        error_message=None,
        registrable_apex=apex,
    )


def compute_file_signature(path: Path) -> dict[str, Any]:
    """Compute file size, mtime, and fast SHA-256 for integrity and resume tracking."""
    stat = path.stat()
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        # Read up to 8MB for signature
        chunk = handle.read(8 * 1024 * 1024)
        hasher.update(chunk)
    return {
        "file_path": str(path.resolve()),
        "file_name": path.name,
        "size_bytes": stat.st_size,
        "mtime": stat.st_mtime,
        "sha256_prefix": hasher.hexdigest(),
    }


def stream_domain_lines(path: Path) -> Iterator[tuple[int, str]]:
    """Stream domain lines one by one without loading entire file into memory."""
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path}")

    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8-sig", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            yield line_no, line.strip("\r\n")


class DomainBatchAuditStore:
    """Isolated SQLite persistence store for checkpointing, progress, and audit records."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(str(self.db_path), timeout=60)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_manifests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dataset_name TEXT NOT NULL,
                    source_file TEXT NOT NULL,
                    source_url TEXT,
                    license TEXT,
                    file_size INTEGER NOT NULL,
                    file_sha256 TEXT NOT NULL,
                    total_lines INTEGER DEFAULT 0,
                    unique_domains INTEGER DEFAULT 0,
                    invalid_lines INTEGER DEFAULT 0,
                    duplicate_lines INTEGER DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(source_file, file_sha256)
                );

                CREATE TABLE IF NOT EXISTS domain_audit_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    manifest_id INTEGER NOT NULL REFERENCES audit_manifests(id),
                    line_number INTEGER NOT NULL,
                    raw_input TEXT NOT NULL,
                    normalized_domain TEXT,
                    domain_type TEXT NOT NULL,
                    validation_status TEXT NOT NULL,
                    validation_error TEXT,
                    investigation_status TEXT NOT NULL,
                    assessment_verdict TEXT NOT NULL,
                    data_availability TEXT NOT NULL,
                    evidence_count INTEGER DEFAULT 0,
                    sources_queried_json TEXT DEFAULT '[]',
                    sources_failed_json TEXT DEFAULT '[]',
                    latency_ms REAL DEFAULT 0.0,
                    error_message TEXT,
                    audited_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS checkpoint_state (
                    manifest_id INTEGER PRIMARY KEY REFERENCES audit_manifests(id),
                    last_processed_line INTEGER DEFAULT 0,
                    total_lines_read INTEGER DEFAULT 0,
                    valid_count INTEGER DEFAULT 0,
                    invalid_count INTEGER DEFAULT 0,
                    duplicate_count INTEGER DEFAULT 0,
                    audited_count INTEGER DEFAULT 0,
                    failed_count INTEGER DEFAULT 0,
                    last_updated TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_records_manifest_domain
                    ON domain_audit_records(manifest_id, normalized_domain);

                CREATE INDEX IF NOT EXISTS idx_records_validation
                    ON domain_audit_records(validation_status);

                CREATE INDEX IF NOT EXISTS idx_records_inv_status
                    ON domain_audit_records(investigation_status);
            """)

    def get_or_create_manifest(
        self,
        dataset_name: str,
        path: Path,
        source_url: str | None = None,
        license_str: str | None = None,
    ) -> int:
        sig = compute_file_signature(path)
        now_ts = utc_now()
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id FROM audit_manifests
                WHERE source_file = ? AND file_sha256 = ?
                """,
                (sig["file_path"], sig["sha256_prefix"]),
            ).fetchone()

            if row:
                return int(row["id"])

            cursor = conn.execute(
                """
                INSERT INTO audit_manifests (
                    dataset_name, source_file, source_url, license,
                    file_size, file_sha256, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', ?, ?)
                """,
                (
                    dataset_name,
                    sig["file_path"],
                    source_url,
                    license_str,
                    sig["size_bytes"],
                    sig["sha256_prefix"],
                    now_ts,
                    now_ts,
                ),
            )
            manifest_id = int(cursor.lastrowid)

            conn.execute(
                """
                INSERT OR IGNORE INTO checkpoint_state (
                    manifest_id, last_processed_line, total_lines_read,
                    valid_count, invalid_count, duplicate_count,
                    audited_count, failed_count, last_updated
                ) VALUES (?, 0, 0, 0, 0, 0, 0, 0, ?)
                """,
                (manifest_id, now_ts),
            )
            conn.commit()
            return manifest_id

    def load_checkpoint(self, manifest_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM checkpoint_state WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchone()
            if not row:
                return {
                    "manifest_id": manifest_id,
                    "last_processed_line": 0,
                    "total_lines_read": 0,
                    "valid_count": 0,
                    "invalid_count": 0,
                    "duplicate_count": 0,
                    "audited_count": 0,
                    "failed_count": 0,
                }
            return dict(row)

    def is_domain_already_audited(self, manifest_id: int, normalized_domain: str) -> bool:
        if not normalized_domain:
            return False
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id FROM domain_audit_records
                WHERE manifest_id = ? AND normalized_domain = ?
                  AND validation_status = 'VALID'
                LIMIT 1
                """,
                (manifest_id, normalized_domain),
            ).fetchone()
            return bool(row)

    def commit_batch(
        self,
        manifest_id: int,
        records: list[dict[str, Any]],
        checkpoint_updates: dict[str, Any],
        manifest_status: str = "IN_PROGRESS",
    ) -> None:
        now_ts = utc_now()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany(
                """
                INSERT INTO domain_audit_records (
                    manifest_id, line_number, raw_input, normalized_domain,
                    domain_type, validation_status, validation_error,
                    investigation_status, assessment_verdict, data_availability,
                    evidence_count, sources_queried_json, sources_failed_json,
                    latency_ms, error_message, audited_at
                ) VALUES (
                    :manifest_id, :line_number, :raw_input, :normalized_domain,
                    :domain_type, :validation_status, :validation_error,
                    :investigation_status, :assessment_verdict, :data_availability,
                    :evidence_count, :sources_queried_json, :sources_failed_json,
                    :latency_ms, :error_message, :audited_at
                )
                """,
                records,
            )

            conn.execute(
                """
                UPDATE checkpoint_state
                SET last_processed_line = ?,
                    total_lines_read = total_lines_read + ?,
                    valid_count = valid_count + ?,
                    invalid_count = invalid_count + ?,
                    duplicate_count = duplicate_count + ?,
                    audited_count = audited_count + ?,
                    failed_count = failed_count + ?,
                    last_updated = ?
                WHERE manifest_id = ?
                """,
                (
                    checkpoint_updates["last_processed_line"],
                    checkpoint_updates.get("lines_in_batch", 0),
                    checkpoint_updates.get("valid_in_batch", 0),
                    checkpoint_updates.get("invalid_in_batch", 0),
                    checkpoint_updates.get("duplicate_in_batch", 0),
                    checkpoint_updates.get("audited_in_batch", 0),
                    checkpoint_updates.get("failed_in_batch", 0),
                    now_ts,
                    manifest_id,
                ),
            )

            conn.execute(
                """
                UPDATE audit_manifests
                SET status = ?,
                    total_lines = (SELECT total_lines_read FROM checkpoint_state WHERE manifest_id = ?),
                    unique_domains = (SELECT audited_count FROM checkpoint_state WHERE manifest_id = ?),
                    invalid_lines = (SELECT invalid_count FROM checkpoint_state WHERE manifest_id = ?),
                    duplicate_lines = (SELECT duplicate_count FROM checkpoint_state WHERE manifest_id = ?),
                    updated_at = ?
                WHERE id = ?
                """,
                (
                    manifest_status,
                    manifest_id,
                    manifest_id,
                    manifest_id,
                    manifest_id,
                    now_ts,
                    manifest_id,
                ),
            )
            conn.commit()

    def get_summary_statistics(self, manifest_id: int | None = None) -> dict[str, Any]:
        with self._connect() as conn:
            where_clause = "WHERE manifest_id = ?" if manifest_id else ""
            params = (manifest_id,) if manifest_id else ()

            totals = conn.execute(
                f"""
                SELECT
                    count(*) as total_records,
                    sum(case when validation_status = 'VALID' then 1 else 0 end) as valid_records,
                    sum(case when validation_status = 'INVALID' then 1 else 0 end) as invalid_records,
                    sum(case when validation_status = 'SKIPPED_DUPLICATE' then 1 else 0 end) as duplicate_records,
                    sum(case when investigation_status = 'INVESTIGATED' then 1 else 0 end) as investigated_count,
                    sum(case when investigation_status = 'NOT_FOUND' then 1 else 0 end) as not_found_count,
                    sum(case when investigation_status = 'NO_EVIDENCE_FOUND' then 1 else 0 end) as no_evidence_count,
                    sum(case when investigation_status = 'PARTIALLY_ASSESSED' then 1 else 0 end) as partial_count,
                    sum(case when investigation_status = 'SOURCE_UNAVAILABLE' then 1 else 0 end) as unavailable_count,
                    sum(case when investigation_status = 'NOT_ASSESSED' then 1 else 0 end) as not_assessed_count,
                    sum(case when investigation_status = 'DRY_RUN' then 1 else 0 end) as dry_run_count,
                    sum(case when investigation_status = 'MOCK_AUDITED' then 1 else 0 end) as mock_count,
                    avg(latency_ms) as avg_latency_ms
                FROM domain_audit_records
                {where_clause}
                """,
                params,
            ).fetchone()

            manifest_info = None
            if manifest_id:
                m_row = conn.execute(
                    "SELECT * FROM audit_manifests WHERE id = ?", (manifest_id,)
                ).fetchone()
                if m_row:
                    manifest_info = dict(m_row)

            return {
                "manifest": manifest_info,
                "counts": dict(totals) if totals else {},
            }


class DomainBatchAuditEngine:
    """
    Core executor for running domain batch audits.
    Supports dry-run, graph-only, live-passive, and mock audit modes.
    """

    def __init__(
        self,
        store: DomainBatchAuditStore | None = None,
        db_path: Path = DEFAULT_DB_PATH,
    ):
        self.store = store or DomainBatchAuditStore(db_path)

    def run_audit(
        self,
        input_path: Path,
        dataset_name: str | None = None,
        mode: str = "graph-only",  # 'dry-run', 'graph-only', 'live-passive', 'mock'
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_domains: int | None = None,
        delay: float = DEFAULT_DELAY_SECONDS,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        retest: bool = False,
        source_url: str | None = None,
        license_str: str | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any]:
        """
        Execute or resume a batch audit against input_path.
        """
        input_path = Path(input_path)
        if not input_path.is_file():
            raise FileNotFoundError(f"Input file not found: {input_path}")

        dataset_name = dataset_name or input_path.stem
        manifest_id = self.store.get_or_create_manifest(
            dataset_name=dataset_name,
            path=input_path,
            source_url=source_url,
            license_str=license_str,
        )

        checkpoint = self.store.load_checkpoint(manifest_id)
        start_line = 0 if retest else checkpoint["last_processed_line"]

        logger.info(
            "Starting audit on %s (Manifest ID: %d, Mode: %s, Resuming after line: %d)",
            input_path.name,
            manifest_id,
            mode,
            start_line,
        )

        batch_records: list[dict[str, Any]] = []
        seen_domains_in_session: set[str] = set()

        processed_this_run = 0
        valid_this_run = 0
        invalid_this_run = 0
        duplicates_this_run = 0
        audited_this_run = 0
        failed_this_run = 0

        start_time = time.time()
        last_line_seen = start_line

        try:
            for line_no, raw_line in stream_domain_lines(input_path):
                if line_no <= start_line:
                    continue

                last_line_seen = line_no
                val_result = validate_and_normalize_domain(raw_line)
                norm_domain = val_result.normalized_domain
                now_str = utc_now()

                if not val_result.is_valid:
                    invalid_this_run += 1
                    batch_records.append({
                        "manifest_id": manifest_id,
                        "line_number": line_no,
                        "raw_input": raw_line,
                        "normalized_domain": norm_domain,
                        "domain_type": val_result.domain_type,
                        "validation_status": "INVALID",
                        "validation_error": val_result.error_message,
                        "investigation_status": "NOT_ASSESSED",
                        "assessment_verdict": "NOT_ASSESSED",
                        "data_availability": "UNAVAILABLE",
                        "evidence_count": 0,
                        "sources_queried_json": "[]",
                        "sources_failed_json": "[]",
                        "latency_ms": 0.0,
                        "error_message": val_result.error_message,
                        "audited_at": now_str,
                    })
                else:
                    valid_this_run += 1

                    # Check for duplicate in session or SQLite store
                    is_dup = (
                        norm_domain in seen_domains_in_session
                        or (not retest and self.store.is_domain_already_audited(manifest_id, norm_domain))
                    )

                    if is_dup:
                        duplicates_this_run += 1
                        batch_records.append({
                            "manifest_id": manifest_id,
                            "line_number": line_no,
                            "raw_input": raw_line,
                            "normalized_domain": norm_domain,
                            "domain_type": val_result.domain_type,
                            "validation_status": "SKIPPED_DUPLICATE",
                            "validation_error": "Domain already processed in this manifest.",
                            "investigation_status": "NOT_ASSESSED",
                            "assessment_verdict": "NOT_ASSESSED",
                            "data_availability": "AVAILABLE" if mode == "graph-only" else "UNAVAILABLE",
                            "evidence_count": 0,
                            "sources_queried_json": "[]",
                            "sources_failed_json": "[]",
                            "latency_ms": 0.0,
                            "error_message": None,
                            "audited_at": now_str,
                        })
                    else:
                        seen_domains_in_session.add(norm_domain)
                        audited_this_run += 1

                        # Perform investigation according to mode
                        inv_res = self._execute_domain_investigation(
                            domain=norm_domain,
                            mode=mode,
                            val_result=val_result,
                            timeout=timeout,
                        )

                        batch_records.append({
                            "manifest_id": manifest_id,
                            "line_number": line_no,
                            "raw_input": raw_line,
                            "normalized_domain": norm_domain,
                            "domain_type": val_result.domain_type,
                            "validation_status": "VALID",
                            "validation_error": None,
                            "investigation_status": inv_res["investigation_status"],
                            "assessment_verdict": inv_res["assessment_verdict"],
                            "data_availability": inv_res["data_availability"],
                            "evidence_count": inv_res["evidence_count"],
                            "sources_queried_json": json.dumps(inv_res["sources_queried"]),
                            "sources_failed_json": json.dumps(inv_res["sources_failed"]),
                            "latency_ms": inv_res["latency_ms"],
                            "error_message": inv_res.get("error_message"),
                            "audited_at": now_str,
                        })

                        if mode == "live-passive" and delay > 0:
                            time.sleep(delay)

                processed_this_run += 1

                # Commit batch if threshold reached
                if len(batch_records) >= batch_size:
                    self._commit_current_batch(
                        manifest_id=manifest_id,
                        records=batch_records,
                        last_line=line_no,
                    )
                    batch_records.clear()

                    if progress_callback:
                        progress_callback({
                            "manifest_id": manifest_id,
                            "last_line": line_no,
                            "processed": processed_this_run,
                            "valid": valid_this_run,
                            "invalid": invalid_this_run,
                            "duplicates": duplicates_this_run,
                            "audited": audited_this_run,
                            "elapsed_seconds": time.time() - start_time,
                        })

                if max_domains and audited_this_run >= max_domains:
                    logger.info("Reached configured max_domains cap (%d)", max_domains)
                    break

            # Commit trailing batch
            if batch_records:
                self._commit_current_batch(
                    manifest_id=manifest_id,
                    records=batch_records,
                    last_line=last_line_seen,
                    manifest_status="COMPLETED",
                )
                batch_records.clear()
            else:
                # Update manifest to completed if all lines processed
                self.store.commit_batch(
                    manifest_id=manifest_id,
                    records=[],
                    checkpoint_updates={"last_processed_line": last_line_seen},
                    manifest_status="COMPLETED",
                )

        except KeyboardInterrupt:
            logger.warning("Audit interrupted by user. Committing buffered state...")
            if batch_records:
                self._commit_current_batch(
                    manifest_id=manifest_id,
                    records=batch_records,
                    last_line=last_line_seen,
                    manifest_status="INTERRUPTED",
                )
            raise

        elapsed = time.time() - start_time
        summary = self.store.get_summary_statistics(manifest_id)

        return {
            "manifest_id": manifest_id,
            "dataset_name": dataset_name,
            "mode": mode,
            "elapsed_seconds": round(elapsed, 3),
            "processed_this_run": processed_this_run,
            "valid_this_run": valid_this_run,
            "invalid_this_run": invalid_this_run,
            "duplicates_this_run": duplicates_this_run,
            "audited_this_run": audited_this_run,
            "throughput_domains_per_sec": round(
                processed_this_run / elapsed if elapsed > 0 else 0.0, 2
            ),
            "statistics": summary,
        }

    def _commit_current_batch(
        self,
        manifest_id: int,
        records: list[dict[str, Any]],
        last_line: int,
        manifest_status: str = "IN_PROGRESS",
    ) -> None:
        valid_count = sum(1 for r in records if r["validation_status"] == "VALID")
        invalid_count = sum(1 for r in records if r["validation_status"] == "INVALID")
        dup_count = sum(1 for r in records if r["validation_status"] == "SKIPPED_DUPLICATE")
        audited_count = valid_count
        failed_count = sum(
            1 for r in records if r["investigation_status"] in {"SOURCE_UNAVAILABLE", "FAILED"}
        )

        updates = {
            "last_processed_line": last_line,
            "lines_in_batch": len(records),
            "valid_in_batch": valid_count,
            "invalid_in_batch": invalid_count,
            "duplicate_in_batch": dup_count,
            "audited_in_batch": audited_count,
            "failed_in_batch": failed_count,
        }
        self.store.commit_batch(
            manifest_id=manifest_id,
            records=records,
            checkpoint_updates=updates,
            manifest_status=manifest_status,
        )

    def _execute_domain_investigation(
        self,
        domain: str,
        mode: str,
        val_result: DomainValidationResult,
        timeout: float,
    ) -> dict[str, Any]:
        """Execute domain lookup according to the selected mode."""
        start = time.perf_counter()

        if mode == "dry-run":
            latency = (time.perf_counter() - start) * 1000.0
            return {
                "investigation_status": "DRY_RUN",
                "assessment_verdict": "NOT_ASSESSED",
                "data_availability": "UNAVAILABLE",
                "evidence_count": 0,
                "sources_queried": ["syntax_validator"],
                "sources_failed": [],
                "latency_ms": round(latency, 2),
                "error_message": None,
            }

        elif mode == "mock":
            # Deterministic mock responses for scale testing
            latency = (time.perf_counter() - start) * 1000.0
            if "malformed" in domain or "fail" in domain:
                return {
                    "investigation_status": "SOURCE_UNAVAILABLE",
                    "assessment_verdict": "NOT_ASSESSED",
                    "data_availability": "UNAVAILABLE",
                    "evidence_count": 0,
                    "sources_queried": ["mock_dns", "mock_rdap"],
                    "sources_failed": ["mock_rdap"],
                    "latency_ms": round(latency + 1.2, 2),
                    "error_message": "Simulated mock provider failure",
                }
            return {
                "investigation_status": "MOCK_AUDITED",
                "assessment_verdict": "NOT_ASSESSED",
                "data_availability": "AVAILABLE",
                "evidence_count": 2,
                "sources_queried": ["mock_dns", "mock_rdap", "mock_ct"],
                "sources_failed": [],
                "latency_ms": round(latency + 0.5, 2),
                "error_message": None,
            }

        elif mode == "graph-only":
            try:
                # Read-only query to FalkorDB
                graph_res = graph_queries.investigate_domain(
                    domain=domain,
                    max_depth=DEFAULT_MAX_DEPTH,
                    max_entities=DEFAULT_MAX_ENTITIES,
                )
                latency = (time.perf_counter() - start) * 1000.0
                found = graph_res.get("found", False)
                evidence = graph_res.get("evidence", [])
                evidence_count = len(evidence)

                if not found:
                    inv_status = "NOT_FOUND"
                    data_avail = "NOT_FOUND"
                elif not evidence:
                    inv_status = "NO_EVIDENCE_FOUND"
                    data_avail = "AVAILABLE"
                else:
                    inv_status = "INVESTIGATED"
                    data_avail = "AVAILABLE"

                return {
                    "investigation_status": inv_status,
                    "assessment_verdict": "NOT_ASSESSED",
                    "data_availability": data_avail,
                    "evidence_count": evidence_count,
                    "sources_queried": ["falkordb_read_only"],
                    "sources_failed": [],
                    "latency_ms": round(latency, 2),
                    "error_message": None,
                }
            except Exception as exc:
                latency = (time.perf_counter() - start) * 1000.0
                return {
                    "investigation_status": "SOURCE_UNAVAILABLE",
                    "assessment_verdict": "NOT_ASSESSED",
                    "data_availability": "UNAVAILABLE",
                    "evidence_count": 0,
                    "sources_queried": ["falkordb_read_only"],
                    "sources_failed": ["falkordb_read_only"],
                    "latency_ms": round(latency, 2),
                    "error_message": str(exc),
                }

        elif mode == "live-passive":
            # Bounded passive queries using real_intel
            try:
                import real_intel
                collected, statuses = real_intel.collect_public_intel(domain)
                latency = (time.perf_counter() - start) * 1000.0

                queried = [s["source"] for s in statuses]
                failed = [s["source"] for s in statuses if s.get("status") in {"error", "timeout", "unavailable"}]

                if not statuses or len(failed) == len(queried):
                    inv_status = "SOURCE_UNAVAILABLE"
                elif failed:
                    inv_status = "PARTIALLY_ASSESSED"
                elif not collected:
                    inv_status = "NO_EVIDENCE_FOUND"
                else:
                    inv_status = "INVESTIGATED"

                return {
                    "investigation_status": inv_status,
                    "assessment_verdict": "NOT_ASSESSED",
                    "data_availability": "AVAILABLE" if collected else "NOT_FOUND",
                    "evidence_count": len(collected),
                    "sources_queried": queried,
                    "sources_failed": failed,
                    "latency_ms": round(latency, 2),
                    "error_message": None if not failed else f"Failed sources: {', '.join(failed)}",
                }
            except Exception as exc:
                latency = (time.perf_counter() - start) * 1000.0
                return {
                    "investigation_status": "SOURCE_UNAVAILABLE",
                    "assessment_verdict": "NOT_ASSESSED",
                    "data_availability": "UNAVAILABLE",
                    "evidence_count": 0,
                    "sources_queried": ["real_intel"],
                    "sources_failed": ["real_intel"],
                    "latency_ms": round(latency, 2),
                    "error_message": str(exc),
                }

        else:
            raise ValueError(f"Unknown audit mode: {mode}")

    def export_csv(self, manifest_id: int, output_path: Path) -> int:
        """Export audited domain records to CSV file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        count = 0

        with self.store._connect() as conn:
            cursor = conn.execute(
                """
                SELECT
                    line_number, raw_input, normalized_domain, domain_type,
                    validation_status, validation_error, investigation_status,
                    assessment_verdict, data_availability, evidence_count,
                    sources_queried_json, sources_failed_json, latency_ms,
                    error_message, audited_at
                FROM domain_audit_records
                WHERE manifest_id = ?
                ORDER BY line_number ASC
                """,
                (manifest_id,),
            )

            fieldnames = [
                "line_number",
                "raw_input",
                "normalized_domain",
                "domain_type",
                "validation_status",
                "validation_error",
                "investigation_status",
                "assessment_verdict",
                "data_availability",
                "evidence_count",
                "sources_queried",
                "sources_failed",
                "latency_ms",
                "error_message",
                "audited_at",
            ]

            with output_path.open("w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for row in cursor:
                    row_dict = dict(row)
                    row_dict["sources_queried"] = ",".join(json.loads(row_dict.pop("sources_queried_json") or "[]"))
                    row_dict["sources_failed"] = ",".join(json.loads(row_dict.pop("sources_failed_json") or "[]"))
                    writer.writerow(row_dict)
                    count += 1

        return count

    def export_jsonl(self, manifest_id: int, output_path: Path) -> int:
        """Export audited domain records to JSONL file."""
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        count = 0

        with self.store._connect() as conn:
            cursor = conn.execute(
                """
                SELECT
                    manifest_id, line_number, raw_input, normalized_domain,
                    domain_type, validation_status, validation_error,
                    investigation_status, assessment_verdict, data_availability,
                    evidence_count, sources_queried_json, sources_failed_json,
                    latency_ms, error_message, audited_at
                FROM domain_audit_records
                WHERE manifest_id = ?
                ORDER BY line_number ASC
                """,
                (manifest_id,),
            )

            with output_path.open("w", encoding="utf-8") as f:
                for row in cursor:
                    item = dict(row)
                    item["sources_queried"] = json.loads(item.pop("sources_queried_json") or "[]")
                    item["sources_failed"] = json.loads(item.pop("sources_failed_json") or "[]")
                    f.write(json.dumps(item) + "\n")
                    count += 1

        return count


def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GraphGuard AI — Resumable Batch Domain Testing and Coverage Engine"
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Path to UTF-8 text file with one domain per line or CSV file.",
    )
    parser.add_argument(
        "--name",
        type=str,
        default=None,
        help="Optional dataset name (defaults to input file stem).",
    )
    parser.add_argument(
        "--mode",
        choices=["dry-run", "graph-only", "live-passive", "mock"],
        default="graph-only",
        help="Audit mode (default: graph-only).",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=f"Batch size for SQLite checkpoint transactions (default: {DEFAULT_BATCH_SIZE}).",
    )
    parser.add_argument(
        "--max-domains",
        type=int,
        default=None,
        help="Cap maximum valid domains to audit in this run.",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=DEFAULT_DELAY_SECONDS,
        help=f"Delay between queries in live-passive mode (default: {DEFAULT_DELAY_SECONDS}s).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS}s).",
    )
    parser.add_argument(
        "--retest",
        action="store_true",
        help="Retest domains from line 1 instead of resuming from checkpoint.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"Path to SQLite checkpoint database (default: {DEFAULT_DB_PATH}).",
    )
    parser.add_argument(
        "--export-csv",
        type=Path,
        default=None,
        help="Optional path to export audit results to CSV.",
    )
    parser.add_argument(
        "--export-jsonl",
        type=Path,
        default=None,
        help="Optional path to export audit results to JSONL.",
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default=None,
        help="Source URL or origin documentation for this dataset.",
    )
    parser.add_argument(
        "--license",
        type=str,
        default=None,
        help="License or usage restrictions of this dataset.",
    )
    return parser


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    parser = build_cli()
    args = parser.parse_args()

    engine = DomainBatchAuditEngine(db_path=args.db)

    print("=" * 70)
    print("GraphGuard AI — Comprehensive Domain Batch Audit Engine")
    print("=" * 70)
    print(f"Input file:       {args.input}")
    print(f"Audit mode:       {args.mode}")
    print(f"Batch size:       {args.batch_size}")
    print(f"Retest:           {args.retest}")
    print(f"Checkpoint store: {args.db}")
    print("-" * 70)

    def print_progress(info: dict[str, Any]) -> None:
        print(
            f"[PROGRESS] Line: {info['last_line']} | Processed: {info['processed']} "
            f"| Valid: {info['valid']} | Invalid: {info['invalid']} "
            f"| Duplicates: {info['duplicates']} | Rate: {info['processed'] / max(info['elapsed_seconds'], 0.1):.1f} d/s"
        )

    result = engine.run_audit(
        input_path=args.input,
        dataset_name=args.name,
        mode=args.mode,
        batch_size=args.batch_size,
        max_domains=args.max_domains,
        delay=args.delay,
        timeout=args.timeout,
        retest=args.retest,
        source_url=args.source_url,
        license_str=args.license,
        progress_callback=print_progress,
    )

    manifest_id = result["manifest_id"]
    stats = result["statistics"]["counts"]

    print("=" * 70)
    print("Audit Complete!")
    print("=" * 70)
    print(f"Manifest ID:      {manifest_id}")
    print(f"Elapsed time:     {result['elapsed_seconds']}s")
    print(f"Total processed:  {result['processed_this_run']}")
    print(f"Unique audited:   {result['audited_this_run']}")
    print(f"Invalid inputs:   {result['invalid_this_run']}")
    print(f"Duplicates:       {result['duplicates_this_run']}")
    print(f"Throughput:       {result['throughput_domains_per_sec']} domains/sec")
    print("-" * 70)
    print("Investigation Status Breakdown:")
    for key, val in stats.items():
        if key.endswith("_count") and val > 0:
            print(f"  * {key.replace('_count', '').upper()}: {val}")
    print("-" * 70)

    if args.export_csv:
        count = engine.export_csv(manifest_id, args.export_csv)
        print(f"Exported {count} records to CSV: {args.export_csv}")

    if args.export_jsonl:
        count = engine.export_jsonl(manifest_id, args.export_jsonl)
        print(f"Exported {count} records to JSONL: {args.export_jsonl}")


if __name__ == "__main__":
    main()
