
import argparse
import hashlib
import json
import ipaddress
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import graph_config


GRAPH_NAME = graph_config.get_graph_settings()[2]
DEFAULT_INPUT = Path("domains.txt")
CHECKPOINT_FILE = Path("bulk_ingest_checkpoint.json")
BATCH_SIZE = 500

DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9-]+$")


def normalize_domain(raw):
    """Return a normalized DNS hostname, or None if invalid."""
    value = raw.strip().lower().rstrip(".")

    if not value or value.startswith("#"):
        return None

    # A domain list should contain hostnames, not URLs or paths.
    if any(ch in value for ch in ("/", "\\", ":", "@", "*")):
        return None

    try:
        value = value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None

    if len(value) > 253 or "." not in value:
        return None

    # Exclude IP address literals.
    try:
        ipaddress.ip_address(value)
        return None
    except ValueError:
        pass

    labels = value.split(".")

    for label in labels:
        if not label or len(label) > 63:
            return None
        if not DOMAIN_LABEL_RE.fullmatch(label):
            return None
        if label.startswith("-") or label.endswith("-"):
            return None

    return value


def file_signature(path):
    stat = path.stat()
    return {
        "path": str(path.resolve()),
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
    }


def load_checkpoint(path, signature, restart):
    if restart or not path.exists():
        return {
            "signature": signature,
            "line_number": 0,
            "valid_lines": 0,
            "invalid_lines": 0,
            "batches_committed": 0,
        }

    state = json.loads(path.read_text(encoding="utf-8"))

    if state.get("signature") != signature:
        raise RuntimeError(
            "The input file changed since the last checkpoint. "
            "Use --restart to begin again with this file."
        )

    return state



def save_checkpoint(path, state):
    # Write directly to the checkpoint file to avoid Windows
    # rename/replace permission errors.
    with path.open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2)
        handle.flush()



def connect_graph():
    return graph_config.connect_graph()


def ingest_batch(graph, rows):
    """
    Idempotently create domain records and source provenance.
    One Cypher query handles the entire batch.
    """
    query = """
    UNWIND $rows AS row
    MERGE (d:Domain {name: row.domain})
    ON CREATE SET d.first_seen = row.collected_at
    SET d.last_seen = row.collected_at
    MERGE (s:Source {name: row.source})
    MERGE (d)-[:DISCOVERED_FROM]->(s)
    """

    graph.query(query, {"rows": rows})


def run_import(input_path, source, batch_size, restart):
    if not input_path.is_file():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    if batch_size < 1 or batch_size > 5000:
        raise ValueError("Batch size must be between 1 and 5000.")

    signature = file_signature(input_path)
    state = load_checkpoint(
        CHECKPOINT_FILE, signature, restart
    )

    start_line = state["line_number"]
    batch = []
    batch_seen = set()
    seen_in_batch = 0
    committed_domains = 0
    invalid_this_run = 0
    line_number = 0

    graph = connect_graph()

    print(f"Graph: {GRAPH_NAME}")
    print(f"Input: {input_path}")
    print(f"Source label: {source}")
    print(f"Resuming after line: {start_line}")

    def commit_batch():
        nonlocal committed_domains, batch

        if not batch:
            return

        collected_at = datetime.now(
            timezone.utc
        ).isoformat()

        rows = [
            {
                "domain": domain,
                "source": source,
                "collected_at": collected_at,
            }
            for domain in batch
        ]

        ingest_batch(graph, rows)

        committed_domains += len(batch)
        state["batches_committed"] += 1
        batch.clear()
        batch_seen.clear()

        save_checkpoint(CHECKPOINT_FILE, state)

        print(
            f"Checkpoint: line {state['line_number']}; "
            f"new unique domains submitted this run: "
            f"{committed_domains}"
        )

    with input_path.open(
        "r", encoding="utf-8-sig", errors="replace"
    ) as handle:
        for line_number, line in enumerate(handle, start=1):
            if line_number <= start_line:
                continue

            state["line_number"] = line_number
            domain = normalize_domain(line)

            if domain is None:
                invalid_this_run += 1
                state["invalid_lines"] += 1
                continue

            state["valid_lines"] += 1

            if domain in batch_seen:
                continue

            batch_seen.add(domain)
            batch.append(domain)
            seen_in_batch += 1

            if len(batch) >= batch_size:
                commit_batch()

    # Commit remaining domains and checkpoint even when the
    # final lines were invalid or comments.
    commit_batch()
    save_checkpoint(CHECKPOINT_FILE, state)

    print("\nImport finished.")
    print(f"Valid domain lines encountered this run: {seen_in_batch}")
    print(f"Invalid/comment lines this run: {invalid_this_run}")
    print(f"Unique domains submitted this run: {committed_domains}")
    print(f"Checkpoint: {CHECKPOINT_FILE}")
    print("Note: MERGE prevents duplicate Domain nodes by name.")
    print("This import does not assess domains for maliciousness.")


def main():
    parser = argparse.ArgumentParser(
        description="Bulk-import domain names into FalkorDB."
    )
    parser.add_argument(
        "--input", default=str(DEFAULT_INPUT),
        help="Text file containing one domain per line.",
    )
    parser.add_argument(
        "--source", default="Public domain dataset",
        help="Dataset/source label recorded in the graph.",
    )
    parser.add_argument(
        "--batch-size", type=int, default=BATCH_SIZE,
        help="Domains per Cypher batch (1-5000).",
    )
    parser.add_argument(
        "--restart", action="store_true",
        help="Restart from line 1 and reset the checkpoint.",
    )

    args = parser.parse_args()

    run_import(
        Path(args.input),
        args.source,
        args.batch_size,
        args.restart,
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Bulk import failed: {exc}", file=sys.stderr)
        sys.exit(1)
