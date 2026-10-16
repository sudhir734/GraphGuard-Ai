import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import api_destination
import discovery_engine
import enrichment_worker
import graph_config
import graph_queries
import injest_intel
import real_intel
import seed_graph


class ApiDestinationTests(unittest.TestCase):
    def test_accepts_configured_http_base_and_rejects_userinfo(self):
        self.assertEqual(
            api_destination.validate_api_base_url(
                "https://api.example.test:8443/base/"
            ),
            "https://api.example.test:8443/base",
        )
        for value in (
            "ftp://api.example.test",
            "http://user:pass@api.example.test",
            "http://api.example.test/path?next=elsewhere",
            "http://api.example.test/#fragment",
            "http://api.example.test:99999",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                api_destination.validate_api_base_url(value)


class RedactionRegressionTests(unittest.TestCase):
    def test_redacts_top_level_sensitive_nested_values(self):
        result = graph_queries._safe_properties({
            "api_key": {"value": "secret"},
            "metadata": [
                {"access_token": "secret", "label": "safe"},
            ],
        })
        self.assertEqual(result["api_key"], "[REDACTED]")
        self.assertEqual(
            result["metadata"][0]["access_token"],
            "[REDACTED]",
        )
        self.assertEqual(result["metadata"][0]["label"], "safe")


class CheckpointLeaseTests(unittest.TestCase):
    def create_checkpoint(self, path):
        with patch.object(enrichment_worker, "CHECKPOINT_DB", path):
            return enrichment_worker.connect_checkpoint()

    def test_claim_is_atomic_between_connections(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "jobs.sqlite3"
            first = self.create_checkpoint(path)
            second = sqlite3.connect(path, timeout=60)
            try:
                first.execute(
                    "INSERT INTO enrichment_jobs (domain) VALUES (?)",
                    ("claim.test",),
                )
                first.commit()
                self.assertEqual(
                    enrichment_worker.get_pending(first, 1),
                    [("claim.test",)],
                )
                self.assertEqual(enrichment_worker.get_pending(second, 1), [])
                row = first.execute(
                    "SELECT status, attempts, lease_expires_at "
                    "FROM enrichment_jobs WHERE domain = ?",
                    ("claim.test",),
                ).fetchone()
                self.assertEqual(row[:2], ("RUNNING", 1))
                self.assertIsNotNone(row[2])
            finally:
                first.close()
                second.close()

    def test_only_expired_explicit_leases_are_recovered(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = self.create_checkpoint(
                Path(directory) / "jobs.sqlite3"
            )
            try:
                checkpoint.executemany(
                    "INSERT INTO enrichment_jobs "
                    "(domain, status, attempts, lease_expires_at) "
                    "VALUES (?, 'RUNNING', 1, ?)",
                    (
                        ("legacy-running.test", None),
                        ("expired-running.test", "2000-01-01T00:00:00+00:00"),
                    ),
                )
                checkpoint.commit()
                self.assertEqual(
                    enrichment_worker.get_pending(checkpoint, 10),
                    [("expired-running.test",)],
                )
                statuses = dict(checkpoint.execute(
                    "SELECT domain, status FROM enrichment_jobs"
                ).fetchall())
                self.assertEqual(statuses["legacy-running.test"], "RUNNING")
                self.assertEqual(statuses["expired-running.test"], "RUNNING")
            finally:
                checkpoint.close()

    def test_backoff_and_attempt_limit_are_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = self.create_checkpoint(
                Path(directory) / "jobs.sqlite3"
            )
            try:
                checkpoint.execute(
                    "INSERT INTO enrichment_jobs (domain) VALUES (?)",
                    ("backoff.test",),
                )
                checkpoint.commit()
                self.assertEqual(
                    enrichment_worker.get_pending(checkpoint, 1),
                    [("backoff.test",)],
                )
                self.assertEqual(
                    enrichment_worker.finish_retry(
                        checkpoint, "backoff.test", "provider failed"
                    ),
                    "RETRY",
                )
                self.assertEqual(enrichment_worker.get_pending(checkpoint, 1), [])
                checkpoint.execute(
                    "UPDATE enrichment_jobs SET next_attempt_at = ? "
                    "WHERE domain = ?",
                    ("2000-01-01T00:00:00+00:00", "backoff.test"),
                )
                checkpoint.commit()
                self.assertEqual(
                    enrichment_worker.get_pending(checkpoint, 1),
                    [("backoff.test",)],
                )
                checkpoint.execute(
                    "UPDATE enrichment_jobs SET attempts = ? "
                    "WHERE domain = ?",
                    (enrichment_worker.MAX_ATTEMPTS, "backoff.test"),
                )
                checkpoint.commit()
                self.assertEqual(
                    enrichment_worker.finish_retry(
                        checkpoint, "backoff.test", "attempts exhausted"
                    ),
                    "FAILED",
                )
                self.assertEqual(enrichment_worker.get_pending(checkpoint, 1), [])
            finally:
                checkpoint.close()

    def test_checkpoint_adds_lease_columns_without_rewriting_legacy_jobs(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.sqlite3"
            legacy = sqlite3.connect(path)
            legacy.execute("""
                CREATE TABLE enrichment_jobs (
                    domain TEXT PRIMARY KEY,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_attempt TEXT,
                    last_error TEXT,
                    observation_count INTEGER NOT NULL DEFAULT 0
                )
            """)
            legacy.execute(
                "INSERT INTO enrichment_jobs (domain, status) "
                "VALUES ('old.test', 'RUNNING')"
            )
            legacy.commit()
            legacy.close()

            checkpoint = self.create_checkpoint(path)
            try:
                columns = {
                    row[1] for row in checkpoint.execute(
                        "PRAGMA table_info(enrichment_jobs)"
                    )
                }
                self.assertIn("lease_expires_at", columns)
                self.assertIn("next_attempt_at", columns)
                self.assertEqual(
                    enrichment_worker.get_pending(checkpoint, 1),
                    [],
                )
                self.assertEqual(
                    checkpoint.execute(
                        "SELECT status FROM enrichment_jobs "
                        "WHERE domain = 'old.test'"
                    ).fetchone()[0],
                    "RUNNING",
                )
            finally:
                checkpoint.close()


class ProviderOutcomeTests(unittest.TestCase):
    def test_dns_empty_is_distinct_from_all_request_failures(self):
        with patch.object(
            real_intel, "get_json", return_value={"Status": 0, "Answer": []}
        ):
            self.assertEqual(
                real_intel.collect_dns("target.example")["status"],
                "no_records",
            )

        with patch.object(
            real_intel, "get_json", side_effect=TimeoutError("offline")
        ):
            failed = real_intel.collect_dns("target.example")
        self.assertEqual(failed["status"], "unavailable")
        self.assertIn("error", failed)

    def test_dns_mixed_provider_outcomes_are_partial(self):
        responses = [
            {"Status": 0, "Answer": [
                {"data": "203.0.113.7", "TTL": 60},
            ]},
            TimeoutError("offline"),
        ]
        responses.extend([TimeoutError("offline")] * 4)
        with patch.object(real_intel, "get_json", side_effect=responses):
            result = real_intel.collect_dns("target.example")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(len(result["observations"]), 1)

    def test_rdap_404_is_a_valid_empty_result(self):
        failure = HTTPError(
            "https://rdap.org/domain/target.example",
            404,
            "not found",
            {},
            None,
        )
        with patch.object(real_intel, "get_json", side_effect=failure):
            result = real_intel.collect_rdap("target.example")
        self.assertEqual(result["status"], "no_records")
        self.assertEqual(result["observations"], [])

    def test_certificate_one_failed_lookup_is_partial_not_empty(self):
        with patch.object(
            real_intel,
            "get_json",
            side_effect=[[], URLError("offline")],
        ):
            result = real_intel.collect_certificates("target.example")
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["observations"], [])


class IdempotentIngestionTests(unittest.TestCase):
    def test_collection_timestamp_does_not_change_observation_identity(self):
        graph = Mock()
        item = {
            "source": "Cloudflare DNS",
            "kind": "DNS_A",
            "value": "203.0.113.7",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "details": {"ttl": 60},
        }
        injest_intel.ingest_observation(graph, "target.example", item)
        item["observed_at"] = "2026-01-02T00:00:00+00:00"
        injest_intel.ingest_observation(graph, "target.example", item)

        observation_ids = [
            call.args[1]["id"]
            for call in graph.query.call_args_list
            if "MERGE (o:Observation" in call.args[0]
        ]
        self.assertEqual(len(observation_ids), 2)
        self.assertEqual(observation_ids[0], observation_ids[1])


class DiscoverySchemaTests(unittest.TestCase):
    def test_engine_accepts_canonical_discovery_checkpoint_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "discovery.sqlite3"
            conn = sqlite3.connect(database)
            try:
                conn.execute("""
                    CREATE TABLE domains (
                        domain TEXT PRIMARY KEY,
                        source_file TEXT NOT NULL,
                        first_seen TEXT NOT NULL,
                        graph_imported INTEGER NOT NULL DEFAULT 0
                    )
                """)
                conn.execute(
                    "INSERT INTO domains "
                    "(domain, source_file, first_seen) VALUES (?, ?, ?)",
                    ("target.example", "source.txt", "2026-01-01"),
                )
                discovery_engine.init_db(conn)
                row = conn.execute("""
                    SELECT domain, source_file, graph_imported, enriched
                    FROM domains WHERE domain = ?
                """, ("target.example",)).fetchone()
                self.assertEqual(
                    row,
                    ("target.example", "source.txt", 0, 0),
                )
            finally:
                conn.close()


class SharedGraphConfigTests(unittest.TestCase):
    def test_environment_settings_are_shared_and_validated(self):
        with patch.dict("os.environ", {
            "FALKORDB_HOST": "db.internal",
            "FALKORDB_PORT": "6381",
            "FALKORDB_GRAPH": "GraphGuardTest",
        }):
            self.assertEqual(
                graph_config.get_graph_settings(),
                ("db.internal", 6381, "GraphGuardTest"),
            )
        with patch.dict("os.environ", {"FALKORDB_PORT": "70000"}):
            with self.assertRaises(ValueError):
                graph_config.get_graph_settings()


class DemoSeedGuardTests(unittest.TestCase):
    def test_default_production_graph_is_rejected_before_connect(self):
        with patch.dict("os.environ", {"FALKORDB_GRAPH": "GraphGuard"}), \
                patch.object(graph_config, "connect_graph") as connect:
            with self.assertRaises(SystemExit):
                seed_graph.main(["--confirm-demo-graph"])
        connect.assert_not_called()

    def test_explicit_demo_graph_and_confirmation_allow_mocked_write(self):
        graph = Mock()
        with patch.dict(
            "os.environ", {"FALKORDB_GRAPH": "GraphGuardDemo_Test"}
        ), patch.object(
            graph_config, "connect_graph", return_value=graph
        ):
            seed_graph.main(["--confirm-demo-graph"])
        graph.query.assert_called_once()


if __name__ == "__main__":
    unittest.main()
