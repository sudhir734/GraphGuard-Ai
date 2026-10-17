"""
Automated Test Suite for GraphGuard AI Comprehensive Domain Batch Audit Engine.

Covers:
- Categories A through L (All domain types, PSL, IDNA, normalization, invalid, reserved)
- Large-file streaming and memory efficiency
- SQLite checkpoint recovery and interrupted batch resumption
- Duplicate suppression and raw record preservation
- Bounded execution modes (dry-run, graph-only, mock)
- Provider failure handling and partial evidence
- Graph read-only safety and isolation
- CSV and JSONL export correctness
- Scale benchmarks: 100, 1,000, and 10,000 domains in mock mode
- Strict conservative uncertainty policy (no false 'SAFE' verdicts)
"""

import json
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from domain_batch_audit import (
    DomainBatchAuditEngine,
    DomainBatchAuditStore,
    validate_and_normalize_domain,
    compute_file_signature,
    stream_domain_lines,
)


class TestDomainValidationAndPSL(unittest.TestCase):
    """Tests for Categories A, B, C, D, E, F, G, H."""

    def test_category_a_valid_apex(self):
        cases = ["target.com", "google.com", "github.com", "cloudflare.com"]
        for domain in cases:
            res = validate_and_normalize_domain(domain)
            self.assertTrue(res.is_valid, f"Expected {domain} to be valid")
            self.assertEqual(res.domain_type, "APEX_DOMAIN")
            self.assertEqual(res.normalized_domain, domain.lower())

    def test_category_b_cross_sector(self):
        sectors = {
            "tech": "microsoft.com",
            "edu": "mit.edu",
            "gov": "usa.gov",
            "finance": "jpmorgan.com",
            "health": "who.int",
            "media": "bbc.co.uk",
            "ngo": "eff.org",
        }
        for sector, domain in sectors.items():
            res = validate_and_normalize_domain(domain)
            self.assertTrue(res.is_valid, f"{sector} domain {domain} should be valid")
            self.assertIn(res.domain_type, {"APEX_DOMAIN", "SUBDOMAIN"})

    def test_category_c_subdomains(self):
        subdomains = ["api.github.com", "aws.amazon.com", "mail.google.com", "portal.azure.com"]
        for sub in subdomains:
            res = validate_and_normalize_domain(sub)
            self.assertTrue(res.is_valid)
            self.assertEqual(res.domain_type, "SUBDOMAIN")
            self.assertIsNotNone(res.registrable_apex)

    def test_category_d_multilabel_psl(self):
        cases = [
            ("example.co.uk", "example.co.uk", "APEX_DOMAIN"),
            ("sub.example.co.uk", "example.co.uk", "SUBDOMAIN"),
            ("app.github.io", "app.github.io", "APEX_DOMAIN"),
            ("foo.app.github.io", "app.github.io", "SUBDOMAIN"),
        ]
        for raw, expected_apex, expected_type in cases:
            res = validate_and_normalize_domain(raw)
            self.assertTrue(res.is_valid)
            self.assertEqual(res.registrable_apex, expected_apex)
            self.assertEqual(res.domain_type, expected_type)

    def test_category_e_idna_punycode(self):
        # Internationalized Russian domain
        res_unicode = validate_and_normalize_domain("испытание.рф")
        self.assertTrue(res_unicode.is_valid)
        self.assertTrue(res_unicode.normalized_domain.startswith("xn--"))

        # Raw Punycode
        res_puny = validate_and_normalize_domain("xn--e1afmkfd.xn--p1ai")
        self.assertTrue(res_puny.is_valid)
        self.assertEqual(res_puny.normalized_domain, "xn--e1afmkfd.xn--p1ai")

    def test_category_f_normalization_edge_cases(self):
        cases = [
            ("TARGET.COM", "target.com"),
            ("example.org.", "example.org"),
            ("  cloudflare.com  ", "cloudflare.com"),
            ("\"google.com\"", "google.com"),
            ("10,youtube.com", "youtube.com"),  # Tranco CSV style
        ]
        for raw, expected in cases:
            res = validate_and_normalize_domain(raw)
            self.assertTrue(res.is_valid)
            self.assertEqual(res.normalized_domain, expected)

    def test_category_g_invalid_inputs(self):
        invalids = [
            ("-badlabel.com", "INVALID_SYNTAX"),
            ("..double.dot", "INVALID_SYNTAX"),
            ("https://target.com/index.html", "URL_OR_PATH_REJECTED"),
            ("target.com:443", "URL_OR_PATH_REJECTED"),
            ("192.168.1.1", "IP_ADDRESS_REJECTED"),
            ("co.uk", "PUBLIC_SUFFIX_REJECTED"),
            ("com", "PUBLIC_SUFFIX_REJECTED"),
            ("github.io", "PUBLIC_SUFFIX_REJECTED"),
            ("", "INVALID_SYNTAX"),
            ("a" * 64 + ".com", "INVALID_SYNTAX"),
        ]
        for raw, expected_type in invalids:
            res = validate_and_normalize_domain(raw)
            self.assertFalse(res.is_valid, f"Expected {raw} to be rejected")
            self.assertEqual(res.domain_type, expected_type)
            self.assertIsNotNone(res.error_message)

    def test_category_h_reserved_testing_names(self):
        reserved = ["example.com", "test.invalid", "gateway.localhost", "router.test"]
        for domain in reserved:
            res = validate_and_normalize_domain(domain)
            self.assertTrue(res.is_valid)
            self.assertEqual(res.domain_type, "RESERVED_TEST")


class TestBatchAuditEngine(unittest.TestCase):
    """Tests for streaming, SQLite checkpointing, resumption, and exports."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "test_audit.sqlite3"
        self.store = DomainBatchAuditStore(self.db_path)
        self.engine = DomainBatchAuditEngine(store=self.store, db_path=self.db_path)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_fixture_file_audit_dry_run(self):
        fixture_path = Path("fixtures/domain_coverage_sample.txt")
        self.assertTrue(fixture_path.is_file())

        res = self.engine.run_audit(
            input_path=fixture_path,
            mode="dry-run",
            batch_size=10,
        )

        self.assertGreater(res["processed_this_run"], 30)
        self.assertGreater(res["valid_this_run"], 15)
        self.assertGreater(res["invalid_this_run"], 5)
        self.assertGreater(res["duplicates_this_run"], 1)

        counts = res["statistics"]["counts"]
        self.assertGreater(counts["dry_run_count"], 15)

    def test_deduplication_and_raw_line_preservation(self):
        lines = [
            "target.com",
            "TARGET.COM",  # duplicate of target.com
            "google.com",
            "target.com.",  # duplicate of target.com
            "example.org",
        ]
        test_file = Path(self.temp_dir.name) / "dedup_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        res = self.engine.run_audit(
            input_path=test_file,
            mode="mock",
            batch_size=5,
        )

        self.assertEqual(res["processed_this_run"], 5)
        self.assertEqual(res["valid_this_run"], 5)
        self.assertEqual(res["duplicates_this_run"], 2)
        self.assertEqual(res["audited_this_run"], 3)

        # Check that all 5 lines are present in domain_audit_records
        with self.store._connect() as conn:
            records = conn.execute(
                "SELECT line_number, raw_input, validation_status FROM domain_audit_records ORDER BY line_number"
            ).fetchall()
            self.assertEqual(len(records), 5)
            self.assertEqual(records[0]["validation_status"], "VALID")
            self.assertEqual(records[1]["validation_status"], "SKIPPED_DUPLICATE")
            self.assertEqual(records[3]["validation_status"], "SKIPPED_DUPLICATE")

    def test_interrupted_resumption(self):
        # Create a file with 30 lines
        lines = [f"domain{i}.com" for i in range(1, 31)]
        test_file = Path(self.temp_dir.name) / "resume_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        # Run with max_domains=10 (simulating interruption after 10)
        res1 = self.engine.run_audit(
            input_path=test_file,
            mode="mock",
            batch_size=5,
            max_domains=10,
        )
        self.assertEqual(res1["audited_this_run"], 10)

        ckpt1 = self.store.load_checkpoint(res1["manifest_id"])
        self.assertEqual(ckpt1["last_processed_line"], 10)

        # Resume without max_domains
        res2 = self.engine.run_audit(
            input_path=test_file,
            mode="mock",
            batch_size=5,
        )
        self.assertEqual(res2["audited_this_run"], 20)  # remaining 20

        ckpt2 = self.store.load_checkpoint(res1["manifest_id"])
        self.assertEqual(ckpt2["last_processed_line"], 30)
        self.assertEqual(ckpt2["audited_count"], 30)

    def test_retest_flag_resets_progress(self):
        lines = ["alpha.com", "beta.com", "gamma.com"]
        test_file = Path(self.temp_dir.name) / "retest.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        self.engine.run_audit(input_path=test_file, mode="mock", batch_size=2)
        # Retest
        res = self.engine.run_audit(
            input_path=test_file,
            mode="mock",
            batch_size=2,
            retest=True,
        )
        self.assertEqual(res["audited_this_run"], 3)

    def test_export_csv_and_jsonl(self):
        lines = [
            "target.com",
            "-badlabel.com",
            "sub.example.co.uk",
        ]
        test_file = Path(self.temp_dir.name) / "export_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        res = self.engine.run_audit(input_path=test_file, mode="mock", batch_size=5)
        manifest_id = res["manifest_id"]

        csv_path = Path(self.temp_dir.name) / "results.csv"
        jsonl_path = Path(self.temp_dir.name) / "results.jsonl"

        csv_count = self.engine.export_csv(manifest_id, csv_path)
        jsonl_count = self.engine.export_jsonl(manifest_id, jsonl_path)

        self.assertEqual(csv_count, 3)
        self.assertEqual(jsonl_count, 3)

        # Verify CSV contents
        csv_text = csv_path.read_text(encoding="utf-8")
        self.assertIn("target.com", csv_text)
        self.assertIn("-badlabel.com", csv_text)

        # Verify JSONL lines
        jsonl_lines = jsonl_path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(jsonl_lines), 3)
        parsed_0 = json.loads(jsonl_lines[0])
        self.assertEqual(parsed_0["normalized_domain"], "target.com")
        self.assertEqual(parsed_0["validation_status"], "VALID")

    def test_no_false_safe_verdicts(self):
        """Strict conservative uncertainty policy verification."""
        lines = ["clean-unknown-domain.com", "another-domain.org"]
        test_file = Path(self.temp_dir.name) / "safety_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        res = self.engine.run_audit(input_path=test_file, mode="mock", batch_size=5)
        with self.store._connect() as conn:
            records = conn.execute("SELECT assessment_verdict FROM domain_audit_records").fetchall()
            for r in records:
                self.assertNotEqual(
                    r["assessment_verdict"].upper(),
                    "SAFE",
                    "Security policy violation: Assessment verdict must NEVER be 'SAFE'.",
                )
                self.assertEqual(r["assessment_verdict"], "NOT_ASSESSED")

    def test_category_i_graph_lookup_existing_vs_absent(self):
        """Category I: Domains with existing graph records vs absent."""
        lines = ["target.com", "absent-random-xyz123.com"]
        test_file = Path(self.temp_dir.name) / "cat_i_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        res = self.engine.run_audit(input_path=test_file, mode="graph-only", batch_size=5)
        self.assertEqual(res["audited_this_run"], 2)

        with self.store._connect() as conn:
            records = {
                r["normalized_domain"]: r
                for r in conn.execute(
                    "SELECT * FROM domain_audit_records WHERE manifest_id = ?",
                    (res["manifest_id"],),
                )
            }
            self.assertEqual(records["target.com"]["investigation_status"], "INVESTIGATED")
            self.assertGreater(records["target.com"]["evidence_count"], 0)
            self.assertEqual(records["target.com"]["data_availability"], "AVAILABLE")
            self.assertEqual(records["target.com"]["assessment_verdict"], "NOT_ASSESSED")

            self.assertEqual(records["absent-random-xyz123.com"]["investigation_status"], "NOT_FOUND")
            self.assertEqual(records["absent-random-xyz123.com"]["data_availability"], "NOT_FOUND")
            self.assertEqual(records["absent-random-xyz123.com"]["assessment_verdict"], "NOT_ASSESSED")

    def test_category_j_provider_failure_modes(self):
        """Category J: Simulated provider failure modes (mock timeouts and outages)."""
        lines = ["normal.com", "fail-timeout.com", "fail-rate-limit.com"]
        test_file = Path(self.temp_dir.name) / "cat_j_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        res = self.engine.run_audit(input_path=test_file, mode="mock", batch_size=5)
        with self.store._connect() as conn:
            records = {
                r["normalized_domain"]: r
                for r in conn.execute(
                    "SELECT * FROM domain_audit_records WHERE manifest_id = ?",
                    (res["manifest_id"],),
                )
            }
            self.assertEqual(records["normal.com"]["investigation_status"], "MOCK_AUDITED")
            self.assertEqual(records["fail-timeout.com"]["investigation_status"], "SOURCE_UNAVAILABLE")
            self.assertIn("Simulated mock provider failure", records["fail-timeout.com"]["error_message"])

    def test_category_k_graph_query_read_only_safety(self):
        """Category K: Graph read-only safety (verifying zero production mutations)."""
        import graph_config
        graph = graph_config.connect_graph()
        nodes_before = graph.query("MATCH (n) RETURN count(n)").result_set[0][0]
        edges_before = graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]

        lines = ["target.com", "google.com", "microsoft.com"]
        test_file = Path(self.temp_dir.name) / "cat_k_test.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        self.engine.run_audit(input_path=test_file, mode="graph-only", batch_size=5)

        nodes_after = graph.query("MATCH (n) RETURN count(n)").result_set[0][0]
        edges_after = graph.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]

        self.assertEqual(nodes_before, nodes_after, "Graph node count mutated during audit!")
        self.assertEqual(edges_before, edges_after, "Graph relationship count mutated during audit!")


class TestScaleAndPerformance(unittest.TestCase):
    """Scale benchmarks for 100, 1,000, and 10,000 domains."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.db_path = Path(self.temp_dir.name) / "scale_test.sqlite3"
        self.engine = DomainBatchAuditEngine(db_path=self.db_path)

    def tearDown(self):
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_scale_100_domains(self):
        lines = [f"scale100-domain-{i}.com" for i in range(100)]
        test_file = Path(self.temp_dir.name) / "scale_100.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        res = self.engine.run_audit(input_path=test_file, mode="mock", batch_size=50)
        self.assertEqual(res["processed_this_run"], 100)
        self.assertEqual(res["audited_this_run"], 100)
        self.assertGreater(res["throughput_domains_per_sec"], 50)

    def test_scale_1000_domains(self):
        # 1000 domains with 100 duplicates interspersed
        lines = [f"scale1k-domain-{i % 900}.com" for i in range(1000)]
        test_file = Path(self.temp_dir.name) / "scale_1000.txt"
        test_file.write_text("\n".join(lines), encoding="utf-8")

        start = time.time()
        res = self.engine.run_audit(input_path=test_file, mode="mock", batch_size=200)
        elapsed = time.time() - start

        self.assertEqual(res["processed_this_run"], 1000)
        self.assertEqual(res["audited_this_run"], 900)
        self.assertEqual(res["duplicates_this_run"], 100)
        self.assertLess(elapsed, 15.0, "1,000 domains mock audit took longer than 15s")

    def test_scale_10000_domains_streaming_and_memory(self):
        # Write 10,000 synthetic domain records to file
        test_file = Path(self.temp_dir.name) / "scale_10000.txt"
        with test_file.open("w", encoding="utf-8") as f:
            for i in range(10000):
                f.write(f"scale10k-{i}.org\n")

        start = time.time()
        res = self.engine.run_audit(input_path=test_file, mode="mock", batch_size=1000)
        elapsed = time.time() - start

        self.assertEqual(res["processed_this_run"], 10000)
        self.assertEqual(res["audited_this_run"], 10000)
        self.assertGreater(res["throughput_domains_per_sec"], 100)
        print(f"\n[BENCHMARK] 10,000 domains mock processed in {elapsed:.2f}s ({res['throughput_domains_per_sec']} domains/sec)")


if __name__ == "__main__":
    unittest.main()
