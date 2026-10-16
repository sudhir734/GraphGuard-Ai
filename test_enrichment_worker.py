import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import enrichment_worker


class EnrichmentOutcomeTests(unittest.TestCase):
    def run_enrichment(self, data):
        with tempfile.TemporaryDirectory() as temp_dir:
            database = Path(temp_dir) / "checkpoint.sqlite3"
            with patch.object(enrichment_worker, "CHECKPOINT_DB", database):
                checkpoint = enrichment_worker.connect_checkpoint()
                checkpoint.execute(
                    "INSERT INTO enrichment_jobs (domain) VALUES (?)",
                    ("target.test",),
                )
                checkpoint.commit()
                graph = Mock()
                try:
                    with patch.object(
                        enrichment_worker.real_intel,
                        "collect_intelligence",
                        return_value=data,
                    ), patch.object(
                        enrichment_worker.injest_intel,
                        "ingest_observation",
                    ) as ingest:
                        result = enrichment_worker.enrich_one(
                            graph,
                            checkpoint,
                            "target.test",
                        )
                    status_row = checkpoint.execute(
                        "SELECT status, observation_count FROM enrichment_jobs "
                        "WHERE domain = ?",
                        ("target.test",),
                    ).fetchone()
                finally:
                    checkpoint.close()

        graph_update = graph.query.call_args
        return result, status_row, graph_update, ingest

    def test_all_unavailable_providers_remain_retryable(self):
        result, job, graph_update, _ = self.run_enrichment({
            "observations": [],
            "sources": [
                {"source": "RDAP", "status": "unavailable"},
                {"source": "CT", "status": "unavailable"},
            ],
        })

        self.assertEqual(result["status"], "RETRY")
        self.assertEqual(result["enrichment_status"], "UNAVAILABLE")
        self.assertEqual(job, ("RETRY", 0))
        self.assertEqual(
            graph_update.args[1]["enrichment_status"],
            "UNAVAILABLE",
        )

    def test_successful_empty_collection_is_distinct_from_unattempted(self):
        result, job, graph_update, _ = self.run_enrichment({
            "observations": [],
            "sources": [
                {"source": "DNS", "status": "no_records"},
                {"source": "RDAP", "status": "success"},
            ],
        })

        self.assertEqual(result["status"], "DONE")
        self.assertEqual(result["enrichment_status"], "NO_OBSERVATIONS")
        self.assertEqual(job, ("DONE", 0))
        self.assertEqual(
            graph_update.args[1]["enrichment_outcome"],
            "NO_OBSERVATIONS",
        )

    def test_partial_collection_is_marked_partial(self):
        observation = {
            "source": "DNS",
            "kind": "DNS_A",
            "value": "203.0.113.2",
            "details": {},
        }
        result, job, graph_update, ingest = self.run_enrichment({
            "observations": [observation],
            "sources": [
                {"source": "DNS", "status": "success"},
                {"source": "RDAP", "status": "unavailable"},
            ],
        })

        self.assertEqual(result["status"], "RETRY")
        self.assertEqual(result["enrichment_status"], "PARTIAL")
        self.assertEqual(job, ("RETRY", 1))
        self.assertEqual(
            graph_update.args[1]["enrichment_status"],
            "PARTIAL",
        )
        ingest.assert_called_once_with(
            unittest.mock.ANY,
            "target.test",
            observation,
        )


if __name__ == "__main__":
    unittest.main()
