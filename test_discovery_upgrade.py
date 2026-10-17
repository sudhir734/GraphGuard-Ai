"""Tests for Global Domain Discovery, Passive Threat Intel, and Investigation Upgrade."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import api
import discovery_engine
import injest_intel
import investigation_agent
import real_intel


class CandidateExtractionTests(unittest.TestCase):
    def test_extract_candidates_from_ct_dns_rdap(self):
        sources = [
            {
                "source": "crt.sh Certificate Transparency",
                "observations": [
                    {
                        "kind": "CERTIFICATE_RECORD",
                        "value": [
                            "sub.example.com",
                            "api.example.com",
                            "*.wildcard.example.com",
                            "another.org",
                        ],
                        "details": {},
                    }
                ],
            },
            {
                "source": "Cloudflare DNS",
                "observations": [
                    {
                        "kind": "DNS_CNAME",
                        "value": "cdn.example.com.",
                        "details": {},
                    },
                    {
                        "kind": "DNS_MX",
                        "value": "10 mail.example.com.",
                        "details": {},
                    },
                ],
            },
            {
                "source": "RDAP",
                "observations": [
                    {
                        "kind": "DOMAIN_REGISTRATION",
                        "value": "example.com",
                        "details": {
                            "nameservers": ["ns1.example.com"],
                        },
                    }
                ],
            },
        ]
        # In-scope
        candidates = real_intel.extract_discovered_candidates(
            root_domain="example.com",
            sources=sources,
            scope_domain="example.com",
        )
        candidate_names = [c["domain"] for c in candidates]
        self.assertIn("sub.example.com", candidate_names)
        self.assertIn("api.example.com", candidate_names)
        self.assertIn("cdn.example.com", candidate_names)
        self.assertIn("mail.example.com", candidate_names)
        self.assertIn("ns1.example.com", candidate_names)
        self.assertNotIn("another.org", candidate_names)  # filtered by scope
        self.assertNotIn("example.com", candidate_names)  # seed itself excluded

    def test_extract_candidates_no_scope_accepts_valid_names(self):
        sources = [
            {
                "source": "crt.sh Certificate Transparency",
                "observations": [
                    {
                        "kind": "CERTIFICATE_RECORD",
                        "value": "valid-other.org",
                        "details": {},
                    }
                ],
            },
            {
                "source": "Cloudflare DNS",
                "observations": [
                    {
                        "kind": "DNS_CNAME",
                        "value": "192.168.1.1",  # IP address, rejected
                        "details": {},
                    }
                ],
            },
        ]
        candidates = real_intel.extract_discovered_candidates(
            root_domain="example.com",
            sources=sources,
            scope_domain=None,
        )
        candidate_names = [c["domain"] for c in candidates]
        self.assertIn("valid-other.org", candidate_names)
        self.assertNotIn("192.168.1.1", candidate_names)


class ThreatIntelCollectionTests(unittest.TestCase):
    @patch("real_intel.post_json")
    def test_collect_threat_intelligence_urlhaus_hit(self, mock_post):
        mock_post.return_value = {
            "query_status": "ok",
            "host_status": "online",
            "url_count": 5,
            "threat": "malware_download",
            "tags": ["elf", "mozi"],
        }
        res = real_intel.collect_threat_intelligence("malicious.example")
        self.assertEqual(res["status"], "success")
        self.assertEqual(len(res["observations"]), 1)
        obs = res["observations"][0]
        self.assertEqual(obs["kind"], "THREAT_REPORT")
        self.assertEqual(obs["value"], "malicious.example")
        self.assertEqual(obs["details"]["threat_type"], "malware_download")
        self.assertEqual(obs["details"]["report_id"], "URLHAUS-malicious.example")
        self.assertEqual(obs["details"]["confidence"], 0.85)

    @patch("real_intel.post_json")
    def test_collect_threat_intelligence_urlhaus_no_results(self, mock_post):
        mock_post.return_value = {"query_status": "no_results"}
        res = real_intel.collect_threat_intelligence("clean.example")
        self.assertEqual(res["status"], "no_records")
        self.assertEqual(len(res["observations"]), 0)


class IngestionEntityLinkingTests(unittest.TestCase):
    def test_ingest_dns_creates_resolves_to_and_belongs_to(self):
        graph = Mock()
        item = {
            "source": "Cloudflare DNS",
            "kind": "DNS_A",
            "value": "93.184.216.34",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "details": {"ttl": 300},
        }
        injest_intel.ingest_observation(graph, "sub.example.com", item)

        cypher_queries = [call.args[0] for call in graph.query.call_args_list]
        query_text = "\n".join(cypher_queries)

        # Resolves to IPAddress
        self.assertIn("MERGE (ip:IPAddress {address: $ip})", query_text)
        self.assertIn("RESOLVES_TO", query_text)

        # Belongs to apex registered domain
        self.assertIn("MERGE (rd:Domain {name: $reg_domain})", query_text)
        self.assertIn("BELONGS_TO", query_text)

    def test_ingest_threat_report_creates_associated_with(self):
        graph = Mock()
        item = {
            "source": "URLhaus (abuse.ch)",
            "kind": "THREAT_REPORT",
            "value": "malicious.example",
            "observed_at": "2026-01-01T00:00:00+00:00",
            "details": {
                "report_id": "urlhaus-999",
                "threat": "malware_download",
                "confidence": 0.9,
                "url": "http://malicious.example/drop.bin",
            },
        }
        injest_intel.ingest_observation(graph, "malicious.example", item)

        cypher_queries = [call.args[0] for call in graph.query.call_args_list]
        query_text = "\n".join(cypher_queries)

        self.assertIn("MERGE (r:Report {id: $report_id})", query_text)
        self.assertIn("ASSOCIATED_WITH", query_text)
        self.assertIn("MENTIONED_IN", query_text)


class DiscoveryEngineBfsTests(unittest.TestCase):
    def test_bounded_discovery_and_scope_filtering(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_disc.sqlite3"
            graph = Mock()

            # Mock collect_intelligence to return discovered subdomains
            def mock_collect(domain, scope_domain=None):
                if domain == "seed.example.com":
                    return {
                        "domain": domain,
                        "overall_status": "success",
                        "sources": [],
                        "discovered_candidates": [
                            {"domain": "api.seed.example.com", "source": "CT", "relationship": "SAN"},
                            {"domain": "other.org", "source": "CT", "relationship": "SAN"},
                        ],
                    }
                elif domain == "api.seed.example.com":
                    return {
                        "domain": domain,
                        "overall_status": "success",
                        "sources": [],
                        "discovered_candidates": [
                            {"domain": "deep.seed.example.com", "source": "CT", "relationship": "SAN"},
                        ],
                    }
                return {
                    "domain": domain,
                    "overall_status": "success",
                    "sources": [],
                    "discovered_candidates": [],
                }

            with patch("discovery_engine.STATE_DB", db_path), \
                 patch("real_intel.collect_intelligence", side_effect=mock_collect):

                # Test depth 1, scope seed.example.com
                result = discovery_engine.discover_from_seeds(
                    seeds=["seed.example.com"],
                    max_depth=1,
                    max_domains=10,
                    scope="seed.example.com",
                    enrich_discovered=False,
                    delay=0.0,
                    graph=graph,
                )

                self.assertEqual(result["status"], "COMPLETED")
                discovered_names = [d["domain"] for d in result["discovered_domains"]]
                self.assertIn("api.seed.example.com", discovered_names)
                # other.org was excluded by scope
                self.assertNotIn("other.org", discovered_names)
                # deep.seed.example.com was excluded by depth 1 limit
                self.assertNotIn("deep.seed.example.com", discovered_names)

                # Check SQLite record creation
                conn = sqlite3.connect(db_path)
                rows = conn.execute("SELECT domain, graph_imported FROM domains").fetchall()
                conn.close()
                domains_in_db = {r[0] for r in rows}
                self.assertIn("seed.example.com", domains_in_db)
                self.assertIn("api.seed.example.com", domains_in_db)

    def test_discovery_metrics_calculation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "test_metrics.sqlite3"
            conn = sqlite3.connect(db_path)
            conn.execute("""
                CREATE TABLE domains (
                    domain TEXT PRIMARY KEY,
                    source_file TEXT,
                    first_seen TEXT,
                    graph_imported INTEGER DEFAULT 0,
                    enriched INTEGER DEFAULT 0
                )
            """)
            conn.execute("INSERT INTO domains VALUES ('a.com', 'seed', '2026', 1, 1)")
            conn.execute("INSERT INTO domains VALUES ('b.com', 'seed', '2026', 0, 0)")
            conn.commit()
            conn.close()

            graph = Mock()
            graph.query.side_effect = [
                Mock(result_set=[[10]]),  # total domains
                Mock(result_set=[[7]]),   # investigated
                Mock(result_set=[[3]]),   # sources
                Mock(result_set=[[5]]),   # ips
                Mock(result_set=[[4]]),   # certs
                Mock(result_set=[[2]]),   # reports
            ]

            with patch("discovery_engine.STATE_DB", db_path):
                metrics = discovery_engine.get_discovery_metrics(graph=graph)

            self.assertEqual(metrics["total_domains_in_graph"], 10)
            self.assertEqual(metrics["investigated_domains"], 7)
            self.assertEqual(metrics["associated_ip_addresses"], 5)
            self.assertEqual(metrics["staged_in_sqlite"], 2)


class InvestigationAgentUpgradeTests(unittest.TestCase):
    def test_investigation_status_and_structured_entities(self):
        mock_report = {
            "domain": "target.example",
            "found": True,
            "nodes": [
                {
                    "id": "n:1",
                    "label": "target.example",
                    "labels": ["Domain"],
                    "properties": {
                        "name": "target.example",
                        "enrichment_status": "COMPLETED",
                        "enrichment_outcome": "SUCCESS",
                        "enrichment_sources_json": json.dumps([
                            {"source": "Cloudflare DNS", "status": "SUCCESS"},
                            {"source": "URLhaus", "status": "SUCCESS"},
                        ]),
                    },
                },
                {
                    "id": "n:2",
                    "label": "93.184.216.34",
                    "labels": ["IPAddress"],
                    "properties": {"address": "93.184.216.34"},
                },
                {
                    "id": "n:3",
                    "label": "Cert-1",
                    "labels": ["Certificate"],
                    "properties": {
                        "sha256": "abcdef123456",
                        "issuer": "DigiCert",
                        "subject": "target.example",
                    },
                },
                {
                    "id": "n:4",
                    "label": "Report-1",
                    "labels": ["Report"],
                    "properties": {
                        "id": "rep-42",
                        "source": "URLhaus",
                        "threat": "malware",
                    },
                },
                {
                    "id": "n:5",
                    "label": "ns1.example.com",
                    "labels": ["Nameserver"],
                    "properties": {"name": "ns1.example.com"},
                },
            ],
            "edges": [],
            "evidence": [
                {
                    "domain": "target.example",
                    "observation_id": "obs-1",
                    "kind": "DNS_A",
                    "sources": ["Cloudflare DNS"],
                }
            ],
            "limitations": [],
            "query_metadata": {"graph": "GraphGuard"},
        }

        with patch.object(
            investigation_agent.graph_queries,
            "investigate_domain",
            return_value=mock_report,
        ):
            res = investigation_agent.investigate_domain("target.example")

        self.assertEqual(res["investigation_status"], "INVESTIGATED")
        self.assertEqual(res["registered_domain"], "target.example")
        self.assertEqual(res["associated_ips"], ["93.184.216.34"])
        self.assertEqual(len(res["associated_certificates"]), 1)
        self.assertEqual(res["associated_certificates"][0]["issuer"], "DigiCert")
        self.assertEqual(len(res["associated_reports"]), 1)
        self.assertEqual(res["associated_reports"][0]["id"], "rep-42")
        self.assertEqual(res["associated_nameservers"], ["ns1.example.com"])

    def test_investigation_status_source_unavailable(self):
        mock_report = {
            "domain": "unavail.example",
            "found": True,
            "nodes": [
                {
                    "id": "n:1",
                    "label": "unavail.example",
                    "labels": ["Domain"],
                    "properties": {
                        "name": "unavail.example",
                        "enrichment_sources_json": json.dumps([
                            {"source": "Cloudflare DNS", "status": "FAILED"},
                        ]),
                    },
                }
            ],
            "edges": [],
            "evidence": [{"observation_id": "obs-1", "sources": ["Cloudflare DNS"]}],
            "limitations": [],
            "query_metadata": {"graph": "GraphGuard"},
        }
        with patch.object(
            investigation_agent.graph_queries,
            "investigate_domain",
            return_value=mock_report,
        ):
            res = investigation_agent.investigate_domain("unavail.example")

        self.assertEqual(res["investigation_status"], "SOURCE_UNAVAILABLE")


class ApiEndpointsUpgradeTests(unittest.TestCase):
    @patch("discovery_engine.get_discovery_metrics")
    def test_discovery_metrics_endpoint(self, mock_metrics):
        mock_metrics.return_value = {
            "total_domains_in_graph": 100,
            "staged_in_sqlite": 500,
        }
        data = api.discovery_metrics()
        self.assertEqual(data["total_domains_in_graph"], 100)

    @patch("discovery_engine.start_discovery_job")
    def test_discovery_run_endpoint_background(self, mock_start):
        mock_start.return_value = {"status": "RUNNING", "discovered": 0}
        req = api.DiscoveryRunRequest(
            seeds=["seed.example"],
            max_depth=1,
            max_domains=20,
            background=True,
        )
        res = api.run_discovery(req)
        self.assertEqual(res["status"], "RUNNING")
        mock_start.assert_called_once()

    @patch("discovery_engine.get_job_status")
    def test_discovery_status_endpoint(self, mock_status):
        mock_status.return_value = {"status": "COMPLETED", "discovered": 12}
        res = api.discovery_status()
        self.assertEqual(res["discovered"], 12)

    def test_start_discovery_job_returns_structured_dict_and_accepts_graph(self):
        with patch("discovery_engine.discover_from_seeds") as mock_discover:
            mock_graph = Mock()
            res = discovery_engine.start_discovery_job(
                seeds=["test.seed.com"],
                max_depth=1,
                max_domains=10,
                graph=mock_graph,
            )
            self.assertIsInstance(res, dict)
            self.assertEqual(res["status"], "RUNNING")
            self.assertIn("job_id", res)
            self.assertEqual(res["discovered"], 0)
            self.assertEqual(res["discovered_count"], 0)

            # Reset status back to IDLE
            with discovery_engine._STATE_LOCK:
                discovery_engine._ACTIVE_JOB["status"] = "IDLE"

    def test_get_discovery_metrics_includes_nested_sections(self):
        mock_graph = Mock()
        mock_graph.query.side_effect = [
            Mock(result_set=[[100]]),  # total domains
            Mock(result_set=[[20]]),   # investigated
            Mock(result_set=[[4]]),    # sources
            Mock(result_set=[[15]]),   # ips
            Mock(result_set=[[8]]),    # certs
            Mock(result_set=[[3]]),    # reports
        ]
        metrics = discovery_engine.get_discovery_metrics(graph=mock_graph)
        self.assertIn("graph", metrics)
        self.assertIn("discovery_repository", metrics)
        self.assertEqual(metrics["graph"]["total_domains"], 100)
        self.assertEqual(metrics["graph"]["investigated_domains"], 20)
        self.assertEqual(metrics["graph"]["total_ips"], 15)
        self.assertEqual(metrics["total_domains_in_graph"], 100)


if __name__ == "__main__":
    unittest.main()
