import unittest
from unittest.mock import patch

import api
import graph_queries
from fastapi import HTTPException
from investigation_agent import (
    DomainValidationError,
    investigate_domain,
    normalize_domain,
)


def graph_report(found=True, evidence=None):
    nodes = [
        {
            "id": "n:1",
            "label": "target.test",
            "type": "Domain",
            "labels": ["Domain"],
            "properties": {
                "name": "target.test",
                "discovery_status": "DISCOVERED",
                "enrichment_status": "NO_OBSERVATIONS",
            },
        }
    ] if found else []
    return {
        "domain": "target.test",
        "found": found,
        "nodes": nodes,
        "edges": [],
        "evidence": evidence or [],
        "limitations": ["Absence of evidence does not establish safety."],
        "query_metadata": {"graph": "GraphGuard"},
    }


class DomainNormalizationTests(unittest.TestCase):
    def test_normalizes_case_and_idna(self):
        self.assertEqual(normalize_domain("BÜCHER.DE"), "xn--bcher-kva.de")

    def test_rejects_urls_paths_ips_and_public_suffixes(self):
        for value in (
            "https://example.org/path",
            "example.org/path",
            "192.0.2.1",
            "co.uk",
            "localhost",
        ):
            with self.subTest(value=value):
                with self.assertRaises(DomainValidationError):
                    normalize_domain(value)


class InvestigationServiceTests(unittest.TestCase):
    @patch("investigation_agent.graph_queries.investigate_domain")
    def test_missing_domain_is_not_found_not_safe(self, query):
        query.return_value = graph_report(found=False)

        result = investigate_domain("TARGET.TEST")

        self.assertEqual(result["domain"], "target.test")
        self.assertEqual(result["assessment"]["verdict"], "NOT_FOUND")
        self.assertIn("not evidence", result["assessment"]["justification"])
        self.assertEqual(result["enrichment_status"], "NOT_RECORDED")

    @patch("investigation_agent.graph_queries.investigate_domain")
    def test_zero_observations_remain_distinct_from_uninvestigated(self, query):
        query.return_value = graph_report()

        result = investigate_domain("target.test")

        self.assertTrue(result["found"])
        self.assertEqual(result["enrichment_status"], "NO_OBSERVATIONS")
        self.assertEqual(result["assessment"]["verdict"], "NOT_ASSESSED")
        self.assertTrue(result["missing_information"])

    @patch("investigation_agent.graph_queries.investigate_domain")
    def test_passes_bounded_options_to_graph_layer(self, query):
        query.return_value = graph_report(found=False)

        investigate_domain("target.test", max_depth=3, max_entities=12)

        query.assert_called_once_with(
            "target.test",
            max_depth=3,
            max_entities=12,
        )

    def test_rejects_out_of_range_graph_limits(self):
        for options in (
            {"max_depth": 0},
            {"max_depth": 4},
            {"max_entities": 0},
            {"max_entities": 201},
            {"max_depth": True},
        ):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    investigate_domain("target.test", **options)

    @patch("investigation_agent.graph_queries.investigate_domain")
    def test_shared_infrastructure_requires_an_actual_graph_path(self, query):
        report = graph_report()
        report["nodes"].extend([
            {
                "id": "n:2",
                "label": "CERT-1",
                "type": "Certificate",
                "labels": ["Certificate"],
                "properties": {"certificate_id": "CERT-1"},
            },
            {
                "id": "n:3",
                "label": "related.test",
                "type": "Domain",
                "labels": ["Domain"],
                "properties": {"name": "related.test"},
            },
        ])
        report["edges"] = [
            {
                "id": "r:20",
                "record_id": "r:20",
                "from": "n:1",
                "to": "n:2",
                "label": "PRESENTED_CERTIFICATE",
            },
            {
                "id": "r:21",
                "record_id": "r:21",
                "from": "n:2",
                "to": "n:3",
                "label": "COVERS",
            },
        ]
        query.return_value = report

        result = investigate_domain("target.test", max_depth=2)

        self.assertEqual(len(result["shared_infrastructure"]), 1)
        finding = result["shared_infrastructure"][0]
        self.assertEqual(finding["infrastructure"]["id"], "n:2")
        self.assertEqual(finding["related_domain"]["id"], "n:3")
        self.assertIn("r:20", finding["graph_record_ids"])
        self.assertIn("r:21", finding["graph_record_ids"])

    @patch("investigation_agent.graph_queries.investigate_domain")
    def test_report_validates_against_api_response_model(self, query):
        query.return_value = graph_report()

        report = investigate_domain("target.test")

        response = api.InvestigationResponse.model_validate(report)
        self.assertEqual(response.target_domain, "target.test")
        self.assertEqual(response.assessment["verdict"], "NOT_ASSESSED")


class GraphQueryTests(unittest.TestCase):
    def test_observation_source_and_relationships_are_traceable(self):
        graph = unittest.mock.Mock()
        graph.query.side_effect = [
            unittest.mock.Mock(result_set=[
                (1, ["Domain"], {
                    "name": "target.test",
                    "api_key": "do-not-disclose",
                }),
            ]),
            unittest.mock.Mock(result_set=[
                (
                    1, ["Domain"], {"name": "target.test"},
                    2, ["Observation"], {
                        "id": "stored-observation-1",
                        "kind": "DNS_A",
                        "value_json": '"203.0.113.7"',
                        "details_json": (
                            '{"access_token":"do-not-disclose","ttl":45}'
                        ),
                        "observed_at": "2026-01-02T03:04:05+00:00",
                    },
                    1, 2, 10, "HAS_OBSERVATION",
                ),
            ]),
            unittest.mock.Mock(result_set=[
                (
                    2, ["Observation"], {
                        "id": "stored-observation-1",
                        "kind": "DNS_A",
                        "value_json": '"203.0.113.7"',
                        "details_json": (
                            '{"access_token":"do-not-disclose","ttl":45}'
                        ),
                        "observed_at": "2026-01-02T03:04:05+00:00",
                    },
                    3, ["Source"], {
                        "name": "Test DNS source",
                        "source_type": "passive_dns",
                    },
                    2, 3, 11, "REPORTED_BY",
                ),
            ]),
        ]

        with patch.object(graph_queries, "_get_graph", return_value=graph):
            result = graph_queries.investigate_domain(
                "target.test",
                max_depth=2,
                max_entities=3,
            )

        self.assertEqual(graph.query.call_count, 3)
        root_query, params = graph.query.call_args_list[0].args
        self.assertNotIn("[*1..", root_query)
        self.assertNotIn("target.test", root_query)
        self.assertEqual(params["domain"], "target.test")
        self.assertIn("LIMIT $row_limit", graph.query.call_args_list[1].args[0])
        self.assertTrue(result["found"])
        self.assertEqual(result["evidence"][0]["sources"], ["Test DNS source"])
        self.assertEqual(
            result["evidence"][0]["source_records"][0]["source_type"],
            "passive_dns",
        )
        self.assertIn(
            "stored-observation-1",
            result["evidence"][0]["observation_id"],
        )
        self.assertIn(
            "n:2",
            result["evidence"][0]["evidence_node_ids"],
        )
        self.assertEqual(
            result["evidence"][0]["observed_at"],
            "2026-01-02T03:04:05+00:00",
        )
        self.assertEqual(
            result["evidence"][0]["details"]["access_token"],
            "[REDACTED]",
        )
        self.assertEqual(
            next(node for node in result["nodes"] if node["id"] == "n:2")
            ["properties"]["details_json"]["access_token"],
            "[REDACTED]",
        )
        self.assertEqual(
            next(node for node in result["nodes"] if node["id"] == "n:1")
            ["properties"]["api_key"],
            "[REDACTED]",
        )

    def test_query_failure_is_explicit(self):
        graph = unittest.mock.Mock()
        graph.query.side_effect = RuntimeError("database unavailable")

        with patch.object(graph_queries, "_get_graph", return_value=graph):
            with self.assertRaises(graph_queries.GraphQueryError):
                graph_queries.investigate_domain("target.test")

    def test_entity_count_never_exceeds_requested_limit(self):
        graph = unittest.mock.Mock()
        graph.query.side_effect = [
            unittest.mock.Mock(result_set=[
                (1, ["Domain"], {"name": "target.test"}),
            ]),
            unittest.mock.Mock(result_set=[
                (
                    1, ["Domain"], {"name": "target.test"},
                    2, ["Observation"], {"id": "obs-1", "kind": "DNS_A"},
                    1, 2, 10, "HAS_OBSERVATION",
                ),
            ]),
            unittest.mock.Mock(result_set=[
                (
                    2, ["Observation"], {"id": "obs-1", "kind": "DNS_A"},
                    3, ["Source"], {"name": "Test source"},
                    2, 3, 11, "REPORTED_BY",
                ),
            ]),
        ]

        with patch.object(graph_queries, "_get_graph", return_value=graph):
            result = graph_queries.investigate_domain(
                "target.test",
                max_entities=2,
            )

        self.assertEqual(len(result["nodes"]), 2)
        known_node_ids = {node["id"] for node in result["nodes"]}
        self.assertTrue(all(
            edge["from"] in known_node_ids and edge["to"] in known_node_ids
            for edge in result["edges"]
        ))
        self.assertTrue(result["query_metadata"]["entity_limit_reached"])


class ApiValidationTests(unittest.TestCase):
    def test_request_limits_and_extra_fields_are_validated(self):
        request = api.InvestigationRequest.model_validate({
            "domain": "target.test",
            "max_depth": 3,
            "max_entities": 50,
        })
        self.assertEqual(request.max_depth, 3)

        with self.assertRaises(ValueError):
            api.InvestigationRequest.model_validate({
                "domain": "target.test",
                "max_depth": 4,
            })

        with self.assertRaises(ValueError):
            api.InvestigationRequest.model_validate({
                "domain": "target.test",
                "unexpected": "value",
            })

    def test_invalid_domain_has_422_response(self):
        request = api.InvestigationRequest(domain="co.uk")

        with self.assertRaises(HTTPException) as error:
            api.investigate_endpoint(request)

        self.assertEqual(error.exception.status_code, 422)

    @patch("api.investigate", side_effect=graph_queries.GraphQueryError("private"))
    def test_graph_failure_is_a_safe_service_unavailable_response(self, _):
        request = api.InvestigationRequest(domain="target.test")

        with self.assertRaises(HTTPException) as error:
            api.investigate_endpoint(request)

        self.assertEqual(error.exception.status_code, 503)
        self.assertNotIn("private", error.exception.detail)

    @patch("api.graph_is_available", return_value=False)
    def test_health_distinguishes_api_from_graph_availability(self, _):
        result = api.health()

        self.assertEqual(result["application"]["status"], "ok")
        self.assertEqual(result["falkordb"]["status"], "unavailable")

    def test_request_supports_live_enrichment_field(self):
        req = api.InvestigationRequest(domain="target.test", live_enrichment=True)
        self.assertTrue(req.live_enrichment)

        req_default = api.InvestigationRequest(domain="target.test")
        self.assertFalse(req_default.live_enrichment)

    @patch("api.investigate")
    def test_investigate_endpoint_forwards_live_enrichment(self, mock_investigate):
        mock_investigate.return_value = {
            "investigation_id": "test-id",
            "target_domain": "target.test",
            "investigation_timestamp": "2026-10-17T00:00:00Z",
            "data_origin": "LIVE_PASSIVE",
            "live_enrichment_requested": True,
            "domain": "target.test",
            "found": False,
            "data_availability": "NOT_FOUND",
            "investigation_status": "NOT_FOUND",
            "discovery_status": "NOT_RECORDED",
            "enrichment_status": "NOT_RECORDED",
            "enrichment_outcome": "NOT_RECORDED",
            "enrichment_sources": [],
            "assessment": {"verdict": "NOT_FOUND"},
            "nodes": [],
            "edges": [],
            "evidence": [],
            "observed_entities": [],
            "relationship_paths": [],
            "shared_infrastructure": [],
            "findings": [],
            "timeline": [],
            "missing_information": [],
            "errors": [],
            "explanation": "No matching domain",
            "limitations": [],
            "query_metadata": {},
        }
        req = api.InvestigationRequest(domain="target.test", live_enrichment=True)
        resp = api.investigate_endpoint(req)
        self.assertEqual(resp["data_origin"], "LIVE_PASSIVE")
        self.assertTrue(resp["live_enrichment_requested"])
        mock_investigate.assert_called_once_with("target.test", max_depth=2, max_entities=100, live_enrichment=True)

    @patch("api.investigate")
    def test_investigate_endpoint_forwards_auto_enrich(self, mock_investigate):
        mock_investigate.return_value = {
            "target_domain": "new-domain.test",
            "data_origin": "LIVE_PASSIVE",
        }
        req = api.InvestigationRequest(domain="new-domain.test", auto_enrich=True)
        resp = api.investigate_endpoint(req)
        self.assertEqual(resp["data_origin"], "LIVE_PASSIVE")
        mock_investigate.assert_called_once_with(
            "new-domain.test", max_depth=2, max_entities=100, live_enrichment=False, auto_enrich=True
        )


if __name__ == "__main__":
    unittest.main()

