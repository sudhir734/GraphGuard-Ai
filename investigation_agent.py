"""Evidence-backed investigations over the existing GraphGuard graph."""

from __future__ import annotations

import ipaddress
import json
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any

import graph_queries
from psl_utils import is_public_suffix, normalize_name, registrable_domain


MAX_DEPTH = 3
MAX_ENTITIES = graph_queries.MAX_GRAPH_ENTITIES
MAX_REPORTED_PATHS = 200


class DomainValidationError(ValueError):
    """Raised when an investigation target is not a valid domain name."""


def normalize_domain(value: str) -> str:
    """Normalize a DNS name and reject URLs, IP addresses, and suffixes."""
    if not isinstance(value, str) or not value:
        raise DomainValidationError("Enter a domain name.")

    value = value.strip()
    if not value or any(character in value for character in "/:@\\"):
        raise DomainValidationError(
            "Enter a domain name only, without a URL, path, or port."
        )

    try:
        ipaddress.ip_address(value.strip("[]"))
    except ValueError:
        pass
    else:
        raise DomainValidationError("Enter a domain name, not an IP address.")

    try:
        domain = normalize_name(value)
    except (ValueError, UnicodeError) as exc:
        raise DomainValidationError(str(exc)) from exc

    if len(domain) > 253:
        raise DomainValidationError("The domain exceeds 253 characters.")

    if is_public_suffix(domain) or registrable_domain(domain) is None:
        raise DomainValidationError(
            "Enter a domain below a public suffix, not the suffix itself."
        )

    return domain


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _root_node(report: dict[str, Any]) -> dict[str, Any] | None:
    domain = report["domain"]
    for node in report.get("nodes", []):
        if "Domain" not in node.get("labels", []):
            continue
        properties = node.get("properties") or {}
        name = (
            properties.get("name")
            or properties.get("domain")
            or properties.get("value")
        )
        if isinstance(name, str) and name.lower() == domain:
            return node
    return None


def _relationship_paths(
    report: dict[str, Any],
    max_depth: int,
) -> list[dict[str, Any]]:
    nodes = {node["id"]: node for node in report.get("nodes", [])}
    adjacency: dict[str, list[tuple[dict[str, Any], str]]] = {}

    for edge in report.get("edges", []):
        adjacency.setdefault(edge["from"], []).append((edge, edge["to"]))
        adjacency.setdefault(edge["to"], []).append((edge, edge["from"]))

    roots = [
        node["id"]
        for node in report.get("nodes", [])
        if "Domain" in node.get("labels", [])
        and (
            (node.get("properties") or {}).get("name")
            or (node.get("properties") or {}).get("domain")
            or (node.get("properties") or {}).get("value")
        ) == report["domain"]
    ]

    paths: list[dict[str, Any]] = []
    for root in roots:
        pending = deque([(root, [root], [])])
        while pending and len(paths) < MAX_REPORTED_PATHS:
            current, node_path, edge_path = pending.popleft()
            if len(edge_path) >= max_depth:
                continue

            for edge, neighbor in adjacency.get(current, []):
                if neighbor in node_path:
                    continue

                next_nodes = [*node_path, neighbor]
                next_edges = [*edge_path, edge]
                evidence_ids = []
                for node_id in next_nodes:
                    node = nodes.get(node_id, {})
                    if "Observation" in node.get("labels", []):
                        observation_id = (node.get("properties") or {}).get("id")
                        if observation_id is not None:
                            evidence_ids.append(str(observation_id))

                relationship_ids = [
                    str(item.get("record_id") or item["id"])
                    for item in next_edges
                ]
                paths.append({
                    "node_ids": next_nodes,
                    "relationship_ids": relationship_ids,
                    "relationship_types": [
                        item.get("label", "") for item in next_edges
                    ],
                    "depth": len(next_edges),
                    "classification": (
                        "DIRECT" if len(next_edges) == 1 else "INFERRED_PATH"
                    ),
                    "evidence_ids": sorted(set(evidence_ids)),
                    "graph_record_ids": [*next_nodes, *relationship_ids],
                })
                pending.append((neighbor, next_nodes, next_edges))

                if len(paths) >= MAX_REPORTED_PATHS:
                    break

    return paths


def _shared_infrastructure(
    report: dict[str, Any],
    paths: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    nodes = {node["id"]: node for node in report.get("nodes", [])}
    infrastructure_labels = {"IPAddress", "Certificate", "Nameserver"}
    findings = []
    seen = set()

    for path in paths:
        domain_nodes = [
            node_id for node_id in path["node_ids"]
            if "Domain" in nodes.get(node_id, {}).get("labels", [])
        ]
        if not any(node_id != path["node_ids"][0] for node_id in domain_nodes):
            continue

        infrastructure = [
            node_id for node_id in path["node_ids"]
            if infrastructure_labels.intersection(
                nodes.get(node_id, {}).get("labels", [])
            )
        ]
        if not infrastructure:
            continue

        related_domains = [
            node_id for node_id in domain_nodes
            if node_id != path["node_ids"][0]
        ]
        for infrastructure_id in infrastructure:
            for related_id in related_domains:
                key = (infrastructure_id, related_id)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "infrastructure": nodes[infrastructure_id],
                    "related_domain": nodes[related_id],
                    "relationship_path": path,
                    "evidence_ids": path["evidence_ids"],
                    "graph_record_ids": path["graph_record_ids"],
                })

    return findings


def _perform_live_enrichment(normalized_domain: str, graph_conn: Any):
    import real_intel
    import injest_intel

    intel_report = real_intel.collect_intelligence(normalized_domain)
    observations = intel_report.get("observations", [])
    sources_statuses = [
        {"source": s.get("source"), "status": str(s.get("status", "unknown")).upper()}
        for s in intel_report.get("sources", [])
    ]

    ingested_count = 0
    for item in observations:
        if isinstance(item, dict):
            injest_intel.ingest_observation(graph_conn, normalized_domain, item)
            ingested_count += 1

    unavailable_sources = [
        s for s in sources_statuses
        if s["status"] in {"UNAVAILABLE", "ERROR", "TIMEOUT"}
    ]
    if ingested_count > 0:
        enrichment_status = "PARTIAL" if unavailable_sources else "COLLECTED"
        enrichment_outcome = enrichment_status
    elif not sources_statuses or all(s["status"] == "UNAVAILABLE" for s in sources_statuses):
        enrichment_status = "UNAVAILABLE"
        enrichment_outcome = "UNAVAILABLE"
    elif unavailable_sources:
        enrichment_status = "PARTIAL"
        enrichment_outcome = "PARTIAL_NO_OBSERVATIONS"
    else:
        enrichment_status = "NO_OBSERVATIONS"
        enrichment_outcome = "NO_OBSERVATIONS"

    now_str = _utc_now()
    source_status_json = json.dumps(sources_statuses, sort_keys=True)
    graph_conn.query("""
        MERGE (d:Domain {name: $domain})
        SET d.last_enriched_at = $timestamp,
            d.enrichment_status = $enrichment_status,
            d.enrichment_outcome = $enrichment_outcome,
            d.enrichment_sources_json = $source_status_json,
            d.enrichment_observation_count = $observation_count,
            d.enrichment_verdict = 'NOT_ASSESSED'
    """, {
        "domain": normalized_domain,
        "timestamp": now_str,
        "enrichment_status": enrichment_status,
        "enrichment_outcome": enrichment_outcome,
        "source_status_json": source_status_json,
        "observation_count": ingested_count,
    })


def investigate_domain(
    domain: str,
    max_depth: int = 2,
    max_entities: int = 100,
    live_enrichment: bool = False,
    auto_enrich: bool = False,
    graph: Any = None,
) -> dict[str, Any]:
    """Return a bounded report derived from FalkorDB, optionally with live passive enrichment."""
    if type(max_depth) is not int or not 1 <= max_depth <= MAX_DEPTH:
        raise ValueError(f"max_depth must be an integer between 1 and {MAX_DEPTH}.")
    if type(max_entities) is not int or not 1 <= max_entities <= MAX_ENTITIES:
        raise ValueError(
            f"max_entities must be an integer between 1 and {MAX_ENTITIES}."
        )

    normalized_domain = normalize_domain(domain)
    data_origin = "STORED_GRAPH"

    inv_kwargs = {"max_depth": max_depth, "max_entities": max_entities}
    if graph is not None:
        inv_kwargs["graph"] = graph

    if live_enrichment:
        data_origin = "LIVE_PASSIVE"
        import graph_config
        graph_conn = graph or graph_config.connect_graph()
        _perform_live_enrichment(normalized_domain, graph_conn)
        graph_report = graph_queries.investigate_domain(
            normalized_domain,
            **inv_kwargs,
        )
    else:
        graph_report = graph_queries.investigate_domain(
            normalized_domain,
            **inv_kwargs,
        )
        root = _root_node(graph_report)
        found = bool(graph_report.get("found") and root)
        if not found and auto_enrich:
            data_origin = "LIVE_PASSIVE"
            import graph_config
            graph_conn = graph or graph_config.connect_graph()
            _perform_live_enrichment(normalized_domain, graph_conn)
            graph_report = graph_queries.investigate_domain(
                normalized_domain,
                **inv_kwargs,
            )

    root = _root_node(graph_report)
    found = bool(graph_report.get("found") and root)
    evidence = graph_report.get("evidence", [])

    if not found:
        verdict = "NOT_FOUND"
        justification = (
            "No matching Domain node was found in the current graph. "
            "This is not evidence that the domain is safe."
        )
        enrichment_status = "NOT_RECORDED"
        discovery_status = "NOT_RECORDED"
        enrichment_outcome = "NOT_RECORDED"
        enrichment_sources = []
        malformed_enrichment_sources = False
    else:
        properties = root.get("properties") or {}
        verdict = "NOT_ASSESSED"
        justification = (
            "The graph contains records for this domain, but the available "
            "evidence is not assessed by a documented verdict policy."
        )
        enrichment_status = str(
            properties.get("enrichment_status") or "NOT_RECORDED"
        ).upper()
        if enrichment_status == "NOT_RECORDED" and evidence:
            enrichment_status = "OBSERVATIONS_PRESENT_STATUS_UNRECORDED"
        discovery_status = str(
            properties.get("discovery_status") or "NOT_RECORDED"
        ).upper()
        enrichment_outcome = str(
            properties.get("enrichment_outcome") or "NOT_RECORDED"
        ).upper()
        raw_enrichment_sources = properties.get("enrichment_sources_json")
        malformed_enrichment_sources = False
        if isinstance(raw_enrichment_sources, str):
            try:
                raw_enrichment_sources = json.loads(raw_enrichment_sources)
            except json.JSONDecodeError:
                raw_enrichment_sources = []
                malformed_enrichment_sources = True
        if raw_enrichment_sources is not None and not isinstance(
            raw_enrichment_sources, list
        ):
            malformed_enrichment_sources = True
        enrichment_sources = (
            [
                {
                    "source": str(item.get("source", "Unknown source")),
                    "status": str(item.get("status", "unknown")).upper(),
                }
                for item in raw_enrichment_sources
                if isinstance(item, dict)
            ]
            if isinstance(raw_enrichment_sources, list)
            else []
        )

    paths = _relationship_paths(graph_report, max_depth) if found else []
    evidence_ids = sorted({
        str(item.get("observation_id"))
        for item in evidence
        if item.get("observation_id") is not None
    })
    observed_sources = sorted({
        str(src)
        for item in evidence
        for src in item.get("sources", [])
        if src
    })

    if not found:
        investigation_status = "NOT_FOUND"
    elif not evidence:
        investigation_status = "NO_EVIDENCE_FOUND"
    elif enrichment_sources and all(
        item.get("status") in {"FAILED", "UNAVAILABLE", "ERROR", "TIMEOUT"}
        for item in enrichment_sources
    ):
        investigation_status = "SOURCE_UNAVAILABLE"
    elif enrichment_status == "COMPLETED" or enrichment_outcome == "SUCCESS":
        investigation_status = "INVESTIGATED"
    elif enrichment_status in {"PARTIAL", "PARTIALLY_COMPLETED"} or enrichment_outcome == "PARTIAL":
        investigation_status = "PARTIALLY_ASSESSED"
    elif enrichment_sources and any(
        item.get("status") == "SUCCESS" for item in enrichment_sources
    ) and any(
        item.get("status") in {"FAILED", "UNAVAILABLE", "ERROR", "TIMEOUT"}
        for item in enrichment_sources
    ):
        investigation_status = "PARTIALLY_ASSESSED"
    elif evidence:
        investigation_status = "INVESTIGATED"
    else:
        investigation_status = "NOT_ASSESSED"

    associated_ips: list[str] = []
    associated_certificates: list[dict[str, Any]] = []
    associated_reports: list[dict[str, Any]] = []
    associated_nameservers: list[str] = []

    for node in graph_report.get("nodes", []):
        labels = set(node.get("labels", []))
        props = node.get("properties") or {}
        if "IPAddress" in labels:
            ip_val = props.get("address") or props.get("ip") or props.get("value") or props.get("name")
            if ip_val and str(ip_val) not in associated_ips:
                associated_ips.append(str(ip_val))
        if "Certificate" in labels:
            cert_info = {
                "id": str(node.get("id")),
                "sha256": str(props.get("sha256") or props.get("fingerprint") or ""),
                "issuer": str(props.get("issuer") or props.get("issuer_cn") or ""),
                "subject": str(props.get("subject_common_name") or props.get("subject") or ""),
                "not_after": str(props.get("not_after") or props.get("valid_to") or ""),
            }
            if cert_info not in associated_certificates:
                associated_certificates.append(cert_info)
        if "Report" in labels:
            rep_info = {
                "id": str(props.get("id") or node.get("id")),
                "source": str(props.get("source") or ""),
                "confidence": str(props.get("confidence") or ""),
                "threat": str(props.get("threat") or props.get("threat_type") or ""),
                "url": str(props.get("url") or ""),
            }
            if rep_info not in associated_reports:
                associated_reports.append(rep_info)
        if "Nameserver" in labels:
            ns_val = props.get("hostname") or props.get("name") or props.get("value")
            if ns_val and str(ns_val).lower() not in associated_nameservers:
                associated_nameservers.append(str(ns_val).lower())

    registered_apex = registrable_domain(normalized_domain)

    missing_information = []
    if found and not evidence:
        missing_information.append(
            "No directly linked Observation records were found."
        )
    if found and (
        enrichment_status == "NOT_RECORDED"
        or enrichment_status.endswith("STATUS_UNRECORDED")
    ):
        missing_information.append(
            "The graph does not reliably record whether passive enrichment "
            "was run."
        )
    if found and evidence and not enrichment_sources:
        missing_information.append(
            "Provider execution details for the enrichment run were not "
            "recorded in the graph."
        )
    if malformed_enrichment_sources:
        missing_information.append(
            "Stored enrichment source-status data is malformed."
        )
    if any(not item.get("sources") for item in evidence):
        missing_information.append(
            "At least one observation has no linked Source record."
        )

    timeline = [
        {
            "timestamp": item.get("observed_at"),
            "event": item.get("kind", "OBSERVATION"),
            "evidence_id": item.get("observation_id"),
            "source": item.get("source"),
        }
        for item in evidence
        if item.get("observed_at")
    ]
    timeline.sort(key=lambda item: str(item["timestamp"]))

    return {
        **graph_report,
        "investigation_id": str(uuid.uuid4()),
        "target_domain": normalized_domain,
        "investigation_timestamp": _utc_now(),
        "data_origin": data_origin,
        "live_enrichment_requested": live_enrichment,
        "explanation": (
            (
                "No matching domain was found in the current graph. "
                "This does not mean the domain is safe."
            )
            if not found
            else (
                "The graph returned stored entities and relationships. "
                "Inspect each source and evidence trail; connectivity alone "
                "does not establish maliciousness."
            )
        ),
        "data_availability": "AVAILABLE" if found else "NOT_FOUND",
        "investigation_status": investigation_status,
        "registered_domain": registered_apex,
        "discovery_status": discovery_status,
        "enrichment_status": enrichment_status,
        "enrichment_outcome": enrichment_outcome,
        "enrichment_sources": enrichment_sources,
        "observed_sources": observed_sources,
        "associated_ips": associated_ips,
        "associated_certificates": associated_certificates,
        "associated_reports": associated_reports,
        "associated_nameservers": associated_nameservers,
        "assessment": {
            "verdict": verdict,
            "justification": justification,
            "evidence_ids": evidence_ids,
        },
        "observed_entities": graph_report.get("nodes", []),
        "relationship_paths": paths,
        "shared_infrastructure": _shared_infrastructure(
            graph_report, paths
        ),
        "findings": [
            {
                "kind": "OBSERVATION",
                "summary": (
                    f"{item.get('kind', 'Observation')} recorded by "
                    f"{item.get('source', 'an unspecified source')}."
                ),
                "evidence_ids": (
                    [str(item["observation_id"])]
                    if item.get("observation_id") is not None else []
                ),
                "graph_record_ids": item.get("evidence_node_ids", []),
            }
            for item in evidence
        ],
        "timeline": timeline,
        "missing_information": missing_information,
        "errors": [],
        "query_metadata": {
            **graph_report.get("query_metadata", {}),
            "requested_max_depth": max_depth,
            "requested_max_entities": max_entities,
        },
    }


def graph_is_available() -> bool:
    """Return whether the configured FalkorDB accepts a read-only query."""
    try:
        graph_queries.check_graph_health()
    except graph_queries.GraphQueryError:
        return False
    return True
