
"""
GraphGuard AI - FalkorDB investigation and evidence layer.

Features:
- Cypher-based graph traversal
- Source-attributed observations
- Certificate validity classification
- Parsed JSON properties
- Deduplicated nodes and relationships
- Evidence linked only through actual graph relationships
- Bounded results and defensive error handling

Expected graph:
    Domain, IPAddress, Certificate, Observation, Source,
    Nameserver, Report

Common relationships:
    HAS_OBSERVATION, REPORTED_BY, DESCRIBES_CERTIFICATE,
    COVERS, RESOLVES_TO, PRESENTED_CERTIFICATE,
    MENTIONED_IN, MENTIONS_NAMESERVER, DISCOVERED_FROM
"""

import json
from datetime import datetime, timezone
from typing import Any

import graph_config


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

FALKORDB_HOST, FALKORDB_PORT, GRAPH_NAME = graph_config.get_graph_settings()

MAX_GRAPH_ROWS = 500
MAX_GRAPH_ENTITIES = 200
MAX_EVIDENCE_RECORDS = 200


def _active_graph_name() -> str:
    """Return the active configured graph name."""
    try:
        return graph_config.get_graph_settings()[2]
    except Exception:
        return GRAPH_NAME


class GraphQueryError(RuntimeError):
    """Raised when the configured graph cannot answer an investigation."""


# ---------------------------------------------------------
# Connection
# ---------------------------------------------------------

def _get_graph():
    """Return the configured FalkorDB graph."""
    return graph_config.connect_graph()


# ---------------------------------------------------------
# Data normalization
# ---------------------------------------------------------

def _as_dict(value: Any) -> dict:
    """Convert graph properties to a regular dictionary."""
    if value is None:
        return {}

    if isinstance(value, dict):
        return value

    try:
        return dict(value)
    except (TypeError, ValueError):
        return {}


def _parse_json(value: Any, default=None):
    """Parse JSON strings while preserving already parsed values."""
    if value is None:
        return default

    if isinstance(value, (dict, list, int, float, bool)):
        return value

    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _first(
    properties: dict,
    *keys: str,
    default: str = "",
) -> str:
    for key in keys:
        value = properties.get(key)
        if value is not None and value != "":
            return _text(value)
    return default


def _safe_properties(properties: Any) -> dict:
    """Make node properties JSON-friendly and redact credential-like keys."""
    properties = _as_dict(properties)
    cleaned = {}

    for key, value in properties.items():
        cleaned[str(key)] = _redact_property(str(key), value)

    return cleaned


def _redact_property(key: str, value: Any) -> Any:
    normalized_key = key.lower().replace("-", "_").replace(" ", "_")
    sensitive_fragments = (
        "api_key",
        "apikey",
        "access_key",
        "private_key",
        "privatekey",
        "token",
        "secret",
        "password",
        "passwd",
        "authorization",
        "credential",
        "cookie",
        "cookies",
        "bearer",
        "auth",
    )
    if any(fragment in normalized_key for fragment in sensitive_fragments):
        return "[REDACTED]"
    if normalized_key.endswith("_json") and isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return value
    return _redact_nested(value)


def _redact_nested(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _redact_property(str(key), item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_nested(item) for item in value]
    return value


# ---------------------------------------------------------
# Certificate validity
# ---------------------------------------------------------

def _parse_datetime(value: Any):
    """Parse an ISO date; naive timestamps are treated as UTC."""
    if not value:
        return None

    try:
        text_value = str(value).strip()

        if text_value.endswith("Z"):
            text_value = text_value[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text_value)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def certificate_status(
    not_before: Any,
    not_after: Any,
) -> str:
    """
    Classify the supplied certificate validity dates.

    This does not prove that the certificate is currently deployed,
    trusted, or associated with malicious activity.
    """
    start = _parse_datetime(not_before)
    end = _parse_datetime(not_after)

    if start is None or end is None:
        return "UNKNOWN"

    if end < start:
        return "INVALID_DATE_RANGE"

    now = datetime.now(timezone.utc)

    if now < start:
        return "NOT_YET_VALID"

    if now > end:
        return "EXPIRED"

    return "WITHIN_VALIDITY_PERIOD"


# ---------------------------------------------------------
# Node presentation
# ---------------------------------------------------------

def _node_title(labels: list, props: dict) -> str:
    label_set = set(labels or [])

    if "Domain" in label_set:
        return _first(
            props, "name", "domain", "hostname", "value",
            default="Unknown domain",
        )

    if "IPAddress" in label_set:
        return _first(
            props, "address", "ip_address", "ip", "name",
            default="Unknown IP",
        )

    if "Certificate" in label_set:
        return _first(
            props, "certificate_id", "fingerprint", "id", "name",
            default="Certificate",
        )

    if "Observation" in label_set:
        kind = _first(props, "kind", default="Observation")
        observation_id = _first(props, "id")
        return (
            f"{kind} ({observation_id})"
            if observation_id else kind
        )

    if "Source" in label_set:
        return _first(
            props, "name", "source", "id",
            default="Unknown source",
        )

    if "Nameserver" in label_set:
        return _first(
            props, "name", "hostname", "value",
            default="Unknown nameserver",
        )

    if "Report" in label_set:
        return _first(
            props, "report_id", "id", "name",
            default="Report",
        )

    return _first(
        props, "name", "address", "value", "id",
        default=next(iter(labels or []), "Entity"),
    )


# ---------------------------------------------------------
# Investigation
# ---------------------------------------------------------

def check_graph_health() -> bool:
    """Check graph connectivity with a read-only query."""
    try:
        graph = _get_graph()
        graph.query("RETURN 1 AS healthy")
    except Exception as exc:
        raise GraphQueryError("FalkorDB is unavailable.") from exc
    return True


def investigate_domain(
    domain: str,
    max_depth: int = 2,
    max_entities: int = 100,
    graph: Any = None,
) -> dict:
    """
    Investigate a domain already present in the graph.

    Returns the established backend interface:
        domain, found, nodes, edges, evidence

    Additional metadata:
        limitations, query_metadata
    """
    if type(max_depth) is not int or not 1 <= max_depth <= 3:
        raise ValueError("max_depth must be an integer between 1 and 3.")

    if (
        type(max_entities) is not int
        or not 1 <= max_entities <= MAX_GRAPH_ENTITIES
    ):
        raise ValueError(
            f"max_entities must be an integer between 1 and "
            f"{MAX_GRAPH_ENTITIES}."
        )

    domain = (domain or "").strip().lower()

    if not domain:
        return {
            "domain": "",
            "found": False,
            "nodes": [],
            "edges": [],
            "evidence": [],
            "limitations": ["No domain was provided."],
            "query_metadata": {"graph": getattr(graph, "name", _active_graph_name())},
        }

    # Avoid accepting whitespace-containing search input.
    if any(character.isspace() for character in domain):
        return {
            "domain": domain,
            "found": False,
            "nodes": [],
            "edges": [],
            "evidence": [],
            "limitations": [
                "The domain input contains whitespace."
            ],
            "query_metadata": {"graph": getattr(graph, "name", _active_graph_name())},
        }

    root_query = """
    MATCH (d:Domain)
    WHERE toLower(coalesce(d.name, d.domain, d.value, "")) = $domain
    RETURN id(d) AS id, labels(d) AS labels,
           properties(d) AS properties
    LIMIT 1
    """

    row_limit = min(MAX_GRAPH_ROWS, max_entities * 5)
    try:
        graph = graph or _get_graph()
        root_result = graph.query(root_query, {"domain": domain})
        root_rows = root_result.result_set
        if not root_rows:
            return {
                "domain": domain,
                "found": False,
                "nodes": [],
                "edges": [],
                "evidence": [],
                "limitations": [
                    "No matching domain node was found.",
                    "The graph may not contain complete or current data.",
                    "Absence of evidence does not establish safety.",
                ],
                "query_metadata": {
                    "graph": _active_graph_name(),
                    "row_limit": row_limit,
                    "rows_returned": 0,
                    "max_depth": max_depth,
                },
            }

        root_id, root_labels, root_properties = root_rows[0]
        raw_nodes = {
            root_id: {
                "labels": root_labels,
                "properties": root_properties,
            }
        }
        root_node_ids = [root_id]
        raw_relationships = {}
        frontier = {root_id}
        visited_node_ids = {root_id}
        rows_returned = 0
        row_limit_reached = False

        # Expand one hop at a time so each frontier is capped before it
        # can trigger another relationship expansion.
        hop_query = """
        MATCH (source)-[rel]-(target)
        WHERE id(source) IN $node_ids
        RETURN id(source) AS source_id,
               labels(source) AS source_labels,
               properties(source) AS source_properties,
               id(target) AS target_id,
               labels(target) AS target_labels,
               properties(target) AS target_properties,
               id(startNode(rel)) AS rel_from,
               id(endNode(rel)) AS rel_to,
               id(rel) AS rel_id,
               type(rel) AS rel_type
        LIMIT $row_limit
        """
        for _ in range(max_depth):
            remaining = MAX_GRAPH_ROWS - rows_returned
            if not frontier or remaining <= 0:
                break
            hop_limit = min(row_limit, remaining)
            hop_rows = graph.query(
                hop_query,
                {
                    "node_ids": sorted(frontier),
                    "row_limit": hop_limit,
                },
            ).result_set
            rows_returned += len(hop_rows)
            if len(hop_rows) >= hop_limit:
                row_limit_reached = True

            next_frontier = set()
            for row in hop_rows:
                (
                    source_id, source_labels, source_properties,
                    target_id, target_labels, target_properties,
                    rel_from, rel_to, rel_id, rel_type,
                ) = row
                raw_nodes.setdefault(source_id, {
                    "labels": source_labels,
                    "properties": source_properties,
                })
                raw_nodes.setdefault(target_id, {
                    "labels": target_labels,
                    "properties": target_properties,
                })
                relationship_key = (
                    rel_id if rel_id is not None
                    else (rel_from, rel_type, rel_to)
                )
                raw_relationships[relationship_key] = {
                    "id": rel_id,
                    "type": rel_type,
                    "from": rel_from,
                    "to": rel_to,
                }
                neighbor_id = (
                    target_id if source_id in frontier else source_id
                )
                if neighbor_id not in visited_node_ids:
                    next_frontier.add(neighbor_id)
                    visited_node_ids.add(neighbor_id)
            frontier = next_frontier
    except Exception as exc:
        raise GraphQueryError("FalkorDB investigation query failed.") from exc

    nodes_by_id = {}
    edges_by_key = {}
    entity_limit_reached = False

    def add_node(node_id, labels, properties):
        nonlocal entity_limit_reached
        if node_id is None:
            return False

        node_key = f"n:{node_id}"
        if node_key not in nodes_by_id and len(nodes_by_id) >= max_entities:
            entity_limit_reached = True
            return False

        labels = list(labels or [])
        properties = _safe_properties(properties)

        nodes_by_id[node_key] = {
            "id": node_key,
            "label": _node_title(labels, properties),
            "type": labels[0] if labels else "Entity",
            "labels": labels,
            "properties": properties,
        }
        return True

    def add_edge(rel_type, source_id, target_id, relationship_id=None):
        if (
            rel_type is None
            or source_id is None
            or target_id is None
        ):
            return

        source = f"n:{source_id}"
        target = f"n:{target_id}"
        if source not in nodes_by_id or target not in nodes_by_id:
            return

        record_id = (
            f"r:{relationship_id}"
            if relationship_id is not None
            else None
        )
        key = (source, str(rel_type), target, record_id)

        edges_by_key[key] = {
            "id": record_id or f"e:{source}|{rel_type}|{target}",
            "record_id": record_id,
            "from": source,
            "to": target,
            "label": str(rel_type),
            "arrows": "to",
        }

    for node_id in dict.fromkeys(root_node_ids):
        record = raw_nodes.get(node_id, {})
        add_node(node_id, record.get("labels"), record.get("properties"))

    source_ids_by_observation = {}
    for relationship in raw_relationships.values():
        if relationship.get("type") != "REPORTED_BY":
            continue
        source_id = relationship.get("from")
        observation_id = relationship.get("to")
        if (
            "Observation" in set(
                raw_nodes.get(source_id, {}).get("labels") or []
            )
            and "Source" in set(
                raw_nodes.get(observation_id, {}).get("labels") or []
            )
        ):
            observation_id, source_id = source_id, observation_id
        if (
            "Observation" in set(
                raw_nodes.get(observation_id, {}).get("labels") or []
            )
            and "Source" in set(
                raw_nodes.get(source_id, {}).get("labels") or []
            )
        ):
            source_ids_by_observation.setdefault(
                observation_id, []
            ).append(source_id)

    prioritized_node_ids = []
    for node_id, record in raw_nodes.items():
        if "Observation" in set(record.get("labels") or []):
            prioritized_node_ids.append(node_id)
            prioritized_node_ids.extend(
                source_ids_by_observation.get(node_id, [])
            )

    for node_id in dict.fromkeys(prioritized_node_ids):
        if node_id not in root_node_ids:
            record = raw_nodes.get(node_id, {})
            add_node(node_id, record.get("labels"), record.get("properties"))

    def node_priority(item):
        labels = set(item[1].get("labels") or [])
        if labels.intersection({"Certificate", "IPAddress", "Nameserver"}):
            return 0
        if "Domain" in labels:
            return 1
        if "Source" in labels:
            return 2
        if "Observation" in labels:
            return 3
        return 4

    remaining_nodes = [
        (node_id, record)
        for node_id, record in raw_nodes.items()
        if node_id not in root_node_ids
        and node_id not in prioritized_node_ids
    ]
    remaining_nodes.sort(key=node_priority)
    for node_id, record in remaining_nodes:
        add_node(node_id, record.get("labels"), record.get("properties"))

    for relationship in raw_relationships.values():
        add_edge(
            relationship.get("type"),
            relationship.get("from"),
            relationship.get("to"),
            relationship.get("id"),
        )

    nodes = list(nodes_by_id.values())
    edges = list(edges_by_key.values())

    root_nodes = [
        node for node in nodes
        if "Domain" in node["labels"]
        and _first(
            node["properties"], "name", "domain", "value"
        ).lower() == domain
    ]

    if not root_nodes:
        return {
            "domain": domain,
            "found": False,
            "nodes": [],
            "edges": [],
            "evidence": [],
            "limitations": [
                "No matching domain node was found.",
                "The graph may not contain complete or current data.",
                "Absence of evidence does not establish safety.",
            ],
            "query_metadata": {
                "graph": _active_graph_name(),
                "rows_limit": MAX_GRAPH_ROWS,
            },
        }

    # Build an index of actual graph relationships.
    outgoing = {}
    incoming = {}

    for edge in edges:
        outgoing.setdefault(edge["from"], []).append(edge)
        incoming.setdefault(edge["to"], []).append(edge)

    def related_nodes(node_id, relationship, direction="out"):
        index = outgoing if direction == "out" else incoming
        matches = []

        for edge in index.get(node_id, []):
            if edge["label"] != relationship:
                continue

            other_id = (
                edge["to"] if direction == "out"
                else edge["from"]
            )
            other = nodes_by_id.get(other_id)

            if other is not None:
                matches.append(other)

        return matches

    # -----------------------------------------------------
    # Extract evidence from Observation nodes only.
    # -----------------------------------------------------

    evidence = []
    seen_observations = set()

    evidence_limit = min(max_entities, MAX_EVIDENCE_RECORDS)

    for node in nodes:
        if "Observation" not in node["labels"]:
            continue

        node_id = node["id"]

        # Require an actual relationship from the searched
        # domain to this observation, not mere co-occurrence.
        has_domain_link = any(
            edge["label"] == "HAS_OBSERVATION"
            and edge["from"] in {
                root["id"] for root in root_nodes
            }
            and edge["to"] == node_id
            for edge in edges
        )

        if not has_domain_link:
            continue

        props = node["properties"]
        observation_id = _first(
            props, "id", default=node_id
        )

        if observation_id in seen_observations:
            continue

        seen_observations.add(observation_id)

        details = _parse_json(
            props.get("details_json"),
            default={},
        )
        value = _parse_json(
            props.get("value_json"),
            default=None,
        )
        details = _redact_nested(details)
        value = _redact_nested(value)

        if not isinstance(details, dict):
            details = {"raw_details": details}

        sources = related_nodes(
            node_id, "REPORTED_BY", "out"
        )
        if not sources:
            sources = related_nodes(
                node_id, "REPORTED_BY", "in"
            )

        certificates = related_nodes(
            node_id, "DESCRIBES_CERTIFICATE", "out"
        )
        if not certificates:
            certificates = related_nodes(
                node_id, "DESCRIBES_CERTIFICATE", "in"
            )

        source_names = [
            _first(
                source["properties"],
                "name", "source", "id",
                default=source["label"],
            )
            for source in sources
        ]
        source_records = [
            {
                "name": source_name,
                "source_type": _first(
                    source["properties"],
                    "source_type",
                    "type",
                    default="NOT_RECORDED",
                ),
                "node_id": source["id"],
            }
            for source, source_name in zip(sources, source_names)
        ]

        certificate_records = []

        for cert in certificates:
            cert_props = cert["properties"]

            not_before = cert_props.get("not_before")
            not_after = cert_props.get("not_after")

            # Some ingestors store certificate dates inside
            # the observation's details_json instead.
            not_before = (
                not_before
                or details.get("not_before")
            )
            not_after = (
                not_after
                or details.get("not_after")
            )

            certificate_records.append({
                "certificate_id": _first(
                    cert_props,
                    "certificate_id", "fingerprint", "id",
                    default=cert["label"],
                ),
                "issuer": cert_props.get(
                    "issuer", details.get("issuer")
                ),
                "not_before": not_before,
                "not_after": not_after,
                "certificate_status": certificate_status(
                    not_before, not_after
                ),
                "node_id": cert["id"],
            })

        # Include details embedded in the observation when
        # no Certificate node is connected to it.
        if not certificate_records and (
            details.get("certificate_id") is not None
            or details.get("not_before") is not None
            or details.get("not_after") is not None
        ):
            not_before = details.get("not_before")
            not_after = details.get("not_after")

            certificate_records.append({
                "certificate_id": details.get(
                    "certificate_id"
                ),
                "issuer": details.get("issuer"),
                "not_before": not_before,
                "not_after": not_after,
                "certificate_status": certificate_status(
                    not_before, not_after
                ),
                "node_id": None,
            })

        primary_certificate = (
            certificate_records[0]
            if certificate_records else {}
        )

        evidence.append({
            "domain": domain,
            "observation_id": observation_id,
            "kind": _first(
                props, "kind", default="OBSERVATION"
            ),
            "source": (
                ", ".join(source_names)
                if source_names
                else "Not specified in graph"
            ),
            "sources": source_names,
            "source_records": source_records,
            "observed_at": props.get("observed_at"),
            "value": value,
            "details": details,
            "certificate": primary_certificate.get(
                "certificate_id"
            ),
            "issuer": primary_certificate.get("issuer"),
            "not_before": primary_certificate.get(
                "not_before"
            ),
            "not_after": primary_certificate.get(
                "not_after"
            ),
            "certificate_status": primary_certificate.get(
                "certificate_status", "NOT_APPLICABLE"
            ),
            "certificates": certificate_records,
            "evidence_node_ids": [
                node_id,
                *[source["id"] for source in sources],
                *[
                    cert["id"] for cert in certificates
                ],
            ],
        })

        if len(evidence) >= evidence_limit:
            break

    # Sort newest collection timestamps first when available.
    evidence.sort(
        key=lambda item: item.get("observed_at") or "",
        reverse=True,
    )

    limitations = [
        "Graph connectivity alone does not establish maliciousness.",
        "Missing evidence does not establish that a domain is safe.",
        "The graph may contain both seeded and externally collected data.",
        "Verify each finding against its source and collection timestamp.",
        "Certificate validity dates do not prove current deployment or trust.",
    ]

    if not evidence:
        limitations.append(
            "No directly linked Observation records were returned."
        )

    return {
        "domain": domain,
        "found": True,
        "nodes": nodes,
        "edges": edges,
        "evidence": evidence,
        "limitations": limitations,
        "query_metadata": {
            "graph": _active_graph_name(),
            "nodes_returned": len(nodes),
            "edges_returned": len(edges),
            "evidence_returned": len(evidence),
            "rows_returned": rows_returned,
            "max_depth": max_depth,
            "max_entities": max_entities,
            "row_limit": row_limit,
            "evidence_limit": evidence_limit,
            "row_limit_reached": row_limit_reached,
            "entity_limit_reached": entity_limit_reached,
            "evidence_limit_reached": len(evidence) >= evidence_limit,
        },
    }
