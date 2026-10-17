
import hashlib
import json
import sys
from pathlib import Path

import graph_config
from psl_utils import registrable_domain

GRAPH_NAME = graph_config.get_graph_settings()[2]
INPUT_FILE = Path("intel_output.json")


def stable_id(*parts):
    raw = json.dumps(
        parts, sort_keys=True, default=str
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def query(graph, cypher, params):
    return graph.query(cypher, params)


def upsert_domain(graph, name):
    query(
        graph,
        """
        MERGE (d:Domain {name: $name})
        RETURN d.name
        """,
        {"name": name},
    )


def upsert_source(graph, source_name):
    query(
        graph,
        """
        MERGE (s:Source {name: $name})
        RETURN s.name
        """,
        {"name": source_name},
    )


def ingest_observation(graph, root_domain, item):
    source_name = str(item.get("source", "Unknown source"))
    kind = str(item.get("kind", "UNKNOWN"))
    value = item.get("value")
    observed_at = str(item.get("observed_at", ""))
    details = item.get("details", {})

    stable_discriminator = (
        details.get("certificate_id")
        if kind == "CERTIFICATE_RECORD" and isinstance(details, dict)
        else None
    )
    observation_id = stable_id(
        root_domain,
        source_name,
        kind,
        value,
        details,
        stable_discriminator,
    )

    upsert_source(graph, source_name)

    query(
        graph,
        """
        MERGE (d:Domain {name: $domain})
        MERGE (s:Source {name: $source})
        MERGE (o:Observation {id: $id})
        SET o.kind = $kind,
            o.value_json = $value_json,
            o.details_json = $details_json,
            o.observed_at = $observed_at
        MERGE (d)-[:HAS_OBSERVATION]->(o)
        MERGE (o)-[:REPORTED_BY]->(s)
        """,
        {
            "domain": root_domain,
            "source": source_name,
            "id": observation_id,
            "kind": kind,
            "value_json": json.dumps(value, default=str),
            "details_json": json.dumps(details, default=str),
            "observed_at": observed_at,
        },
    )

    # Store certificate records and their individual names.
    if kind == "CERTIFICATE_RECORD":
        cert_id = details.get("certificate_id")
        if cert_id is None:
            cert_id = observation_id

        cert_key = str(cert_id)

        query(
            graph,
            """
            MERGE (c:Certificate {certificate_id: $cert_id})
            SET c.issuer = $issuer,
                c.not_before = $not_before,
                c.not_after = $not_after
            WITH c
            MATCH (o:Observation {id: $observation_id})
            MERGE (o)-[:DESCRIBES_CERTIFICATE]->(c)
            """,
            {
                "cert_id": cert_key,
                "issuer": str(details.get("issuer", "")),
                "not_before": str(details.get("not_before", "")),
                "not_after": str(details.get("not_after", "")),
                "observation_id": observation_id,
            },
        )

        names = value if isinstance(value, list) else [value]
        for name in names:
            if not isinstance(name, str):
                continue

            name = name.strip().lower().rstrip(".")
            if not name:
                continue

            # Recheck exact-domain/subdomain boundaries.
            if name.startswith("*."):
                bare_name = name[2:]
            else:
                bare_name = name

            if not (
                bare_name == root_domain
                or bare_name.endswith("." + root_domain)
            ):
                continue

            query(
                graph,
                """
                MERGE (c:Certificate {certificate_id: $cert_id})
                MERGE (d:Domain {name: $name})
                MERGE (c)-[:COVERS]->(d)
                """,
                {"cert_id": cert_key, "name": bare_name},
            )

    # RDAP nameservers are linked to the observation that reported them.
    nameservers = details.get("nameservers", [])
    if isinstance(nameservers, list):
        for server in nameservers:
            if not isinstance(server, str) or not server.strip():
                continue

            server = server.strip().lower().rstrip(".")
            query(
                graph,
                """
                MERGE (n:Nameserver {name: $name})
                WITH n
                MATCH (o:Observation {id: $observation_id})
                MERGE (o)-[:MENTIONS_NAMESERVER]->(n)
                WITH n
                MATCH (d:Domain {name: $domain})
                MERGE (d)-[:HAS_NAMESERVER]->(n)
                """,
                {
                    "name": server,
                    "observation_id": observation_id,
                    "domain": root_domain,
                },
            )

    # Link domain to PSL registered domain if this is a subdomain
    reg_domain = registrable_domain(root_domain)
    if reg_domain and reg_domain != root_domain:
        query(
            graph,
            """
            MERGE (rd:Domain {name: $reg_domain})
            WITH rd
            MATCH (d:Domain {name: $domain})
            MERGE (d)-[:BELONGS_TO]->(rd)
            """,
            {"reg_domain": reg_domain, "domain": root_domain},
        )

    # DNS A and AAAA records establish direct IP resolution
    if kind in ("DNS_A", "DNS_AAAA") and isinstance(value, str) and value.strip():
        ip_addr = value.strip()
        query(
            graph,
            """
            MERGE (ip:IPAddress {address: $ip})
            WITH ip
            MATCH (d:Domain {name: $domain})
            MERGE (d)-[:RESOLVES_TO]->(ip)
            """,
            {"ip": ip_addr, "domain": root_domain},
        )

    # Threat reports create explicit Report nodes and associate with the domain
    if kind == "THREAT_REPORT":
        report_id = str(details.get("report_id") or f"REPORT-{observation_id[:12]}")
        query(
            graph,
            """
            MERGE (r:Report {id: $report_id})
            SET r.source = $source,
                r.confidence = $confidence,
                r.url_count = $url_count,
                r.threat_type = $threat_type,
                r.threat_status = $threat_status,
                r.tags_json = $tags_json
            WITH r
            MATCH (d:Domain {name: $domain})
            MERGE (d)-[:ASSOCIATED_WITH]->(r)
            WITH r
            MATCH (o:Observation {id: $observation_id})
            MERGE (o)-[:MENTIONED_IN]->(r)
            """,
            {
                "report_id": report_id,
                "source": source_name,
                "confidence": float(details.get("confidence", 0.7)),
                "url_count": int(details.get("url_count", 0)),
                "threat_type": str(details.get("threat_type", "malware")),
                "threat_status": str(details.get("threat_status", "unknown")),
                "tags_json": json.dumps(details.get("tags") or []),
                "domain": root_domain,
                "observation_id": observation_id,
            },
        )


def main():
    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"{INPUT_FILE} not found. Run real_intel.py first."
        )

    data = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    domain = data.get("domain", "").strip().lower().rstrip(".")

    if not domain or "/" in domain or "://" in domain:
        raise ValueError("Invalid domain in input JSON.")

    observations = data.get("observations", [])
    if not isinstance(observations, list):
        raise ValueError("'observations' must be a list.")

    graph = graph_config.connect_graph()

    upsert_domain(graph, domain)

    for item in observations:
        if isinstance(item, dict):
            ingest_observation(graph, domain, item)

    print(f"Graph: {GRAPH_NAME}")
    print(f"Domain: {domain}")
    print(f"Observations processed: {len(observations)}")
    print("Assessment: NOT_ASSESSED")
    print("No maliciousness or safety verdict was inferred.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Ingestion failed: {exc}")
        sys.exit(1)
