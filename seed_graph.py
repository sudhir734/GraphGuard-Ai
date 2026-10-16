
import argparse

import graph_config


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Create fictional records in an isolated demo graph."
    )
    parser.add_argument(
        "--confirm-demo-graph",
        action="store_true",
        help="Confirm writes to the GraphGuardDemo graph.",
    )
    args = parser.parse_args(argv)
    graph_name = graph_config.get_graph_settings()[2]
    if not args.confirm_demo_graph or not (
        graph_name == "GraphGuardDemo"
        or graph_name.startswith("GraphGuardDemo_")
    ):
        parser.error(
            "Seeding requires --confirm-demo-graph and "
            "FALKORDB_GRAPH=GraphGuardDemo (or GraphGuardDemo_<suffix>)."
        )

    graph = graph_config.connect_graph()
    graph.query("""
    CREATE
      (d:Domain {name: 'demo.example'}),
      (ip:IPAddress {address: '192.0.2.10'}),
      (c:Certificate {fingerprint: 'DEMO-CERT-001'}),
      (r:Report {id: 'REPORT-001', source: 'Synthetic demo data',
                 confidence: 0.60}),
      (d)-[:RESOLVES_TO]->(ip),
      (d)-[:PRESENTED_CERTIFICATE]->(c),
      (ip)-[:MENTIONED_IN]->(r)
    """)
    print(f"GraphGuard demo graph created in {graph_name}.")


if __name__ == "__main__":
    main()
