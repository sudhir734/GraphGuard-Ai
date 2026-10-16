
import graph_config


def main():
    graph = graph_config.connect_graph()

    result = graph.query("""
    MATCH (d:Domain {name: 'demo.example'})
          -[r1:RESOLVES_TO]->(ip:IPAddress)
          -[r2:MENTIONED_IN]->(report:Report)
    RETURN d.name, ip.address, report.id,
           report.source, report.confidence
    """)

    for row in result.result_set:
        print(row)


if __name__ == "__main__":
    main()
