"""Shared FalkorDB configuration for GraphGuard entry points."""

import os

from falkordb import FalkorDB


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6379
DEFAULT_GRAPH = "GraphGuard"


def get_graph_settings():
    host = os.getenv("FALKORDB_HOST", DEFAULT_HOST).strip()
    port_text = os.getenv("FALKORDB_PORT", str(DEFAULT_PORT)).strip()
    graph_name = os.getenv("FALKORDB_GRAPH", DEFAULT_GRAPH).strip()

    if not host:
        raise ValueError("FALKORDB_HOST must not be empty.")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("FALKORDB_PORT must be an integer.") from exc
    if not 1 <= port <= 65535:
        raise ValueError("FALKORDB_PORT must be between 1 and 65535.")
    if not graph_name:
        raise ValueError("FALKORDB_GRAPH must not be empty.")

    return host, port, graph_name


def connect_graph():
    host, port, graph_name = get_graph_settings()
    return FalkorDB(host=host, port=port).select_graph(graph_name)
