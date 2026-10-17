"""Shared FalkorDB configuration for GraphGuard entry points.

Local defaults preserve the existing developer workflow. Cloud deployments
should set credentials and enable TLS explicitly.
"""
import os

from falkordb import FalkorDB


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 6379
DEFAULT_GRAPH = "GraphGuard"


def _optional_env(name: str) -> str | None:
    value = os.getenv(name, "").strip()
    return value or None


def _enabled(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off", ""}:
        return False
    raise ValueError(f"{name} must be a boolean value.")


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
    """Return the configured FalkorDB graph with optional auth and TLS."""
    host, port, graph_name = get_graph_settings()
    tls = _enabled("FALKORDB_TLS", default=False)
    db = FalkorDB(
        host=host,
        port=port,
        username=_optional_env("FALKORDB_USERNAME"),
        password=_optional_env("FALKORDB_PASSWORD"),
        ssl=tls,
        ssl_cert_reqs="required",
        ssl_check_hostname=tls,
    )
    return db.select_graph(graph_name)
