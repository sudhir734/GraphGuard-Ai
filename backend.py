"""Application service interface for graph investigations."""

from typing import Any

from investigation_agent import investigate_domain


def investigate(
    domain: str,
    max_depth: int = 2,
    max_entities: int = 100,
    live_enrichment: bool = False,
    auto_enrich: bool = False,
    graph: Any = None,
) -> dict[str, Any]:
    """Run a validated, bounded investigation against FalkorDB."""
    return investigate_domain(
        domain,
        max_depth=max_depth,
        max_entities=max_entities,
        live_enrichment=live_enrichment,
        auto_enrich=auto_enrich,
        graph=graph,
    )

