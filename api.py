"""FastAPI endpoints for GraphGuard investigations and health checks."""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

import discovery_engine
import graph_queries
from backend import investigate
from investigation_agent import DomainValidationError, graph_is_available


logger = logging.getLogger("graphguard.api")

app = FastAPI(
    title="GraphGuard AI API",
    version="1.1.0",
    description=(
        "Evidence-first cybersecurity investigation over the existing "
        "FalkorDB graph."
    ),
)


class InvestigationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(
        min_length=1,
        max_length=253,
        strict=True,
        description="Domain to investigate; URLs and IP addresses are rejected.",
    )
    max_depth: int = Field(default=2, strict=True, ge=1, le=3)
    max_entities: int = Field(default=100, strict=True, ge=1, le=200)
    live_enrichment: bool = Field(
        default=False,
        description="Explicitly run live passive enrichment before graph investigation.",
    )
    auto_enrich: bool = Field(
        default=False,
        description="Automatically run live passive enrichment and store in FalkorDB if unindexed.",
    )


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    investigation_id: str
    target_domain: str
    investigation_timestamp: str
    data_origin: str = "STORED_GRAPH"
    live_enrichment_requested: bool = False
    domain: str
    found: bool
    data_availability: str
    investigation_status: str = "NOT_ASSESSED"
    registered_domain: str | None = None
    discovery_status: str
    enrichment_status: str
    enrichment_outcome: str
    enrichment_sources: list[dict[str, Any]]
    observed_sources: list[str] = Field(default_factory=list)
    associated_ips: list[str] = Field(default_factory=list)
    associated_certificates: list[dict[str, Any]] = Field(default_factory=list)
    associated_reports: list[dict[str, Any]] = Field(default_factory=list)
    associated_nameservers: list[str] = Field(default_factory=list)
    assessment: dict[str, Any]
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    observed_entities: list[dict[str, Any]]
    relationship_paths: list[dict[str, Any]]
    shared_infrastructure: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    timeline: list[dict[str, Any]]
    missing_information: list[str]
    errors: list[str]
    explanation: str
    limitations: list[str]
    query_metadata: dict[str, Any]


class DiscoveryRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    seeds: list[str] = Field(
        default_factory=list,
        description="Seed domains to explore.",
    )
    max_depth: int = Field(default=1, ge=1, le=2)
    max_domains: int = Field(default=50, ge=1, le=100)
    scope: str | None = Field(
        default=None,
        description="Optional scope domain (e.g. example.com)",
    )
    enrich_discovered: bool = Field(
        default=False,
        description="Enrich discovered domains with passive intel.",
    )
    delay: float = Field(default=0.5, ge=0.0, le=5.0)
    background: bool = Field(
        default=True,
        description="Run in background thread if True.",
    )


class HealthResponse(BaseModel):
    status: str
    service: str
    application: dict[str, str]
    falkordb: dict[str, str]


@app.get("/health", response_model=HealthResponse)
def health() -> dict[str, Any]:
    """Report application availability separately from graph availability."""
    graph_available = graph_is_available()
    return {
        "status": "ok",
        "service": "GraphGuard AI",
        "application": {"status": "ok"},
        "falkordb": {
            "status": "ok" if graph_available else "unavailable",
        },
    }


@app.get("/health/ready", response_model=HealthResponse)
def readiness() -> dict[str, Any]:
    result = health()
    if result["falkordb"]["status"] != "ok":
        raise HTTPException(
            status_code=503,
            detail="The application is running but FalkorDB is unavailable.",
        )
    return result


@app.post("/investigate", response_model=InvestigationResponse)
def investigate_endpoint(
    request: InvestigationRequest,
) -> dict[str, Any]:
    try:
        kwargs: dict[str, Any] = {
            "max_depth": request.max_depth,
            "max_entities": request.max_entities,
            "live_enrichment": request.live_enrichment,
        }
        if request.auto_enrich:
            kwargs["auto_enrich"] = True
        return investigate(
            request.domain,
            **kwargs,
        )
    except DomainValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except graph_queries.GraphQueryError as exc:
        logger.error(
            "Investigation failed because FalkorDB is unavailable (%s).",
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=503,
            detail="The investigation could not query the graph.",
        ) from exc


@app.get("/discovery/metrics")
def discovery_metrics() -> dict[str, Any]:
    """Return real-time counts and health across FalkorDB and the discovery repository."""
    try:
        return discovery_engine.get_discovery_metrics()
    except Exception as exc:
        logger.error("Failed to collect discovery metrics: %s", exc)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve discovery metrics."
        ) from exc


@app.post("/discovery/run")
def run_discovery(request: DiscoveryRunRequest) -> dict[str, Any]:
    """Run incremental passive domain discovery from seeds."""
    try:
        if request.background:
            return discovery_engine.start_discovery_job(
                seeds=request.seeds,
                max_depth=request.max_depth,
                max_domains=request.max_domains,
                scope=request.scope,
                enrich_discovered=request.enrich_discovered,
                delay=request.delay,
            )
        return discovery_engine.discover_from_seeds(
            seeds=request.seeds,
            max_depth=request.max_depth,
            max_domains=request.max_domains,
            scope=request.scope,
            enrich_discovered=request.enrich_discovered,
            delay=request.delay,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.error("Discovery run failed: %s", exc)
        raise HTTPException(
            status_code=500, detail=f"Discovery failed: {exc}"
        ) from exc


@app.get("/discovery/status")
def discovery_status() -> dict[str, Any]:
    """Return the status and progress of any active or recent background discovery job."""
    return discovery_engine.get_job_status()


@app.get("/audit/summary")
def audit_summary() -> dict[str, Any]:
    """Return aggregated coverage and audit metrics from the batch audit store."""
    try:
        from domain_batch_audit import DomainBatchAuditStore, DEFAULT_DB_PATH
        store = DomainBatchAuditStore(DEFAULT_DB_PATH)
        return store.get_summary_statistics()
    except Exception as exc:
        logger.error("Failed to retrieve audit summary: %s", exc)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve audit summary."
        ) from exc


@app.get("/audit/manifests")
def audit_manifests() -> list[dict[str, Any]]:
    """Return all registered batch audit datasets and their progress."""
    try:
        from domain_batch_audit import DomainBatchAuditStore, DEFAULT_DB_PATH
        store = DomainBatchAuditStore(DEFAULT_DB_PATH)
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_manifests ORDER BY id DESC"
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("Failed to retrieve audit manifests: %s", exc)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve audit manifests."
        ) from exc
