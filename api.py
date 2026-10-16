"""FastAPI endpoints for GraphGuard investigations and health checks."""

import logging
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

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


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    investigation_id: str
    target_domain: str
    investigation_timestamp: str
    domain: str
    found: bool
    data_availability: str
    discovery_status: str
    enrichment_status: str
    enrichment_outcome: str
    enrichment_sources: list[dict[str, Any]]
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
        return investigate(
            request.domain,
            max_depth=request.max_depth,
            max_entities=request.max_entities,
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
