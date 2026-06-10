"""Pydantic response models for the Falcon Inventory REST API.

These models drive OpenAPI schema generation and provide automatic
validation of every response.  They are intentionally thin wrappers —
the records themselves are opaque ``dict`` blobs from the CrowdStrike
API, so we use ``dict[str, Any]`` rather than trying to pin every field.
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Shared / envelope models
# ---------------------------------------------------------------------------

class ErrorResponse(BaseModel):
    """Normalised error envelope for all non-2xx responses."""

    error: str = Field(description="Machine-readable error code")
    message: str = Field(description="Human-readable detail")
    status: int = Field(description="HTTP status code")


class PageMeta(BaseModel):
    """Pagination and cache-freshness metadata attached to every list response."""

    total: int = Field(description="Total records matching the query")
    offset: int = Field(description="Offset of the first record in this page")
    limit: int = Field(description="Requested page size")
    count: int = Field(description="Records returned in this page")
    generated_at: Optional[str] = Field(
        None, description="ISO-8601 timestamp when the data was fetched"
    )
    data_age_seconds: Optional[float] = Field(
        None, description="Seconds since the data was loaded into memory"
    )
    stale: bool = Field(
        False, description="True when data age exceeds max-age threshold"
    )


# ---------------------------------------------------------------------------
# Dataset responses
# ---------------------------------------------------------------------------

class PaginatedResponse(BaseModel):
    """Generic paginated list of inventory records."""

    dataset: str = Field(description="Dataset name (applications, vulnerabilities, assessments)")
    meta: PageMeta
    records: list[dict[str, Any]] = Field(description="Page of records")


class HostMapResponse(BaseModel):
    """Full host map keyed by Discover host ID."""

    host_map: dict[str, dict[str, Any]]


class CountsResponse(BaseModel):
    """Record counts per dataset."""

    counts: dict[str, int]
    generated_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

class HealthResponse(BaseModel):
    """Liveness and freshness probe."""

    status: str = Field(default="ok")
    generated_at: Optional[str] = None
    age_seconds: float = Field(default=0.0, description="Seconds since last data load")
    stale: bool = False
    fetch_running: bool = False
    fetch_last_error: Optional[str] = None
    counts: dict[str, int] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Fetch / job responses
# ---------------------------------------------------------------------------

class FetchResponse(BaseModel):
    """Response from POST /v1/fetch."""

    status: str = Field(description="'started' or 'already_running'")
