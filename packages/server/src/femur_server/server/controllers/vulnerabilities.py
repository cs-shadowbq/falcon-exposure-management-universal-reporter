"""Vulnerabilities controller — ``GET /v1/vulnerabilities``."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_max_age, get_store
from ..models import PageMeta, PaginatedResponse
from ..store import InventoryStore

router = APIRouter(tags=["vulnerabilities"])


def _filter_vulnerabilities(
    records: list[dict],
    *,
    q: Optional[str] = None,
    aid: Optional[str] = None,
    cid: Optional[str] = None,
    vulnerability_id: Optional[str] = None,
    is_suppressed: Optional[bool] = None,
) -> list[dict]:
    """Apply all supported filters to vulnerability records."""
    if q:
        q_lower = q.lower()
        records = [
            r for r in records if q_lower in json.dumps(r, default=str).lower()
        ]
    if aid:
        records = [r for r in records if r.get("aid") == aid]
    if cid:
        records = [r for r in records if r.get("cid") == cid]
    if vulnerability_id:
        records = [r for r in records if r.get("vulnerability_id") == vulnerability_id]
    if is_suppressed is not None:
        records = [
            r for r in records
            if (r.get("suppression_info") or {}).get("is_suppressed") is is_suppressed
        ]
    return records


@router.get(
    "/vulnerabilities",
    response_model=PaginatedResponse,
    summary="Paginated list of Spotlight vulnerabilities",
    response_description="Page of vulnerability records with pagination metadata",
)
def list_vulnerabilities(
    limit: int = Query(100, ge=1, le=10_000, description="Page size"),
    offset: int = Query(0, ge=0, description="Starting record offset"),
    q: Optional[str] = Query(None, description="Substring search across JSON-serialised records"),
    aid: Optional[str] = Query(None, description="Filter by agent ID"),
    cid: Optional[str] = Query(None, description="Filter by CID (tenant)"),
    vulnerability_id: Optional[str] = Query(None, description="Exact match on vulnerability_id (e.g. CVE-2024-0001)"),
    is_suppressed: Optional[bool] = Query(None, description="Filter by suppression_info.is_suppressed"),
    store: InventoryStore = Depends(get_store),
    max_age: float = Depends(get_max_age),
) -> PaginatedResponse:
    records = _filter_vulnerabilities(
        store.get_dataset("vulnerabilities"),
        q=q, aid=aid, cid=cid,
        vulnerability_id=vulnerability_id, is_suppressed=is_suppressed,
    )
    total = len(records)
    page = records[offset: offset + limit]
    age = store.age_seconds or 0.0
    return PaginatedResponse(
        dataset="vulnerabilities",
        meta=PageMeta(
            total=total,
            offset=offset,
            limit=limit,
            count=len(page),
            generated_at=store.generated_at,
            data_age_seconds=round(age, 1),
            stale=age > max_age,
        ),
        records=page,
    )


@router.get(
    "/vulnerabilities/by-aid/{aid}",
    response_model=PaginatedResponse,
    summary="All vulnerabilities for a specific agent ID",
    response_description="Vulnerability records matching the given aid",
)
def vulnerabilities_by_aid(
    aid: str,
    limit: int = Query(100, ge=1, le=10_000, description="Page size"),
    offset: int = Query(0, ge=0, description="Starting record offset"),
    store: InventoryStore = Depends(get_store),
    max_age: float = Depends(get_max_age),
) -> PaginatedResponse:
    records = [r for r in store.get_dataset("vulnerabilities") if r.get("aid") == aid]
    total = len(records)
    page = records[offset: offset + limit]
    age = store.age_seconds or 0.0
    return PaginatedResponse(
        dataset="vulnerabilities",
        meta=PageMeta(
            total=total,
            offset=offset,
            limit=limit,
            count=len(page),
            generated_at=store.generated_at,
            data_age_seconds=round(age, 1),
            stale=age > max_age,
        ),
        records=page,
    )
