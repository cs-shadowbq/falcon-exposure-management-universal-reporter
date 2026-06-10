"""Applications controller — ``GET /v1/applications``."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ..dependencies import get_max_age, get_store
from ..models import PageMeta, PaginatedResponse
from ..store import InventoryStore

router = APIRouter(tags=["applications"])


def _filter_applications(
    records: list[dict],
    *,
    q: Optional[str] = None,
    aid: Optional[str] = None,
    cid: Optional[str] = None,
    name: Optional[str] = None,
    vendor: Optional[str] = None,
    version: Optional[str] = None,
    software_type: Optional[str] = None,
    is_suspicious: Optional[bool] = None,
    name_vendor: Optional[str] = None,
    category: Optional[str] = None,
) -> list[dict]:
    """Apply all supported filters to application records."""
    if q:
        q_lower = q.lower()
        records = [
            r for r in records if q_lower in json.dumps(r, default=str).lower()
        ]
    if aid:
        records = [r for r in records if r.get("aid") == aid]
    if cid:
        records = [r for r in records if r.get("cid") == cid]
    if name:
        name_lower = name.lower()
        records = [r for r in records if name_lower in (r.get("name") or "").lower()]
    if vendor:
        vendor_lower = vendor.lower()
        records = [r for r in records if vendor_lower in (r.get("vendor") or "").lower()]
    if version:
        records = [r for r in records if r.get("version") == version]
    if software_type:
        records = [r for r in records if r.get("software_type") == software_type]
    if is_suspicious is not None:
        records = [r for r in records if r.get("is_suspicious") is is_suspicious]
    if name_vendor:
        nv_lower = name_vendor.lower()
        records = [r for r in records if nv_lower in (r.get("name_vendor") or "").lower()]
    if category:
        cat_lower = category.lower()
        records = [r for r in records if cat_lower in (r.get("category") or "").lower()]
    return records


@router.get(
    "/applications",
    response_model=PaginatedResponse,
    summary="Paginated list of discovered applications",
    response_description="Page of application records with pagination metadata",
)
def list_applications(
    limit: int = Query(100, ge=1, le=10_000, description="Page size"),
    offset: int = Query(0, ge=0, description="Starting record offset"),
    q: Optional[str] = Query(None, description="Substring search across JSON-serialised records"),
    aid: Optional[str] = Query(None, description="Filter by agent ID"),
    cid: Optional[str] = Query(None, description="Filter by CID (tenant)"),
    name: Optional[str] = Query(None, description="Substring match on application name"),
    vendor: Optional[str] = Query(None, description="Substring match on vendor"),
    version: Optional[str] = Query(None, description="Exact match on version"),
    software_type: Optional[str] = Query(None, description="Exact match on software_type"),
    is_suspicious: Optional[bool] = Query(None, description="Filter by is_suspicious flag"),
    name_vendor: Optional[str] = Query(None, description="Substring match on name_vendor"),
    category: Optional[str] = Query(None, description="Substring match on category"),
    store: InventoryStore = Depends(get_store),
    max_age: float = Depends(get_max_age),
) -> PaginatedResponse:
    records = _filter_applications(
        store.get_dataset("applications"),
        q=q, aid=aid, cid=cid, name=name, vendor=vendor,
        version=version, software_type=software_type,
        is_suspicious=is_suspicious, name_vendor=name_vendor,
        category=category,
    )
    total = len(records)
    page = records[offset: offset + limit]
    age = store.age_seconds or 0.0
    return PaginatedResponse(
        dataset="applications",
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
    "/applications/by-aid/{aid}",
    response_model=PaginatedResponse,
    summary="All applications for a specific agent ID",
    response_description="Application records matching the given aid",
)
def applications_by_aid(
    aid: str,
    limit: int = Query(100, ge=1, le=10_000, description="Page size"),
    offset: int = Query(0, ge=0, description="Starting record offset"),
    store: InventoryStore = Depends(get_store),
    max_age: float = Depends(get_max_age),
) -> PaginatedResponse:
    records = [r for r in store.get_dataset("applications") if r.get("aid") == aid]
    total = len(records)
    page = records[offset: offset + limit]
    age = store.age_seconds or 0.0
    return PaginatedResponse(
        dataset="applications",
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
