"""Assessments controller — ``GET /v1/assessments``."""

import json
from typing import Optional

from fastapi import APIRouter, Depends, Query

from ..dependencies import get_max_age, get_store
from ..models import PageMeta, PaginatedResponse
from ..store import InventoryStore

router = APIRouter(tags=["assessments"])


def _filter_assessments(
    records: list[dict],
    *,
    q: Optional[str] = None,
    aid: Optional[str] = None,
    cid: Optional[str] = None,
    status: Optional[str] = None,
    rule_name: Optional[str] = None,
    rule_platform: Optional[str] = None,
    rule_severity: Optional[str] = None,
    group_name: Optional[str] = None,
) -> list[dict]:
    """Apply all supported filters to assessment records."""
    if q:
        q_lower = q.lower()
        records = [
            r for r in records if q_lower in json.dumps(r, default=str).lower()
        ]
    if aid:
        records = [r for r in records if r.get("aid") == aid]
    if cid:
        records = [r for r in records if r.get("cid") == cid]
    if status:
        status_lower = status.lower()
        records = [
            r for r in records
            if (r.get("finding") or {}).get("status", "").lower() == status_lower
        ]
    if rule_name:
        rn_lower = rule_name.lower()
        records = [
            r for r in records
            if rn_lower in ((r.get("finding") or {}).get("rule") or {}).get("name", "").lower()
        ]
    if rule_platform:
        rp_lower = rule_platform.lower()
        records = [
            r for r in records
            if ((r.get("finding") or {}).get("rule") or {}).get("platform_name", "").lower() == rp_lower
        ]
    if rule_severity:
        rs_lower = rule_severity.lower()
        records = [
            r for r in records
            if ((r.get("finding") or {}).get("rule") or {}).get("severity", "").lower() == rs_lower
        ]
    if group_name:
        gn_lower = group_name.lower()
        records = [
            r for r in records
            if gn_lower in ((r.get("finding") or {}).get("rule") or {}).get("group_name", "").lower()
        ]
    return records


@router.get(
    "/assessments",
    response_model=PaginatedResponse,
    summary="Paginated list of configuration assessments",
    response_description="Page of assessment records with pagination metadata",
)
def list_assessments(
    limit: int = Query(100, ge=1, le=10_000, description="Page size"),
    offset: int = Query(0, ge=0, description="Starting record offset"),
    q: Optional[str] = Query(None, description="Substring search across JSON-serialised records"),
    aid: Optional[str] = Query(None, description="Filter by agent ID"),
    cid: Optional[str] = Query(None, description="Filter by CID (tenant)"),
    status: Optional[str] = Query(None, description="Filter by finding status (pass, fail, unsupported, manual, etc.)"),
    rule_name: Optional[str] = Query(None, description="Substring match on finding.rule.name"),
    rule_platform: Optional[str] = Query(None, description="Exact match on finding.rule.platform_name"),
    rule_severity: Optional[str] = Query(None, description="Exact match on finding.rule.severity (Critical, High, Medium, Low)"),
    group_name: Optional[str] = Query(None, description="Substring match on finding.rule.group_name"),
    store: InventoryStore = Depends(get_store),
    max_age: float = Depends(get_max_age),
) -> PaginatedResponse:
    records = _filter_assessments(
        store.get_dataset("assessments"),
        q=q, aid=aid, cid=cid, status=status,
        rule_name=rule_name, rule_platform=rule_platform,
        rule_severity=rule_severity, group_name=group_name,
    )
    total = len(records)
    page = records[offset: offset + limit]
    age = store.age_seconds or 0.0
    return PaginatedResponse(
        dataset="assessments",
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
    "/assessments/by-aid/{aid}",
    response_model=PaginatedResponse,
    summary="All assessments for a specific agent ID",
    response_description="Assessment records matching the given aid",
)
def assessments_by_aid(
    aid: str,
    limit: int = Query(100, ge=1, le=10_000, description="Page size"),
    offset: int = Query(0, ge=0, description="Starting record offset"),
    store: InventoryStore = Depends(get_store),
    max_age: float = Depends(get_max_age),
) -> PaginatedResponse:
    records = [r for r in store.get_dataset("assessments") if r.get("aid") == aid]
    total = len(records)
    page = records[offset: offset + limit]
    age = store.age_seconds or 0.0
    return PaginatedResponse(
        dataset="assessments",
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
