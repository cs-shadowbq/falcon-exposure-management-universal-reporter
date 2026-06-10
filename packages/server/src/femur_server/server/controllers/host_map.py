"""Host map controller — ``GET /v1/host_map``."""

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from ..dependencies import get_store
from ..models import HostMapResponse
from ..store import InventoryStore

router = APIRouter(tags=["host_map"])


@router.get(
    "/host_map",
    response_model=HostMapResponse,
    summary="Full host map (Discover host ID → agent details)",
    response_description="Complete host map dictionary, optionally filtered by aid or cid",
)
def get_host_map(
    aid: Optional[str] = Query(None, description="Filter entries by agent ID"),
    cid: Optional[str] = Query(None, description="Filter entries by CID (tenant)"),
    store: InventoryStore = Depends(get_store),
) -> HostMapResponse:
    hm = store.get_host_map()
    if aid:
        hm = {k: v for k, v in hm.items() if v.get("aid") == aid}
    if cid:
        hm = {k: v for k, v in hm.items() if v.get("cid") == cid}
    return HostMapResponse(host_map=hm)


@router.get(
    "/host_map/by-aid/{aid}",
    response_model=HostMapResponse,
    summary="Host map entries for a specific agent ID",
    response_description="Host map entries matching the given aid",
)
def host_map_by_aid(
    aid: str,
    store: InventoryStore = Depends(get_store),
) -> HostMapResponse:
    hm = {k: v for k, v in store.get_host_map().items() if v.get("aid") == aid}
    return HostMapResponse(host_map=hm)
