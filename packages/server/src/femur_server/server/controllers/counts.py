"""Counts controller — ``GET /v1/counts``."""

from fastapi import APIRouter, Depends

from ..dependencies import get_store
from ..models import CountsResponse
from ..store import InventoryStore

router = APIRouter(tags=["counts"])


@router.get(
    "/counts",
    response_model=CountsResponse,
    summary="Record counts per dataset",
    response_description="Object with per-dataset record counts",
)
def get_counts(
    store: InventoryStore = Depends(get_store),
) -> CountsResponse:
    return CountsResponse(
        counts=store.counts,
        generated_at=store.generated_at,
    )
