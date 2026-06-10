"""Fetch controller — ``POST /v1/fetch``."""

from fastapi import APIRouter, Depends

from ..dependencies import get_fetch_job, get_max_age, get_store
from ..jobs import FetchJob
from ..models import FetchResponse
from ..store import InventoryStore

router = APIRouter(tags=["fetch"])


@router.post(
    "/fetch",
    response_model=FetchResponse,
    summary="Trigger a background inventory re-fetch",
    response_description="Status of the fetch trigger ('started' or 'already_running')",
)
def trigger_fetch(
    store: InventoryStore = Depends(get_store),
    job: FetchJob = Depends(get_fetch_job),
) -> FetchResponse:
    started = job.trigger(store)
    if not started:
        return FetchResponse(status="already_running")
    return FetchResponse(status="started")
