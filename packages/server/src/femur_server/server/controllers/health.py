"""Health controller — ``GET /health``."""

from fastapi import APIRouter, Depends

from ..dependencies import get_fetch_job, get_max_age, get_store
from ..jobs import FetchJob
from ..models import HealthResponse
from ..store import InventoryStore

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness and data freshness check",
    response_description="Current server health including data age and staleness",
)
def health(
    store: InventoryStore = Depends(get_store),
    job: FetchJob = Depends(get_fetch_job),
    max_age: float = Depends(get_max_age),
) -> HealthResponse:
    age = store.age_seconds or 0.0
    return HealthResponse(
        status="ok",
        generated_at=store.generated_at,
        age_seconds=round(age, 1),
        stale=age > max_age,
        fetch_running=job.is_running,
        fetch_last_error=job.last_error,
        counts=store.counts,
    )
