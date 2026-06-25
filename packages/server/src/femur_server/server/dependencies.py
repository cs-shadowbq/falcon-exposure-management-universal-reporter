"""Shared FastAPI dependencies for the Falcon Inventory API server.

Dependencies are injected via ``Depends()`` in controller signatures
so that controllers never access ``app.state`` directly.
"""

from __future__ import annotations

from fastapi import HTTPException, Request

from .jobs import FetchJob
from .store import InventoryStore


def get_store(request: Request) -> InventoryStore:
    """Return the shared :class:`InventoryStore` from application state.

    Raises 503 if the store has not been configured.
    """
    store: InventoryStore | None = getattr(request.app.state, "store", None)
    if store is None:
        raise HTTPException(503, "Store not configured")
    return store


def get_fetch_job(request: Request) -> FetchJob:
    """Return the shared :class:`FetchJob` from application state.

    Raises 503 if the fetch job has not been configured.
    """
    job: FetchJob | None = getattr(request.app.state, "fetch_job", None)
    if job is None:
        raise HTTPException(503, "Fetch job not configured")
    return job


def get_max_age(request: Request) -> float:
    """Return the configured max-age threshold (seconds)."""
    return getattr(request.app.state, "max_age", 10800.0)
