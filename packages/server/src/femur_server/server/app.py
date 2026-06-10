"""FastAPI application factory for the Falcon Inventory REST API.

The :func:`create_app` factory wires up lifespan management, middleware,
error handlers, and all controller routers.  Uvicorn can invoke it as
a factory string::

    uvicorn femur_server.server.app:create_app --factory
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from .controllers import applications, assessments, counts, fetch, health, host_map, vulnerabilities
from .jobs import FetchJob
from .models import ErrorResponse
from .store import InventoryStore

log = logging.getLogger("femur.server")


# ---------------------------------------------------------------------------
# Configuration helper
# ---------------------------------------------------------------------------

def _configure_state(app: FastAPI) -> None:
    """Populate ``app.state`` from env vars or previously set attributes.

    Called during lifespan startup.  Reads:

    - ``FALCON_INVENTORY_DATA_DIR`` — directory with JSONL output
    - ``FALCON_INVENTORY_ENV_FILE`` — ``.env`` file for background re-fetch
    - ``FALCON_INVENTORY_MAX_AGE`` — max data age in seconds (default 10800)
    """
    data_dir: str | None = getattr(app.state, "data_dir", None) or os.environ.get(
        "FALCON_INVENTORY_DATA_DIR"
    )
    if data_dir is None:
        log.warning(
            "No data directory configured — set FALCON_INVENTORY_DATA_DIR "
            "or call configure() before startup"
        )
        return

    env_file: str | None = getattr(app.state, "env_file", None) or os.environ.get(
        "FALCON_INVENTORY_ENV_FILE"
    )
    max_age: float = getattr(
        app.state, "max_age", float(os.environ.get("FALCON_INVENTORY_MAX_AGE", "10800"))
    )

    store = InventoryStore(data_dir)
    job = FetchJob(data_dir, env_file=env_file)

    if Path(data_dir).exists():
        store.load()

    app.state.store = store
    app.state.fetch_job = job
    app.state.max_age = max_age


def _maybe_refresh(app: FastAPI) -> None:
    """Trigger a background re-fetch if data is stale."""
    store: InventoryStore | None = getattr(app.state, "store", None)
    job: FetchJob | None = getattr(app.state, "fetch_job", None)
    if store is None or job is None:
        return
    max_age: float = getattr(app.state, "max_age", 10800.0)
    age = store.age_seconds
    if age is None or age > max_age:
        job.trigger(store)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: configure store on startup, cleanup on shutdown."""
    _configure_state(app)
    _maybe_refresh(app)
    log.info("Falcon Inventory API server started")
    yield
    log.info("Falcon Inventory API server shutting down")


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    data_dir: Optional[str] = None,
    env_file: Optional[str] = None,
    max_age: float = 10800.0,
) -> FastAPI:
    """Create and configure a :class:`FastAPI` application.

    Parameters
    ----------
    data_dir :
        Directory containing JSONL output from ``femur``.
        Falls back to ``FALCON_INVENTORY_DATA_DIR`` env var.
    env_file :
        Env file for background re-fetch jobs.
    max_age :
        Max data age in seconds before background re-fetch (default 3h).
    """
    app = FastAPI(
        title="Falcon Inventory API",
        description=(
            "Serves pre-fetched CrowdStrike Falcon application inventory, "
            "vulnerability, and configuration assessment data over REST.\n\n"
            "Data is sourced from JSONL files produced by the "
            "`femur` CLI and cached in memory. When data exceeds "
            "the configured max-age, a background re-fetch is triggered "
            "automatically."
        ),
        version="2.0.0",
        lifespan=lifespan,
        responses={
            503: {"model": ErrorResponse, "description": "Store not configured"},
        },
    )

    # Store config for lifespan to pick up.
    if data_dir:
        app.state.data_dir = data_dir
    if env_file:
        app.state.env_file = env_file
    app.state.max_age = max_age

    # -- Middleware (order matters: last added = first executed) ---------------
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Error handlers -------------------------------------------------------
    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                error=type(exc).__name__,
                message=str(exc.detail),
                status=exc.status_code,
            ).model_dump(),
        )

    # -- Routers --------------------------------------------------------------
    app.include_router(health.router)
    app.include_router(applications.router, prefix="/v1")
    app.include_router(vulnerabilities.router, prefix="/v1")
    app.include_router(assessments.router, prefix="/v1")
    app.include_router(host_map.router, prefix="/v1")
    app.include_router(counts.router, prefix="/v1")
    app.include_router(fetch.router, prefix="/v1")

    # -- Root index -----------------------------------------------------------
    @app.get(
        "/",
        include_in_schema=False,
        summary="API index & documentation links",
    )
    def root() -> dict[str, Any]:
        return {
            "service": "Falcon Inventory API",
            "version": "2.0.0",
            "docs": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
            "endpoints": {
                "health": "/health",
                "applications": "/v1/applications",
                "vulnerabilities": "/v1/vulnerabilities",
                "assessments": "/v1/assessments",
                "host_map": "/v1/host_map",
                "counts": "/v1/counts",
                "fetch": "/v1/fetch",
            },
        }

    return app


def _cors_origins() -> list[str]:
    """Build CORS allow list from env vars.

    Always includes localhost dev servers.  Additional origins can be
    supplied via ``CORS_ORIGINS`` (comma-separated).
    """
    origins = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:8080",
    ]
    extra = os.environ.get("CORS_ORIGINS", "")
    if extra:
        origins.extend(o.strip() for o in extra.split(",") if o.strip())
    return origins
