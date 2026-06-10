# femur-server

REST API server for the CrowdStrike Falcon Exposure Management Universal Reporter (FEMUR). Serves pre-fetched inventory data over HTTP and optionally triggers background re-fetches when data becomes stale.

This package is a thin transport layer. All data is produced by [`femur-cli`](../cli/README.md) and stored as JSONL files on disk; the server reads those files into memory and exposes them via FastAPI endpoints.

## Requirements

- Python 3.10+
- JSONL output directory produced by `femur --output-format jsonl`
- (Optional) Credentials env file for background re-fetch

## Installation

```bash
pip install femur-server
```

Or in editable mode from the monorepo root:

```bash
pip install -e packages/server
```

## Usage

### Command line

```bash
femurd --data-dir ./inventory --env-file talon1.env
```

| Flag | Default | Description |
|---|---|---|
| `--data-dir` / `-d` | *(required)* | Directory containing JSONL output from `femur` |
| `--env-file` / `-e` | — | Env file with CrowdStrike credentials (enables background re-fetch) |
| `--max-age` | `10800` | Data age in seconds before a background re-fetch is triggered (default: 3h) |
| `--host` | `127.0.0.1` | Bind address |
| `--port` | `8000` | Bind port |
| `--reload` | off | Enable auto-reload for development |
| `--workers` | `1` | Number of uvicorn worker processes |

### Uvicorn factory (advanced)

```bash
uvicorn femur_server.server.app:create_app --factory \
    --host 0.0.0.0 --port 8000 --workers 4
```

Set configuration via environment variables when using the factory directly:

| Variable | Description |
|---|---|
| `FEMUR_DATA_DIR` | Directory with JSONL output files |
| `FEMUR_ENV_FILE` | Credentials env file for background re-fetch |
| `FEMUR_MAX_AGE` | Max data age in seconds (default: `10800`) |

## API Endpoints

Interactive docs are available at `http://localhost:8000/docs` (Swagger UI) and `http://localhost:8000/redoc` once the server is running.

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Liveness check with data freshness and staleness status |
| `GET` | `/v1/applications` | Paginated list of discovered applications |
| `GET` | `/v1/vulnerabilities` | Paginated list of Spotlight vulnerabilities |
| `GET` | `/v1/assessments` | Paginated list of configuration assessment findings |
| `GET` | `/v1/host_map` | Host identity map (`disc_id` → `{ cid, aid }`) |
| `GET` | `/v1/counts` | Record counts per dataset from the manifest |
| `POST` | `/v1/fetch` | Trigger a background inventory re-fetch |

### Pagination

`/v1/applications`, `/v1/vulnerabilities`, and `/v1/assessments` all support:

| Parameter | Default | Description |
|---|---|---|
| `limit` | `100` | Page size (max `10000`) |
| `offset` | `0` | Starting record offset |
| `q` | — | Substring search across JSON-serialised records |

### Health response

```json
{
  "status": "ok",
  "generated_at": "2026-03-30T04:00:00+00:00",
  "age_seconds": 3602.4,
  "stale": false,
  "fetch_running": false,
  "fetch_last_error": null,
  "counts": { "applications": 12450, "vulnerabilities": 38100, "assessments": 9200 }
}
```

## Background Re-fetch

When `--env-file` is provided the server checks data freshness on startup and each time `/health` is polled. If the data is older than `--max-age` seconds, `femur` is invoked as a subprocess in a background thread. The store is reloaded from disk once the fetch completes. Only one fetch runs at a time; `POST /v1/fetch` returns `"already_running"` if triggered again mid-run.

## Data Flow

```
femur (CLI)
       │
       ▼
  ./inventory/
    ├── manifest.json
    ├── applications.jsonl
    ├── vulnerabilities.jsonl
    ├── assessments.jsonl
    └── host_map.jsonl
       │
       ▼
  InventoryStore (in-memory)
       │
       ▼
  FastAPI endpoints → HTTP clients
```

## Development

```bash
# Run tests
pytest packages/server/tests/

# Start with auto-reload
femurd -d ./data/talon1_severity --reload
```
