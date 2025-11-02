# Orchestrator Service (MVP)

FastAPI-based pipeline coordinator for ZORBOX. Provides job submission, status retrieval, and Prometheus metrics.

## Endpoints
- `POST /analyze` — Accept file upload or URL, optional `password`, optional `adapters[]`. Returns `{ job_id, accepted }`.
- `GET /result/{id}` — Returns job snapshot including state and timestamps.
- `GET /jobs` — Filter by `state` query (e.g., `?state=queued`).
- `GET /metrics` — Prometheus metrics.
- `GET /healthz` — Liveness check.
- `POST /frontend-errors` — Accepts frontend error events (increments `frontend_errors_total`).
- `POST /frontend-rum` — Accepts frontend RUM events (increments `frontend_rum_events_total`).
- `POST /feedback` — Accept feedback for a job `{ job_id, kind, comment }`.
- `POST /reanalysis` — Request re-analysis `{ job_id }` → `{ job_id }` for new job.

## Development
- Python 3.11+
- Install: `pip install -e .`
- Run: `uvicorn app.main:app --reload --port 8080`

## Metrics (initial)
- `orchestrator_jobs_in_state{state}` (gauge)
- `orchestrator_queue_length` (gauge)
- `orchestrator_job_latency_seconds` (histogram)
- `frontend_errors_total` (counter)
- `frontend_rum_events_total` (counter)

## Notes
- In-memory store with on-disk snapshots can be added for durability.
- Adapters and downstream services are stubbed in this MVP.
- Reporter integration: set `REPORTER_BASE` (default `http://localhost:8090`).
- Static analyzer integration: set `ANALYZER_BASE` (default `http://localhost:8060`).
- Optional OSS sandbox integrations via API:
  - `CUCKOO_BASE` (e.g., `http://cuckoo:8090`) enables submitting samples to Cuckoo (`tasks/create/file`).
  - `CAPE_BASE` (e.g., `http://cape:8000`) enables submitting samples to CAPE (`tasks/create/file`).
  - When set, orchestrator will include these adapters in the sandbox list unless explicit `adapters` are provided in the request.

## Constraints (MVP)
- Max upload size: 10 MB (`0 < size ≤ 10MB`). Larger uploads return HTTP 413.
- Either `file` or `url` must be provided in `/analyze`.
- Encrypted ZIP without `password` is rejected (`accepted=false`) and job is marked failed with error.

## Storage & Archive (MVP)
- Safe path utilities prevent zip-slip; only ZIP detection via stdlib implemented.
- RAR/7Z planned via external libs; currently not enabled in MVP.
