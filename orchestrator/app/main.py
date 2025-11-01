from __future__ import annotations

import hashlib
import io
import time
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, Query
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
import logging
import os
from pathlib import Path
import httpx
from urllib.parse import urlparse

from .schemas import AnalyzeRequest, AnalyzeResponse, JobState, JobsResponse
from .state import JobStore
from .archive import detect_archive
from .storage import save_bytes


app = FastAPI(title="ZORBOX Orchestrator", version="0.1.0")

store = JobStore()

registry = CollectorRegistry()
jobs_in_state = Gauge("orchestrator_jobs_in_state", "Jobs per state", labelnames=("state",), registry=registry)
queue_length = Gauge("orchestrator_queue_length", "Jobs in queue", registry=registry)
job_latency = Histogram(
    "orchestrator_job_latency_seconds",
    "Time from submission to done",
    registry=registry,
    buckets=(0.5, 1, 2, 5, 10, 30, 60, 120, 300),
)
jobs_submitted = Counter("orchestrator_jobs_submitted_total", "Submitted jobs", registry=registry)
frontend_errors = Counter("frontend_errors_total", "Frontend errors received", registry=registry)
frontend_rum_events = Counter("frontend_rum_events_total", "Frontend RUM events received", registry=registry)

logger = logging.getLogger("zorbox.orchestrator")
logging.basicConfig(level=logging.INFO)

REPORTER_BASE = os.getenv("REPORTER_BASE", "http://localhost:8090")
UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"
ANALYZER_BASE = os.getenv("ANALYZER_BASE", "http://localhost:8060")
TI_BASE = os.getenv("TI_BASE", "http://localhost:8070")


def _update_gauges() -> None:
    # Reset and recount
    for st in JobState:
        jobs_in_state.labels(state=st.value).set(0)
    counts = {st: 0 for st in JobState}
    for j in store.by_state(None):
        counts[j.state] += 1
    for st, c in counts.items():
        jobs_in_state.labels(state=st.value).set(c)
    queue_length.set(len(store.by_state(JobState.queued)))


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _simulate_pipeline(job_id: str, start_time: float) -> None:
    # Simulates the pipeline state progression for MVP
    store.set_state(job_id, JobState.running)
    _update_gauges()
    time.sleep(0.2)

    store.set_state(job_id, JobState.enriching)
    _update_gauges()
    time.sleep(0.2)

    store.set_state(job_id, JobState.reporting)
    _update_gauges()
    time.sleep(0.2)

    store.set_state(job_id, JobState.done)
    _update_gauges()
    job_latency.observe(time.time() - start_time)
    try:
        _maybe_generate_report(job_id)
    except Exception as e:
        logger.exception({"event": "report_error", "job_id": job_id, "error": str(e)})


def _maybe_generate_report(job_id: str) -> None:
    job = store.get(job_id)
    if not job:
        return
    analysis = {
        "id": job.id,
        "title": f"Job {job.id}",
        "summary": f"File {job.file_name} analyzed (MVP report).",
        "file": {"name": job.file_name, "size": job.file_size, "sha256": job.file_sha256},
        "score": {"total": 42, "rules": []},
        "ti": {"domains": [], "ips": []},
    }
    # attach static analyzer findings if present
    try:
        if job.file_name and job.file_size:
            file_path = (UPLOAD_DIR / job.id / job.file_name)
            if file_path.exists():
                with open(file_path, 'rb') as f:
                    files = {'file': (job.file_name, f, 'application/octet-stream')}
                    with httpx.Client(timeout=15) as client:
                        ar = client.post(f"{ANALYZER_BASE}/analyze", files=files)
                        if ar.status_code == 200:
                            analysis['static'] = ar.json()
    except Exception as e:
        logger.warning({"event": "analyzer_error", "job_id": job.id, "error": str(e)})
    # TI enrichment
    try:
        ti_payload = {"domains": [], "ips": [], "hashes": []}
        static = analysis.get('static') or {}
        heur = static.get('heuristics') or {}
        urls = heur.get('urls_found') or []
        domains = []
        for u in urls:
            try:
                p = urlparse(u)
                if p.hostname:
                    domains.append(p.hostname)
            except Exception:
                pass
        if domains:
            ti_payload["domains"] = list({d for d in domains})[:20]
            with httpx.Client(timeout=10) as client:
                tr = client.post(f"{TI_BASE}/enrich", json=ti_payload)
                if tr.status_code == 200:
                    analysis['ti'] = tr.json().get('reputation', {})
    except Exception as e:
        logger.warning({"event": "ti_error", "job_id": job.id, "error": str(e)})
    url = f"{REPORTER_BASE}/report"
    with httpx.Client(timeout=10) as client:
        r = client.post(url, json=analysis)
        r.raise_for_status()
        data = r.json()
        job.export_json_url = data.get("json_url")
        job.export_pdf_url = data.get("pdf_url")
        job.export_stix_url = data.get("stix_url")


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    background: BackgroundTasks,
    file: Optional[UploadFile] = File(default=None),
    url: Optional[str] = Form(default=None),
    password: Optional[str] = Form(default=None),
    adapters: Optional[str] = Form(default=None),
):
    MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
    if file is None and not url:
        return JSONResponse(status_code=400, content={"detail": "file or url is required"})

    # Case 1: direct file upload
    if file is not None:
        data = await file.read()
        file_name = file.filename
        file_size = len(data)
        if file_size <= 0 or file_size > MAX_UPLOAD_BYTES:
            return JSONResponse(status_code=413, content={"detail": "file size must be 0 < size <= 10MB"})
        file_hash = _sha256_bytes(data)
        arch = detect_archive(file_name, data)
        requires_password = False
        archive_type = None
        if arch:
            archive_type, is_encrypted, _cnt = arch
            if is_encrypted and not password:
                requires_password = True
        job = store.create(file_name=file_name, file_size=file_size, file_sha256=file_hash)
        job.archive_type = archive_type
        job.requires_password = requires_password
        if requires_password:
            store.set_state(job.id, JobState.failed, error="password required for encrypted archive")
            _update_gauges()
            return AnalyzeResponse(job_id=job.id, accepted=False)
        try:
            base = UPLOAD_DIR / job.id
            rel_name = file_name or "sample.bin"
            _path, digest, size = save_bytes(base, rel_name, data)
            job.file_sha256 = digest
            job.file_size = size
        except Exception as e:
            store.set_state(job.id, JobState.failed, error=f"storage error: {e}")
            _update_gauges()
            return AnalyzeResponse(job_id=job.id, accepted=False)
        jobs_submitted.inc()
        _update_gauges()
        start_ts = time.time()
        background.add_task(_simulate_pipeline, job.id, start_ts)
        return AnalyzeResponse(job_id=job.id, accepted=True)

    # Case 2: URL download
    if url:
        try:
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                try:
                    hr = client.head(url)
                    if hr.status_code < 400:
                        cl = int(hr.headers.get('Content-Length', '0'))
                        if cl > MAX_UPLOAD_BYTES:
                            return JSONResponse(status_code=413, content={"detail": "remote file too large (>10MB)"})
                except Exception:
                    pass
                r = client.get(url)
                r.raise_for_status()
                data = r.content
                if len(data) <= 0 or len(data) > MAX_UPLOAD_BYTES:
                    return JSONResponse(status_code=413, content={"detail": "remote file size must be 0 < size <= 10MB"})
                fn = None
                cd = r.headers.get('Content-Disposition')
                if cd and 'filename=' in cd:
                    fn = cd.split('filename=')[-1].strip().strip('"')
                if not fn:
                    p = urlparse(url)
                    fn = Path(p.path).name or 'download.bin'
                job = store.create(file_name=fn, file_size=len(data), file_sha256=_sha256_bytes(data))
                jobs_submitted.inc()
                _update_gauges()
                try:
                    base = UPLOAD_DIR / job.id
                    _path, digest, size = save_bytes(base, fn, data)
                    job.file_sha256 = digest
                    job.file_size = size
                except Exception as e:
                    store.set_state(job.id, JobState.failed, error=f"storage error: {e}")
                    _update_gauges()
                    return AnalyzeResponse(job_id=job.id, accepted=False)
                start_ts = time.time()
                background.add_task(_simulate_pipeline, job.id, start_ts)
                return AnalyzeResponse(job_id=job.id, accepted=True)
        except Exception as e:
            return JSONResponse(status_code=400, content={"detail": f"download failed: {e}"})


@app.get("/result/{job_id}")
def result(job_id: str):
    job = store.get(job_id)
    if not job:
        return JSONResponse(status_code=404, content={"detail": "job not found"})
    return job.to_summary().model_dump()


@app.get("/jobs", response_model=JobsResponse)
def jobs(state: Optional[JobState] = Query(default=None)):
    items = [j.to_summary() for j in store.by_state(state)]
    return JobsResponse(items=items)


@app.get("/metrics")
def metrics():
    _update_gauges()
    output = generate_latest(registry)
    return PlainTextResponse(output.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


@app.post("/frontend-errors")
async def frontend_errors_ingest(payload: dict):
    frontend_errors.inc()
    logger.info({"event": "frontend_error", "payload": payload})
    return JSONResponse(status_code=202, content={"accepted": True})


feedback_received = Counter("feedback_received_total", "Feedback events", registry=registry)
reanalysis_requests = Counter("reanalysis_requests_total", "Reanalysis requests", registry=registry)


@app.post("/feedback")
async def feedback(payload: dict):
    job_id = payload.get("job_id")
    kind = payload.get("kind", "generic")
    comment = payload.get("comment")
    job = store.get(job_id) if job_id else None
    if not job:
        return JSONResponse(status_code=404, content={"detail": "job not found"})
    feedback_received.inc()
    logger.info({"event": "feedback", "job_id": job_id, "kind": kind, "comment": comment})
    return {"accepted": True}


@app.post("/reanalysis")
async def reanalysis(payload: dict):
    original_id = payload.get("job_id")
    orig = store.get(original_id) if original_id else None
    if not orig:
        return JSONResponse(status_code=404, content={"detail": "job not found"})
    reanalysis_requests.inc()
    new_job = store.create(file_name=orig.file_name, file_size=orig.file_size, file_sha256=orig.file_sha256)
    _update_gauges()
    start_ts = time.time()
    # BackgroundTasks instance may not be available here; simulate inline short delay
    _simulate_pipeline(new_job.id, start_ts)
    return {"job_id": new_job.id}


@app.post("/frontend-rum")
async def frontend_rum_ingest(payload: dict):
    frontend_rum_events.inc()
    logger.info({"event": "frontend_rum", "payload": payload})
    return JSONResponse(status_code=202, content={"accepted": True})
