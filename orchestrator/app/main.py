from __future__ import annotations

import hashlib
import io
import time
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, generate_latest, CONTENT_TYPE_LATEST
import logging
import os
from pathlib import Path
import httpx
import re
import magic
from urllib.parse import urlparse, unquote
import json as _json

from .schemas import AnalyzeRequest, AnalyzeResponse, JobState, JobsResponse
from .state import JobStore
from .archive import detect_archive
from .storage import save_bytes, write_job_meta, dir_size_bytes, cleanup_retention


app = FastAPI(title="ZORBOX Orchestrator", version="0.1.0")

# CORS for local dev UI (configurable via env)
UI_ORIGIN = os.getenv("UI_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[UI_ORIGIN],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = JobStore()
_AUDIT: list[dict] = []

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
SANDBOX_BASE = os.getenv("SANDBOX_BASE", "http://localhost:8050")
CUCKOO_BASE = os.getenv("CUCKOO_BASE")  # e.g., http://cuckoo:8090
CAPE_BASE = os.getenv("CAPE_BASE")      # e.g., http://cape:8000
URL_ALLOWLIST = os.getenv("URL_ALLOWLIST")  # comma-separated host patterns
URL_BLOCKLIST = os.getenv("URL_BLOCKLIST")  # comma-separated host patterns
UPLOADS_QUOTA_MB = int(os.getenv("UPLOADS_QUOTA_MB", "0") or 0)  # 0 disables
RETENTION_HOURS = int(os.getenv("RETENTION_HOURS", "0") or 0)    # 0 disables


def _sanitize_filename(name: str) -> str:
    # Remove directory separators and keep a safe subset of chars
    safe = []
    for ch in name:
        if ch.isalnum() or ch in ('.', '-', '_'):
            safe.append(ch)
        else:
            safe.append('_')
    cleaned = ''.join(safe).lstrip('._')
    return cleaned or 'download.bin'


def _extract_filename(headers: dict, url: str) -> str:
    cd = headers.get('Content-Disposition') or headers.get('content-disposition')
    filename = None
    if cd:
        parts = [p.strip() for p in cd.split(';')]
        # RFC 5987: filename*=UTF-8''encoded
        for p in parts:
            if p.lower().startswith('filename*='):
                val = p.split('=', 1)[1]
                try:
                    if "''" in val:
                        _, enc_val = val.split("''", 1)
                        filename = unquote(enc_val.strip('"'))
                    else:
                        filename = unquote(val.strip('"'))
                except Exception:
                    pass
                break
        if not filename:
            for p in parts:
                if p.lower().startswith('filename='):
                    val = p.split('=', 1)[1]
                    filename = val.strip('"')
                    break
    if not filename:
        p = urlparse(url)
        filename = Path(p.path).name or 'download.bin'
    return _sanitize_filename(filename)


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


def _audit(event: str, job_id: Optional[str] = None, payload: Optional[dict] = None) -> None:
    try:
        rec = {"ts": time.time(), "event": event, "job_id": job_id, "payload": payload or {}}
        _AUDIT.append(rec)
        if len(_AUDIT) > 1000:
            del _AUDIT[: len(_AUDIT) - 1000]
        try:
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
            with open(UPLOAD_DIR / 'audit.log', 'a', encoding='utf-8') as f:
                f.write(_json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception:
            pass
    except Exception:
        pass


def _host_allowed(url: str) -> bool:
    try:
        h = urlparse(url).hostname or ""
    except Exception:
        return False
    # blocklist first
    if URL_BLOCKLIST:
        for pat in URL_BLOCKLIST.split(','):
            pat = pat.strip()
            if not pat:
                continue
            if re.fullmatch(pat.replace('.', r'\.').replace('*', '.*'), h):
                return False
    if URL_ALLOWLIST:
        for pat in URL_ALLOWLIST.split(','):
            pat = pat.strip()
            if not pat:
                continue
            if re.fullmatch(pat.replace('.', r'\.').replace('*', '.*'), h):
                return True
        return False
    return True


def _download_with_retries(url: str, client: httpx.Client, retries: int = 3):
    last_exc = None
    for attempt in range(retries):
        try:
            r = client.get(url)
            return r
        except Exception as e:
            last_exc = e
            time.sleep(min(2 ** attempt * 0.5, 2.0))
    if last_exc:
        raise last_exc
    raise RuntimeError("download failed")


def _enforce_quota(incoming_size: int) -> None:
    if UPLOADS_QUOTA_MB and UPLOADS_QUOTA_MB > 0:
        try:
            current = dir_size_bytes(UPLOAD_DIR)
            if current + incoming_size > UPLOADS_QUOTA_MB * 1024 * 1024:
                raise RuntimeError("storage quota exceeded")
        except Exception as e:
            # If quota computation fails, be conservative
            raise RuntimeError(f"quota check failed: {e}")


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


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
    # Generate report while in 'reporting' state so exports are ready when 'done'
    try:
        _maybe_generate_report(job_id)
    except Exception as e:
        logger.exception({"event": "report_error", "job_id": job_id, "error": str(e)})
    time.sleep(0.1)

    store.set_state(job_id, JobState.done)
    _update_gauges()
    job_latency.observe(time.time() - start_time)


def _maybe_generate_report(job_id: str) -> None:
    job = store.get(job_id)
    if not job:
        return
    analysis = {
        "id": job.id,
        "title": f"Job {job.id}",
        "summary": f"File {job.file_name} analyzed (MVP report).",
        "file": {"name": job.file_name, "size": job.file_size, "sha256": job.file_sha256},
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
    # sandbox-native run(s)
    try:
        # determine adapters to try
        adapters_list = list(job.adapters) if job.adapters else ["bwrap", "firejail", "strace", "nsjail"]
        # append remote OSS adapters if configured via env and not explicitly requested
        if not job.adapters:
            if CUCKOO_BASE:
                adapters_list.append("cuckoo")
            if CAPE_BASE:
                adapters_list.append("cape")
        sand_results = []
        if job.file_name and job.file_size:
            file_path = (UPLOAD_DIR / job.id / job.file_name)
            if file_path.exists():
                for ad in adapters_list:
                    try:
                        if ad == "firejail":
                            with open(file_path, 'rb') as f:
                                files = {'file': (job.file_name, f, 'application/octet-stream')}
                                data = {"adapter": ad}
                                with httpx.Client(timeout=15) as client:
                                    sr = client.post(f"{SANDBOX_BASE}/run", files=files, data=data)
                                    if sr.status_code == 200:
                                        sand_results.append(sr.json())
                        elif ad == "cuckoo":
                            if not CUCKOO_BASE:
                                raise RuntimeError("CUCKOO_BASE not configured")
                            with open(file_path, 'rb') as f:
                                files = {'file': (job.file_name, f, 'application/octet-stream')}
                                with httpx.Client(timeout=8) as client:
                                    cr = client.post(f"{CUCKOO_BASE.rstrip('/')}/tasks/create/file", files=files)
                                    task_id = None
                                    status = "submitted"
                                    try:
                                        jd = cr.json()
                                        task_id = jd.get('task_id') or jd.get('taskid')
                                    except Exception:
                                        pass
                                    sand_results.append({
                                        "adapter": "cuckoo",
                                        "rc": 0 if cr.status_code < 400 else cr.status_code,
                                        "status": status,
                                        "task_id": task_id,
                                    })
                        elif ad == "cape":
                            if not CAPE_BASE:
                                raise RuntimeError("CAPE_BASE not configured")
                            with open(file_path, 'rb') as f:
                                files = {'file': (job.file_name, f, 'application/octet-stream')}
                                with httpx.Client(timeout=8) as client:
                                    rr = client.post(f"{CAPE_BASE.rstrip('/')}/tasks/create/file", files=files)
                                    task_id = None
                                    status = "submitted"
                                    try:
                                        jd = rr.json()
                                        task_id = jd.get('task_id') or jd.get('taskid')
                                    except Exception:
                                        pass
                                    sand_results.append({
                                        "adapter": "cape",
                                        "rc": 0 if rr.status_code < 400 else rr.status_code,
                                        "status": status,
                                        "task_id": task_id,
                                    })
                        else:
                            # Unknown adapter name: try native endpoint with given name, fallback record
                            with open(file_path, 'rb') as f:
                                files = {'file': (job.file_name, f, 'application/octet-stream')}
                                data = {"adapter": ad}
                                with httpx.Client(timeout=10) as client:
                                    sr = client.post(f"{SANDBOX_BASE}/run", files=files, data=data)
                                    if sr.status_code == 200:
                                        sand_results.append(sr.json())
                    except Exception as inner:
                        logger.warning({"event": "sandbox_error", "job_id": job.id, "adapter": ad, "error": str(inner)})
        if sand_results:
            analysis['sandboxes'] = sand_results
    except Exception as e:
        logger.warning({"event": "sandbox_error", "job_id": job.id, "error": str(e)})
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
        # include sha256 for hash reputation if available
        if job.file_sha256:
            ti_payload["hashes"] = [job.file_sha256]
        if ti_payload["domains"] or ti_payload["hashes"]:
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
    # persist meta after report
    try:
        base = UPLOAD_DIR / job.id
        write_job_meta(base, job.to_summary().model_dump())
    except Exception:
        pass


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
        try:
            _enforce_quota(file_size)
        except Exception as e:
            return JSONResponse(status_code=507, content={"detail": str(e)})
        file_hash = _sha256_bytes(data)
        file_md5 = _md5_bytes(data)
        try:
            m = magic.Magic(mime=True)
            mime_detected = m.from_buffer(data[:4096])
        except Exception:
            mime_detected = None
        mime_mismatch = None
        try:
            ext = (Path(file_name).suffix or '').lower()
            expected = {
                '.zip': 'zip', '.pdf': 'pdf', '.exe': 'executable', '.dll': 'executable',
                '.js': 'javascript', '.ps1': 'text', '.docx': 'zip', '.xlsx': 'zip', '.pptx': 'zip',
                '.rar': 'rar', '.7z': '7-zip', '.apk': 'android', '.jar': 'java',
            }.get(ext)
            if mime_detected and expected:
                mime_mismatch = (expected not in mime_detected)
        except Exception:
            mime_mismatch = None
        arch = detect_archive(file_name, data)
        requires_password = False
        archive_type = None
        if arch:
            archive_type, is_encrypted, _cnt = arch
            if is_encrypted and not password:
                requires_password = True
            # 7z: attempt to detect encryption by listing members
            if archive_type == '7z' and not requires_password:
                try:
                    from .archive import list_7z_members
                    _members = list_7z_members(data, password=password)
                except Exception:
                    if not password:
                        requires_password = True
            # RAR: conservatively require password if not provided (cannot reliably detect without backend)
            if archive_type == 'rar' and not password:
                requires_password = True
        job = store.create(file_name=file_name, file_size=file_size, file_sha256=file_hash)
        if adapters:
            job.adapters = [a.strip() for a in adapters.split(',') if a.strip()]
        job.file_md5 = file_md5
        job.mime_detected = mime_detected
        job.mime_mismatch = mime_mismatch
        job.archive_type = archive_type
        job.requires_password = requires_password
        if requires_password:
            store.set_state(job.id, JobState.waiting_password, error=None)
            _update_gauges()
            try:
                base = UPLOAD_DIR / job.id
                rel_name = file_name or "sample.bin"
                _path, digest, size = save_bytes(base, rel_name, data)
                job.file_sha256 = digest
                job.file_size = size
                write_job_meta(base, job.to_summary().model_dump())
            except Exception as e:
                store.set_state(job.id, JobState.failed, error=f"storage/meta error: {e}")
                _update_gauges()
                return AnalyzeResponse(job_id=job.id, accepted=False)
            try:
                _audit("job_waiting_password", job.id, {"file": file_name, "size": file_size, "archive": archive_type})
            except Exception:
                pass
            return AnalyzeResponse(job_id=job.id, accepted=True)
        try:
            base = UPLOAD_DIR / job.id
            rel_name = file_name or "sample.bin"
            _path, digest, size = save_bytes(base, rel_name, data)
            job.file_sha256 = digest
            job.file_size = size
            try:
                write_job_meta(base, job.to_summary().model_dump())
            except Exception as e:
                store.set_state(job.id, JobState.failed, error=f"meta write error: {e}")
                _update_gauges()
                return AnalyzeResponse(job_id=job.id, accepted=False)
            # Optional archive handling
            if archive_type == 'zip':
                try:
                    from .archive import extract_zip, list_zip_members
                    out_dir = str((base / 'extracted').resolve())
                    # If password given, attempt extraction with it; else just list members
                    if password:
                        members = extract_zip(data, out_dir, password=password)
                        job.archive_members = members
                    else:
                        job.archive_members = list_zip_members(data)
                except Exception as e:
                    logger.warning({"event": "zip_extract_error", "job_id": job.id, "error": str(e)})
            elif archive_type == '7z':
                try:
                    from .archive import list_7z_members
                    job.archive_members = list_7z_members(data, password=password)
                except Exception as e:
                    logger.warning({"event": "7z_list_error", "job_id": job.id, "error": str(e)})
            elif archive_type == 'rar' and password:
                try:
                    from .archive import list_rar_members
                    job.archive_members = list_rar_members(data, password=password)
                except Exception as e:
                    logger.warning({"event": "rar_list_error", "job_id": job.id, "error": str(e)})
        except Exception as e:
            store.set_state(job.id, JobState.failed, error=f"storage error: {e}")
            _update_gauges()
            return AnalyzeResponse(job_id=job.id, accepted=False)
        jobs_submitted.inc()
        _update_gauges()
        try:
            if archive_type == 'zip' and password:
                from .archive import list_zip_members
                job.archive_members = list_zip_members(data, password=password)
        except Exception as e:
            logger.warning({"event": "zip_list_error", "job_id": job.id, "error": str(e)})
        start_ts = time.time()
        background.add_task(_simulate_pipeline, job.id, start_ts)
        try:
            _audit("job_submitted", job.id, {"file": file_name, "size": file_size, "adapters": job.adapters})
        except Exception:
            pass
        return AnalyzeResponse(job_id=job.id, accepted=True)

    # Case 2: URL download
    if url:
        try:
            if not _host_allowed(url):
                return JSONResponse(status_code=400, content={"detail": "URL host not allowed"})
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                try:
                    hr = client.head(url)
                    if hr.status_code < 400:
                        cl = int(hr.headers.get('Content-Length', '0'))
                        if cl > MAX_UPLOAD_BYTES:
                            return JSONResponse(status_code=413, content={"detail": "remote file too large (>10MB)"})
                except Exception:
                    pass
                r = _download_with_retries(url, client, retries=3)
                r.raise_for_status()
                data = r.content
                if len(data) <= 0 or len(data) > MAX_UPLOAD_BYTES:
                    return JSONResponse(status_code=413, content={"detail": "remote file size must be 0 < size <= 10MB"})
                try:
                    _enforce_quota(len(data))
                except Exception as e:
                    return JSONResponse(status_code=507, content={"detail": str(e)})
                fn = _extract_filename(dict(r.headers), url)
                sha = _sha256_bytes(data)
                md5 = _md5_bytes(data)
                try:
                    m = magic.Magic(mime=True)
                    mime_detected = m.from_buffer(data[:4096])
                except Exception:
                    mime_detected = None
                mime_mismatch = None
                try:
                    ext = (Path(fn).suffix or '').lower()
                    expected = {
                        '.zip': 'zip', '.pdf': 'pdf', '.exe': 'executable', '.dll': 'executable',
                        '.js': 'javascript', '.ps1': 'text', '.docx': 'zip', '.xlsx': 'zip', '.pptx': 'zip',
                        '.rar': 'rar', '.7z': '7-zip', '.apk': 'android', '.jar': 'java',
                    }.get(ext)
                    if mime_detected and expected:
                        mime_mismatch = (expected not in mime_detected)
                except Exception:
                    mime_mismatch = None
                job = store.create(file_name=fn, file_size=len(data), file_sha256=sha)
                if adapters:
                    job.adapters = [a.strip() for a in adapters.split(',') if a.strip()]
                job.file_md5 = md5
                job.mime_detected = mime_detected
                job.mime_mismatch = mime_mismatch
                job.source_url = url
                job.http_status = r.status_code
                try:
                    job.http_headers = dict(r.headers)
                except Exception:
                    job.http_headers = None
                jobs_submitted.inc()
                _update_gauges()
                try:
                    base = UPLOAD_DIR / job.id
                    _path, digest, size = save_bytes(base, fn, data)
                    job.file_sha256 = digest
                    job.file_size = size
                    try:
                        write_job_meta(base, job.to_summary().model_dump())
                    except Exception as e:
                        store.set_state(job.id, JobState.failed, error=f"meta write error: {e}")
                        _update_gauges()
                        return AnalyzeResponse(job_id=job.id, accepted=False)
                    # Optional archive handling (URL case)
                    from .archive import detect_archive
                    arch = detect_archive(fn, data)
                    job.archive_type = arch[0] if arch else None
                    if arch:
                        a_type, a_enc, _ = arch
                        # If encrypted and no password provided, mark waiting
                        if a_enc and not password:
                            job.requires_password = True
                        elif a_type == '7z':
                            try:
                                from .archive import list_7z_members
                                job.archive_members = list_7z_members(data, password=password)
                            except Exception:
                                if not password:
                                    job.requires_password = True
                        elif a_type == 'zip':
                            try:
                                from .archive import list_zip_members
                                job.archive_members = list_zip_members(data)
                            except Exception:
                                pass
                        elif a_type == 'rar' and not password:
                            job.requires_password = True
                except Exception as e:
                    store.set_state(job.id, JobState.failed, error=f"storage error: {e}")
                    _update_gauges()
                    return AnalyzeResponse(job_id=job.id, accepted=False)
                # If password required, pause pipeline and wait for user-provided password
                if job.requires_password:
                    store.set_state(job.id, JobState.waiting_password, error=None)
                    _update_gauges()
                    return AnalyzeResponse(job_id=job.id, accepted=True)
                start_ts = time.time()
                background.add_task(_simulate_pipeline, job.id, start_ts)
                try:
                    _audit("job_submitted", job.id, {"url": url, "size": len(data), "adapters": job.adapters})
                except Exception:
                    pass
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
    # Opportunistic retention cleanup
    try:
        if RETENTION_HOURS and RETENTION_HOURS > 0:
            cleanup_retention(UPLOAD_DIR, RETENTION_HOURS)
    except Exception:
        pass
    output = generate_latest(registry)
    return PlainTextResponse(output.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


@app.post("/provide-password")
async def provide_password(payload: dict):
    job_id = payload.get("job_id")
    password = payload.get("password")
    job = store.get(job_id) if job_id else None
    if not job:
        return JSONResponse(status_code=404, content={"detail": "job not found"})
    if not password:
        return JSONResponse(status_code=400, content={"detail": "password is required"})
    # Only applicable if waiting for password
    if job.state != JobState.waiting_password:
        return JSONResponse(status_code=409, content={"detail": "job not waiting for password"})
    try:
        base = UPLOAD_DIR / job.id
        file_path = base / (job.file_name or "sample.bin")
        if not file_path.exists():
            return JSONResponse(status_code=404, content={"detail": "stored file missing"})
        data = file_path.read_bytes()
        # Process archive with provided password
        arch = detect_archive(job.file_name, data)
        if arch and arch[0] == 'zip':
            from .archive import list_zip_members, extract_zip
            try:
                # list members to validate password
                members = list_zip_members(data, password=password)
                job.archive_members = members
                # optionally extract limited files
                out_dir = str((base / 'extracted').resolve())
                extract_zip(data, out_dir, password=password)
            except Exception as e:
                return JSONResponse(status_code=400, content={"detail": f"zip error: {e}"})
        elif arch and arch[0] == '7z':
            try:
                from .archive import list_7z_members
                members = list_7z_members(data, password=password)
                job.archive_members = members
            except Exception as e:
                return JSONResponse(status_code=400, content={"detail": f"7z error: {e}"})
        elif arch and arch[0] == 'rar':
            try:
                from .archive import list_rar_members
                members = list_rar_members(data, password=password)
                job.archive_members = members
            except Exception as e:
                # RAR support optional; surface clear message
                return JSONResponse(status_code=501, content={"detail": f"rar listing not available: {e}"})
        # Mark password provided and continue pipeline
        job.requires_password = False
        store.set_state(job.id, JobState.queued)
        _update_gauges()
        try:
            write_job_meta(base, job.to_summary().model_dump())
        except Exception:
            pass
        start_ts = time.time()
        _simulate_pipeline(job.id, start_ts)
        _audit("password_provided", job.id, {"archive": arch[0] if arch else None})
        return {"accepted": True, "job_id": job.id}
    except Exception as e:
        logger.exception({"event": "provide_password_error", "job_id": job.id, "error": str(e)})
        return JSONResponse(status_code=500, content={"detail": "internal error"})


@app.post("/frontend-errors")
async def frontend_errors_ingest(payload: dict):
    frontend_errors.inc()
    logger.info({"event": "frontend_error", "payload": payload})
    try:
        _audit("frontend_error", None, payload)
    except Exception:
        pass
    return JSONResponse(status_code=202, content={"accepted": True})


@app.get("/audit")
def audit(limit: int = 100):
    try:
        limit = max(1, min(1000, int(limit)))
    except Exception:
        limit = 100
    # Return the most recent first
    items = list(_AUDIT[-limit:])
    items.reverse()
    return {"items": items}


 
                        
