from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI
from fastapi import Body
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.staticfiles import StaticFiles

from .pdf import build_pdf


EXPORT_DIR = Path(__file__).resolve().parent.parent / "exports"


app = FastAPI(title="ZORBOX Reporter", version="0.1.0")

registry = CollectorRegistry()
reports_generated = Counter("reporter_reports_generated_total", "Reports generated", registry=registry)
pdf_time = Histogram("reporter_pdf_generation_time_seconds", "PDF generation time", registry=registry)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def build_stix_bundle(analysis: Dict[str, Any]) -> Dict[str, Any]:
    # Minimal STIX 2.1-like bundle (not using stix2 lib in MVP)
    iocs = analysis.get("ti", {})
    indicators = []
    for d in iocs.get("domains", [])[:10]:
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--domain-{d}",
            "name": f"Domain indicator {d}",
            "pattern": f"[domain-name:value = '{d}']",
            "pattern_type": "stix",
        })
    for ip in iocs.get("ips", [])[:10]:
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--ip-{ip}",
            "name": f"IP indicator {ip}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
        })
    return {"type": "bundle", "spec_version": "2.1", "objects": indicators}


@app.post("/report")
def report(analysis: Dict[str, Any] = Body(...)):
    ensure_dir(EXPORT_DIR)
    job_id = analysis.get("id") or str(int(time.time()))
    base = EXPORT_DIR / job_id
    ensure_dir(base)

    # JSON export
    json_path = base / "report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(analysis, f, ensure_ascii=False, indent=2)

    # PDF export
    start = time.time()
    pdf_bytes = build_pdf(analysis)
    pdf_path = base / "report.pdf"
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    pdf_time.observe(time.time() - start)

    # STIX export (minimal)
    stix = build_stix_bundle(analysis)
    stix_path = base / "report.stix.json"
    with open(stix_path, "w", encoding="utf-8") as f:
        json.dump(stix, f, ensure_ascii=False, indent=2)

    reports_generated.inc()
    # Expose files over HTTP via static mount
    http_base = f"/exports/{job_id}"
    return {
        "json_url": f"{http_base}/report.json",
        "pdf_url": f"{http_base}/report.pdf",
        "stix_url": f"{http_base}/report.stix.json",
    }


@app.get("/metrics")
def metrics():
    output = generate_latest(registry)
    return PlainTextResponse(output.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)

# Mount static exports for HTTP access
ensure_dir(EXPORT_DIR)
app.mount("/exports", StaticFiles(directory=str(EXPORT_DIR), html=False), name="exports")
