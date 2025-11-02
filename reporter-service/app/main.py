from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Body
from fastapi.responses import PlainTextResponse, JSONResponse
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.staticfiles import StaticFiles

from .pdf import build_pdf


def _flatten_ti_bad(reputation: Dict[str, Any]) -> int:
    bad = 0
    try:
        for cat in ("domains", "ips", "hashes"):
            vals = reputation.get(cat) or {}
            if isinstance(vals, dict):
                for _k, v in vals.items():
                    if str(v).lower() == "bad":
                        bad += 1
    except Exception:
        pass
    return bad


def ensure_score(analysis: Dict[str, Any]) -> None:
    # Build a transparent, lightweight score from available features.
    # Recompute if no score, or placeholder (e.g., total==42 with empty rules)
    if isinstance(analysis.get("score"), dict):
        cur = analysis["score"]
        cur_total = cur.get("total")
        cur_rules = cur.get("rules") or []
        if isinstance(cur_total, int) and cur_total != 42 and cur_rules:
            return
    rules = []
    total = 0
    static = analysis.get("static") or {}
    heur = static.get("heuristics") or {}
    details = static.get("details") or {}
    yara_hits = static.get("yara_hits") or []
    # YARA
    yh = len(yara_hits)
    if yh:
        pts = min(40, yh * 10)
        rules.append({"desc": f"YARA hits ({yh})", "hit": True, "points": pts})
        total += pts
    # Heuristic danger flags
    danger_keys = [
        "encoded_command", "suspicious_cmdlets", "uses_eval", "uses_unescape",
        "obfuscation_tokens", "openaction", "has_js", "macro_tokens",
    ]
    for k in danger_keys:
        if heur.get(k):
            rules.append({"desc": f"Heuristic: {k}", "hit": True, "points": 5})
            total += 5
    # URLs found (indicator of activity)
    urls = heur.get("urls_found") or []
    if isinstance(urls, list) and urls:
        pts = min(10, len(urls) * 2)
        rules.append({"desc": f"URLs found ({len(urls)})", "hit": True, "points": pts})
        total += pts
    # Office macros present
    try:
        office = details.get("office") or {}
        macros = office.get("macros") or {}
        if macros.get("present"):
            rules.append({"desc": "Office macros present", "hit": True, "points": 10})
            total += 10
    except Exception:
        pass
    # PE packer flags
    try:
        pe = details.get("pe") or {}
        if pe.get("packer_flags"):
            rules.append({"desc": "PE packer flags detected", "hit": True, "points": 10})
            total += 10
    except Exception:
        pass
    # PE suspicious imports
    try:
        pe = details.get("pe") or {}
        simps = pe.get("suspicious_imports") or []
        if isinstance(simps, list) and simps:
            pts = min(20, len(simps) * 2)
            rules.append({"desc": f"Suspicious imports ({len(simps)})", "hit": True, "points": pts})
            total += pts
    except Exception:
        pass
    # PE RWX sections
    try:
        pe = details.get("pe") or {}
        rwx = pe.get("rwx_sections") or []
        if isinstance(rwx, list) and rwx:
            rules.append({"desc": "RWX sections present", "hit": True, "points": 8})
            total += 8
    except Exception:
        pass
    # MIME mismatch (filename vs magic)
    try:
        # prefer orchestrator-captured flags if available
        if analysis.get("file") is None and analysis.get("mime_mismatch"):
            rules.append({"desc": "MIME does not match extension", "hit": True, "points": 5})
            total += 5
    except Exception:
        pass
    # TI bad reputation
    ti_rep = analysis.get("ti") or {}
    bad_cnt = _flatten_ti_bad(ti_rep)
    if bad_cnt:
        pts = min(32, bad_cnt * 8)
        rules.append({"desc": f"Threat intel bad indicators ({bad_cnt})", "hit": True, "points": pts})
        total += pts
    # Dynamic anomalies (non-zero rc)
    try:
        sands = analysis.get("sandboxes") or []
        nonzero = sum(1 for s in sands if (s.get("rc") or 0) != 0)
        if nonzero:
            pts = min(10, nonzero * 5)
            rules.append({"desc": f"Sandbox non-zero return codes ({nonzero})", "hit": True, "points": pts})
            total += pts
    except Exception:
        pass
    # Clamp and level
    total = int(max(0, min(100, total)))
    def level(v: int) -> str:
        if v >= 80: return "critical"
        if v >= 60: return "high"
        if v >= 30: return "medium"
        return "low"
    analysis["score"] = {"total": total, "rules": rules, "level": level(total)}


def compute_ai_score(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Lightweight linear model over transparent features with explainability."""
    static = analysis.get("static") or {}
    details = static.get("details") or {}
    heur = static.get("heuristics") or {}
    yara_hits = static.get("yara_hits") or []

    # Features
    f_num_yara = float(len(yara_hits) or 0)
    pe = details.get("pe") or {}
    f_sus_imports = float(len(pe.get("suspicious_imports") or []))
    f_rwx = float(len(pe.get("rwx_sections") or []))
    f_packer = 1.0 if pe.get("packer_flags") else 0.0
    urls = heur.get("urls_found") or []
    f_urls = float(len(urls) or 0)
    # TI bad indicators
    def _bad_cnt(rep: Dict[str, Any]) -> int:
        n = 0
        for cat in ("domains", "ips", "hashes"):
            vals = rep.get(cat) or {}
            if isinstance(vals, dict):
                for _k, v in vals.items():
                    if str(v).lower() == "bad": n += 1
        return n
    ti_rep = analysis.get("ti") or {}
    f_ti_bad = float(_bad_cnt(ti_rep))

    # Weights (tunable via env later)
    W = {
        "yara": 8.0,
        "sus_imports": 6.0,
        "rwx": 5.0,
        "packer": 5.0,
        "urls": 2.0,
        "ti_bad": 10.0,
    }
    raw = (
        f_num_yara * W["yara"] +
        f_sus_imports * W["sus_imports"] +
        f_rwx * W["rwx"] +
        f_packer * W["packer"] +
        f_urls * W["urls"] +
        f_ti_bad * W["ti_bad"]
    )
    score = int(max(0, min(100, raw)))
    feats = {
        "num_yara_hits": f_num_yara,
        "suspicious_imports": f_sus_imports,
        "rwx_sections": f_rwx,
        "packer_flag": f_packer,
        "urls_found": f_urls,
        "ti_bad": f_ti_bad,
    }
    contrib = {
        "num_yara_hits": f_num_yara * W["yara"],
        "suspicious_imports": f_sus_imports * W["sus_imports"],
        "rwx_sections": f_rwx * W["rwx"],
        "packer_flag": f_packer * W["packer"],
        "urls_found": f_urls * W["urls"],
        "ti_bad": f_ti_bad * W["ti_bad"],
    }
    top = sorted(contrib.items(), key=lambda kv: kv[1], reverse=True)[:3]
    return {"total": score, "features": feats, "top": top, "weights": W}


def compute_final_score(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate rule-based and AI scores into a final score with risk level.
    Weights are configurable via env: RULE_W (default 0.6), AI_W (default 0.4).
    """
    import os
    rule_total = int(((analysis.get("score") or {}).get("total") or 0))
    ai_total = int(((analysis.get("ai") or {}).get("total") or 0))
    try:
        rw = float(os.getenv("RULE_W", "0.6"))
        aw = float(os.getenv("AI_W", "0.4"))
    except Exception:
        rw, aw = 0.6, 0.4
    raw = rule_total * rw + ai_total * aw
    total = int(max(0, min(100, raw)))
    def level(v: int) -> str:
        if v >= 80: return "critical"
        if v >= 60: return "high"
        if v >= 30: return "medium"
        return "low"
    return {"total": total, "level": level(total), "weights": {"rule": rw, "ai": aw}}


EXPORT_DIR = Path(__file__).resolve().parent.parent / "exports"


app = FastAPI(title="ZORBOX Reporter", version="0.1.0")

# Allow frontend to fetch JSON/PDF/STIX across origins in dev/demo
import os as _os
UI_ORIGIN = _os.getenv("UI_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[UI_ORIGIN],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"]
)

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
    iocs = analysis.get("ti", {}) or {}
    indicators = []
    domains = iocs.get("domains", [])
    ips = iocs.get("ips", [])
    # Accept either list or dict-of-reputation
    if isinstance(domains, dict):
        domains_list = list(domains.keys())
    else:
        domains_list = list(domains)
    if isinstance(ips, dict):
        ips_list = list(ips.keys())
    else:
        ips_list = list(ips)
    for d in domains_list[:10]:
        indicators.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--domain-{d}",
            "name": f"Domain indicator {d}",
            "pattern": f"[domain-name:value = '{d}']",
            "pattern_type": "stix",
        })
    for ip in ips_list[:10]:
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

    # Ensure AI-minimum scoring is present for PDF/JSON consumers
    try:
        ensure_score(analysis)
        # Also include a lightweight AI score with explainability
        analysis["ai"] = compute_ai_score(analysis)
        analysis["final"] = compute_final_score(analysis)
    except Exception:
        pass

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


@app.get("/schema")
def schema():
    try:
        p = Path(__file__).parent / "schema_report.json"
        with open(p, "r", encoding="utf-8") as f:
            return JSONResponse(content=json.load(f))
    except Exception:
        return JSONResponse(status_code=500, content={"detail": "schema unavailable"})


@app.get("/example")
def example_report():
    ensure_dir(EXPORT_DIR)
    # Build a small sample analysis for demo
    analysis: Dict[str, Any] = {
        "id": f"example-{int(time.time())}",
        "title": "ZORBOX Example Report",
        "summary": "This is a sample report demonstrating PDF/JSON/STIX exports.",
        "file": {"name": "sample.exe", "size": 123456, "sha256": "00..ff"},
        "static": {
            "yara_hits": ["sample_rule_1", "packed_upx"],
            "heuristics": {"urls_found": ["http://mal.example/a"]},
            "details": {
                "pe": {
                    "suspicious_imports": ["kernel32.dll!CreateRemoteThread"],
                    "rwx_sections": [".text"],
                    "packer_flags": True
                }
            }
        },
        "ti": {"domains": {"mal.example": "bad"}, "ips": {}, "hashes": {}},
        "sandboxes": [
            {"adapter": "strace", "rc": 0, "duration_ms": 1200, "artifacts": {"trace": "open->read->close"}}
        ],
    }
    # Reuse report pipeline
    try:
        ensure_score(analysis)
        analysis["ai"] = compute_ai_score(analysis)
    except Exception:
        pass
    job_id = analysis.get("id")
    base = EXPORT_DIR / job_id
    ensure_dir(base)
    # JSON
    with open(base / "report.json", "w", encoding="utf-8") as f:
        json.dump(analysis, f, ensure_ascii=False, indent=2)
    # PDF
    pdf_bytes = build_pdf(analysis)
    with open(base / "report.pdf", "wb") as f:
        f.write(pdf_bytes)
    # STIX
    stix = build_stix_bundle(analysis)
    with open(base / "report.stix.json", "w", encoding="utf-8") as f:
        json.dump(stix, f, ensure_ascii=False, indent=2)
    reports_generated.inc()
    http_base = f"/exports/{job_id}"
    return {"json_url": f"{http_base}/report.json", "pdf_url": f"{http_base}/report.pdf", "stix_url": f"{http_base}/report.stix.json"}
