from __future__ import annotations

import time
from typing import Dict, Any
import os
import shutil
import subprocess
import tempfile

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import PlainTextResponse
from prometheus_client import CollectorRegistry, Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST


app = FastAPI(title="ZORBOX Sandbox Native (MVP)", version="0.1.0")

registry = CollectorRegistry()
sandbox_runs_total = Counter(
    "sandbox_runs_total", "Sandbox runs processed", ["adapter"], registry=registry
)
sandbox_run_duration = Histogram(
    "sandbox_run_duration_seconds", "Sandbox run duration", ["adapter"], registry=registry
)
sandbox_errors_total = Counter(
    "sandbox_errors_total", "Sandbox run errors", ["adapter"], registry=registry
)


@app.get("/healthz", response_class=PlainTextResponse)
def healthz() -> str:
    return "ok"


@app.get("/metrics")
def metrics():
    output = generate_latest(registry)
    return PlainTextResponse(output.decode("utf-8"), media_type=CONTENT_TYPE_LATEST)


def _run_firejail(sample_path: str, workdir: str, timeout_sec: int = 10) -> Dict[str, Any]:
    adapter = "firejail"
    start = time.time()
    if not shutil.which("firejail") or not shutil.which("strace") or not shutil.which("strings"):
        return {"adapter": adapter, "status": "unavailable"}
    trace_path = os.path.join(workdir, "trace.log")
    cmd = [
        "firejail", "--quiet", "--net=none", "--private=%s" % workdir,
        "--seccomp", "--caps.drop=all", "--noroot",
        "strace", "-f", "-tt", "-o", trace_path,
        "strings", os.path.basename(sample_path)
    ]
    rc = -1
    stdout = b""
    stderr = b""
    try:
        p = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        rc = p.returncode
        stdout = p.stdout
        stderr = p.stderr
    except subprocess.TimeoutExpired:
        rc = 124
    dur = time.time() - start
    sandbox_runs_total.labels(adapter=adapter).inc()
    sandbox_run_duration.labels(adapter=adapter).observe(dur)
    # read trace (truncate)
    trace_text = ""
    try:
        with open(trace_path, "r", encoding="utf-8", errors="ignore") as f:
            trace_text = f.read(10000)
    except Exception:
        pass
    return {
        "adapter": adapter,
        "duration_ms": int(dur * 1000),
        "rc": rc,
        "artifacts": {
            "trace": trace_text,
            "files": [os.path.basename(sample_path)],
            "stdout": stdout.decode("utf-8", "ignore")[:2000],
            "stderr": stderr.decode("utf-8", "ignore")[:2000],
        },
    }


def _run_strace(sample_path: str, workdir: str, timeout_sec: int = 10) -> Dict[str, Any]:
    adapter = "strace"
    start = time.time()
    if not shutil.which("strace") or not shutil.which("strings"):
        return {"adapter": adapter, "status": "unavailable"}
    trace_path = os.path.join(workdir, "trace.log")
    cmd = [
        "strace", "-f", "-tt", "-o", trace_path,
        "strings", os.path.basename(sample_path)
    ]
    rc = -1
    stdout = b""
    stderr = b""
    try:
        p = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        rc = p.returncode
        stdout = p.stdout
        stderr = p.stderr
    except subprocess.TimeoutExpired:
        rc = 124
    dur = time.time() - start
    sandbox_runs_total.labels(adapter=adapter).inc()
    sandbox_run_duration.labels(adapter=adapter).observe(dur)
    trace_text = ""
    try:
        with open(trace_path, "r", encoding="utf-8", errors="ignore") as f:
            trace_text = f.read(10000)
    except Exception:
        pass
    return {
        "adapter": adapter,
        "duration_ms": int(dur * 1000),
        "rc": rc,
        "artifacts": {
            "trace": trace_text,
            "files": [os.path.basename(sample_path)],
            "stdout": stdout.decode("utf-8", "ignore")[:2000],
            "stderr": stderr.decode("utf-8", "ignore")[:2000],
        },
    }


def _run_bwrap(sample_path: str, workdir: str, timeout_sec: int = 10) -> Dict[str, Any]:
    adapter = "bwrap"
    start = time.time()
    if not shutil.which("bwrap") or not shutil.which("strings"):
        return {"adapter": adapter, "status": "unavailable"}
    # Execute strings inside a bubblewrap-contained environment (no-net, read-only binds)
    cmd = [
        "bwrap",
        "--unshare-all", "--unshare-net",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind", "/bin", "/bin",
        "--ro-bind", "/lib", "/lib",
        "--ro-bind", "/lib64", "/lib64",
        "--ro-bind", "/etc", "/etc",
        "--ro-bind", workdir, workdir,
        "--chdir", workdir,
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        "--die-with-parent", "--new-session",
        "strings", os.path.basename(sample_path)
    ]
    rc = -1
    stdout = b""
    stderr = b""
    try:
        p = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        rc = p.returncode
        stdout = p.stdout
        stderr = p.stderr
    except subprocess.TimeoutExpired:
        rc = 124
    dur = time.time() - start
    sandbox_runs_total.labels(adapter=adapter).inc()
    sandbox_run_duration.labels(adapter=adapter).observe(dur)
    trace_lines = [
        "adapter=bwrap",
        "cmd=" + " ".join(cmd),
        "note=no-net, ro-bind, unprivileged",
    ]
    return {
        "adapter": adapter,
        "duration_ms": int(dur * 1000),
        "rc": rc,
        "artifacts": {
            "trace": "\n".join(trace_lines)[:10000],
            "files": [os.path.basename(sample_path)],
            "stdout": stdout.decode("utf-8", "ignore")[:2000],
            "stderr": stderr.decode("utf-8", "ignore")[:2000],
        },
    }


def _run_nsjail(sample_path: str, workdir: str, timeout_sec: int = 10) -> Dict[str, Any]:
    adapter = "nsjail"
    start = time.time()
    if not shutil.which("nsjail") or not shutil.which("strings"):
        return {"adapter": adapter, "status": "unavailable"}
    # Minimal nsjail: disable network clone, readonly binds for system dirs, bind workdir, run strings
    cmd = [
        "nsjail",
        "-Mo",  # run once in standalone mode
        "--disable_clone_newnet",  # no new net ns (keep it simple); still no outbound in container net
        "-R", "/usr",
        "-R", "/bin",
        "-R", "/lib",
        "-R", "/lib64",
        "-R", "/etc",
        "-R", workdir,  # bind workdir ro
        "-D", workdir,  # chdir
        "--", "strings", os.path.basename(sample_path)
    ]
    rc = -1
    stdout = b""
    stderr = b""
    try:
        p = subprocess.run(cmd, cwd=workdir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout_sec)
        rc = p.returncode
        stdout = p.stdout
        stderr = p.stderr
    except subprocess.TimeoutExpired:
        rc = 124
    dur = time.time() - start
    sandbox_runs_total.labels(adapter=adapter).inc()
    sandbox_run_duration.labels(adapter=adapter).observe(dur)
    trace_text = "cmd=" + " ".join(cmd)
    return {
        "adapter": adapter,
        "duration_ms": int(dur * 1000),
        "rc": rc,
        "artifacts": {
            "trace": trace_text[:10000],
            "files": [os.path.basename(sample_path)],
            "stdout": stdout.decode("utf-8", "ignore")[:2000],
            "stderr": stderr.decode("utf-8", "ignore")[:2000],
        },
    }

@app.post("/run")
async def run(file: UploadFile = File(...), adapter: str = Form(default="mock")) -> Dict[str, Any]:
    start = time.time()
    try:
        data = await file.read()
        # Write to isolated temp dir
        workdir = tempfile.mkdtemp(prefix="sbx-")
        sample_path = os.path.join(workdir, file.filename or "sample.bin")
        with open(sample_path, "wb") as f:
            f.write(data)
        if adapter == "firejail":
            return _run_firejail(sample_path, workdir)
        if adapter == "strace":
            return _run_strace(sample_path, workdir)
        if adapter == "bwrap":
            return _run_bwrap(sample_path, workdir)
        if adapter == "nsjail":
            return _run_nsjail(sample_path, workdir)
        # default mock
        trace_lines = [
            f"adapter={adapter}", f"file={file.filename}", f"size={len(data)} bytes", "syscall: open -> read -> close",
        ]
        artifacts = {"trace": "\n".join(trace_lines), "files": [file.filename]}
        rc = 0
        dur = time.time() - start
        sandbox_runs_total.labels(adapter=adapter).inc()
        sandbox_run_duration.labels(adapter=adapter).observe(dur)
        return {"adapter": adapter, "duration_ms": int(dur * 1000), "rc": rc, "artifacts": artifacts}
    except Exception:
        sandbox_errors_total.labels(adapter=adapter).inc()
        raise
