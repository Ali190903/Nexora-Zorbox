from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Tuple, Optional, Dict, Any
import json
import time
import shutil


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def ensure_base_dir(base: Path) -> None:
    base.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(base, 0o700)
    except Exception:
        pass


def safe_join(base: Path, *parts: str) -> Path:
    """Join path parts under base ensuring the result stays within base (zip-slip guard)."""
    candidate = (base / Path(*parts)).resolve()
    base_resolved = base.resolve()
    if not str(candidate).startswith(str(base_resolved)):
        raise ValueError("unsafe path traversal detected")
    return candidate


def save_bytes(base: Path, rel_name: str, data: bytes) -> Tuple[Path, str, int]:
    """Save bytes under base safely. Returns (path, sha256, size)."""
    ensure_base_dir(base)
    target = safe_join(base, rel_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "wb") as f:
        f.write(data)
    os.chmod(target, 0o600)
    digest = sha256_bytes(data)
    size = len(data)
    return target, digest, size


def dir_size_bytes(path: Path) -> int:
    total = 0
    if not path.exists():
        return 0
    for p in path.rglob('*'):
        if p.is_file():
            try:
                total += p.stat().st_size
            except Exception:
                pass
    return total


def write_job_meta(base: Path, meta: Dict[str, Any]) -> None:
    ensure_base_dir(base)
    meta_path = base / 'meta.json'
    tmp = base / f"meta.{int(time.time()*1000)}.tmp"
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    tmp.replace(meta_path)


def cleanup_retention(base: Path, older_than_hours: Optional[int]) -> int:
    """Delete job directories older than N hours. Returns count of removed dirs."""
    if not older_than_hours or older_than_hours <= 0:
        return 0
    removed = 0
    threshold = time.time() - older_than_hours * 3600
    if not base.exists():
        return 0
    for child in base.iterdir():
        try:
            if not child.is_dir():
                continue
            st = child.stat()
            mtime = max(st.st_mtime, st.st_ctime)
            if mtime < threshold:
                shutil.rmtree(child, ignore_errors=True)
                removed += 1
        except Exception:
            continue
    return removed
