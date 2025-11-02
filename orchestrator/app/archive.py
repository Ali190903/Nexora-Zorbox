from __future__ import annotations

import io
import zipfile
from typing import List, Optional, Tuple
from pathlib import Path


class ArchiveInfo(Tuple[str, bool, int]):
    # (type, is_encrypted, members_count)
    pass


def detect_zip_encryption(data: bytes) -> Optional[ArchiveInfo]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            members = zf.infolist()
            enc = any(i.flag_bits & 0x1 for i in members) if members else False
            return ArchiveInfo(("zip", enc, len(members)))
    except zipfile.BadZipFile:
        return None


def detect_archive(file_name: Optional[str], data: bytes) -> Optional[ArchiveInfo]:
    # ZIP
    info = detect_zip_encryption(data)
    if info:
        return info
    # 7z: magic 37 7A BC AF 27 1C
    if len(data) >= 6 and data[:6] == b'7z\xBC\xAF\x27\x1C':
        return ArchiveInfo(("7z", False, 0))
    # RAR: Rar! 1A 07 00 (RAR4) or Rar! 1A 07 01 00 (RAR5)
    if (len(data) >= 7 and data[:7] == b'Rar!\x1A\x07\x00') or (len(data) >= 8 and data[:8] == b'Rar!\x1A\x07\x01\x00'):
        return ArchiveInfo(("rar", False, 0))
    # ISO heuristic: 'CD001' near typical offsets or .iso extension
    try:
        if file_name and str(file_name).lower().endswith('.iso'):
            return ArchiveInfo(("iso", False, 0))
        for off in (0x8001, 0x8801, 0x9001):
            if len(data) > off + 5 and data[off:off+5] == b'CD001':
                return ArchiveInfo(("iso", False, 0))
    except Exception:
        pass
    # IMG by extension only (best effort)
    try:
        if file_name and str(file_name).lower().endswith('.img'):
            return ArchiveInfo(("img", False, 0))
    except Exception:
        pass
    return None


def list_zip_members(data: bytes, password: Optional[str] = None) -> List[str]:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        if password:
            zf.setpassword(password.encode('utf-8'))
        names = [i.filename for i in zf.infolist()]
        return names


def extract_zip(data: bytes, out_dir: str, password: Optional[str] = None, max_members: int = 50, max_total: int = 50 * 1024 * 1024) -> List[str]:
    """
    Extract ZIP archive safely into out_dir (create if needed).
    - Protects against zip-slip by resolving path inside out_dir.
    - Limits number of members and total uncompressed size.
    Returns list of extracted relative paths.
    """
    import os
    from pathlib import Path

    Path(out_dir).mkdir(parents=True, exist_ok=True)
    extracted: List[str] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        if password:
            zf.setpassword(password.encode('utf-8'))
        infos = zf.infolist()[:max_members]
        for info in infos:
            # Skip directories
            if info.is_dir():
                continue
            total += info.file_size or 0
            if total > max_total:
                break
            # Safe path resolution
            target = Path(out_dir) / Path(info.filename)
            target_parent = target.parent
            target_parent.mkdir(parents=True, exist_ok=True)
            # Normalize and ensure within out_dir
            resolved = target.resolve()
            if not str(resolved).startswith(str(Path(out_dir).resolve())):
                continue
            with zf.open(info) as src, open(resolved, 'wb') as dst:
                dst.write(src.read())
            # Record relative path
            extracted.append(str(resolved.relative_to(Path(out_dir))))
    return extracted


def list_7z_members(data: bytes, password: Optional[str] = None, max_members: int = 200) -> List[str]:
    """List 7z archive members (no extraction). If password is required and not provided, raises Exception."""
    import py7zr
    from io import BytesIO
    names: List[str] = []
    try:
        with py7zr.SevenZipFile(BytesIO(data), mode='r', password=password) as z:
            for i, name in enumerate(z.getnames()):
                if i >= max_members:
                    break
                # normalize
                names.append(name)
    except py7zr.exceptions.PasswordRequired:
        raise
    return names


def list_rar_members(data: bytes, password: Optional[str] = None, max_members: int = 200) -> List[str]:
    """Attempt to list RAR archive members using rarfile if available. Raises if unsupported."""
    try:
        import rarfile  # type: ignore
        from io import BytesIO
        rf = rarfile.RarFile(BytesIO(data), pwd=password)
        names: List[str] = []
        for i, info in enumerate(rf.infolist()):
            if i >= max_members:
                break
            names.append(info.filename)
        return names
    except Exception as e:
        raise e
