from __future__ import annotations

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, HttpUrl, Field


class JobState(str, Enum):
    queued = "queued"
    running = "running"
    enriching = "enriching"
    reporting = "reporting"
    done = "done"
    failed = "failed"
    waiting_password = "waiting_password"


class AnalyzeRequest(BaseModel):
    url: Optional[HttpUrl] = None
    password: Optional[str] = None
    adapters: Optional[List[str]] = Field(default=None, description="sandbox adapters to use")


class AnalyzeResponse(BaseModel):
    job_id: str
    accepted: bool = True


class JobSummary(BaseModel):
    id: str
    state: JobState
    created_at: float
    updated_at: float
    file_name: Optional[str] = None
    file_size: Optional[int] = None
    file_sha256: Optional[str] = None
    file_md5: Optional[str] = None
    mime_detected: Optional[str] = None
    mime_mismatch: Optional[bool] = None
    source_url: Optional[str] = None
    http_status: Optional[int] = None
    http_headers: Optional[dict] = None
    archive_type: Optional[str] = None
    requires_password: Optional[bool] = None
    archive_members: Optional[List[str]] = None
    error: Optional[str] = None
    export: Optional[dict] = None
    adapters: Optional[List[str]] = None


class JobsResponse(BaseModel):
    items: List[JobSummary]
