from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, List

from .schemas import JobState, JobSummary


@dataclass
class Job:
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
    export_json_url: Optional[str] = None
    export_pdf_url: Optional[str] = None
    export_stix_url: Optional[str] = None
    adapters: Optional[List[str]] = None

    def to_summary(self) -> JobSummary:
        return JobSummary(
            id=self.id,
            state=self.state,
            created_at=self.created_at,
            updated_at=self.updated_at,
            file_name=self.file_name,
            file_size=self.file_size,
            file_sha256=self.file_sha256,
            file_md5=self.file_md5,
            mime_detected=self.mime_detected,
            mime_mismatch=self.mime_mismatch,
            source_url=self.source_url,
            http_status=self.http_status,
            http_headers=self.http_headers,
            error=self.error,
            archive_type=self.archive_type,
            requires_password=self.requires_password,
            archive_members=self.archive_members,
            export={
                "json_url": self.export_json_url,
                "pdf_url": self.export_pdf_url,
                "stix_url": self.export_stix_url,
            } if any([self.export_json_url, self.export_pdf_url, self.export_stix_url]) else None,
            adapters=self.adapters,
            
        )


class JobStore:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.jobs: Dict[str, Job] = {}

    def create(self, file_name: Optional[str] = None, file_size: Optional[int] = None, file_sha256: Optional[str] = None) -> Job:
        with self._lock:
            jid = str(uuid.uuid4())
            now = time.time()
            job = Job(
                id=jid,
                state=JobState.queued,
                created_at=now,
                updated_at=now,
                file_name=file_name,
                file_size=file_size,
                file_sha256=file_sha256,
            )
            self.jobs[jid] = job
            return job

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self.jobs.get(job_id)

    def set_state(self, job_id: str, state: JobState, error: Optional[str] = None) -> None:
        with self._lock:
            job = self.jobs[job_id]
            job.state = state
            job.updated_at = time.time()
            job.error = error

    def by_state(self, state: Optional[JobState] = None):
        with self._lock:
            if state is None:
                return list(self.jobs.values())
            return [j for j in self.jobs.values() if j.state == state]
