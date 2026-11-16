"""File de tâches entre la console (API) et le planificateur (worker).

L'API n'a pas d'accès réseau sortant (règle 8) : elle se contente de déposer une tâche dans
STATE_DIR/jobs/<id>.json ; le worker la prend, l'exécute et met à jour l'avancement que la console affiche.

Types : « scan » (collecte + analyse [+ IA]), « test » (connexion AD/Entra), « ai » (analyse IA d'un scan).
"""

from __future__ import annotations

import json
import os
import secrets
import threading
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field

from .config import STATE_DIR


class JobKind(StrEnum):
    scan = "scan"
    test = "test"
    ai = "ai"


class JobStatus(StrEnum):
    queued = "queued"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    cancelled = "cancelled"


class Job(BaseModel):
    id: str
    kind: JobKind
    target: str | None = None
    scan_id: str | None = None  # scan à analyser (ai) ou produit (scan)
    requested_by: str | None = None
    trigger: str = "manual"  # manual | schedule
    status: JobStatus = JobStatus.queued
    progress: int = 0
    step: str = "En attente du planificateur"
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    log: list[dict] = Field(default_factory=list)
    result: dict = Field(default_factory=dict)

    @property
    def active(self) -> bool:
        return self.status in (JobStatus.queued, JobStatus.running)


class JobStore:
    def __init__(self, root: Path | None = None):
        self.root = root or STATE_DIR / "jobs"
        self._lock = threading.Lock()

    def _path(self, job_id: str) -> Path:
        if not job_id.replace("-", "").isalnum():
            raise ValueError("Identifiant de tâche invalide")
        return self.root / f"{job_id}.json"

    def save(self, job: Job) -> Job:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self._path(job.id)
        tmp = path.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(job.model_dump_json(), encoding="utf-8")
        os.replace(tmp, path)
        return job

    def get(self, job_id: str) -> Job | None:
        path = self._path(job_id)
        if not path.exists():
            return None
        try:
            return Job.model_validate_json(path.read_text(encoding="utf-8"))
        except ValueError:
            return None

    def list(self, limit: int = 100) -> list[Job]:
        if not self.root.exists():
            return []
        jobs = []
        for p in self.root.glob("*.json"):
            try:
                jobs.append(Job.model_validate_json(p.read_text(encoding="utf-8")))
            except ValueError:
                continue
        return sorted(jobs, key=lambda j: j.created_at, reverse=True)[:limit]

    def create(
        self,
        kind: JobKind,
        *,
        target: str | None = None,
        scan_id: str | None = None,
        user: str | None = None,
        trigger: str = "manual",
    ) -> Job:
        with self._lock:
            for j in self.list(limit=500):
                if j.active and j.kind == kind and j.target == target and j.scan_id == scan_id:
                    raise JobConflict(j)
            now = datetime.now(UTC)
            job = Job(
                id=f"{now:%Y%m%d%H%M%S}-{secrets.token_hex(3)}",
                kind=kind,
                target=target,
                scan_id=scan_id,
                requested_by=user,
                trigger=trigger,
                created_at=now,
            )
            return self.save(job)

    def claim_next(self) -> Job | None:
        """Prend la plus ancienne tâche en attente (un seul worker par appliance)."""
        with self._lock:
            queued = [j for j in self.list(limit=500) if j.status == JobStatus.queued]
            if not queued:
                return None
            job = min(queued, key=lambda j: j.created_at)
            job.status, job.started_at, job.step = JobStatus.running, datetime.now(UTC), "Démarrage"
            return self.save(job)

    def cancel(self, job_id: str) -> Job:
        with self._lock:
            job = self.get(job_id)
            if job is None:
                raise KeyError(job_id)
            if job.status != JobStatus.queued:
                raise ValueError("Seule une tâche en attente peut être annulée")
            job.status, job.finished_at, job.step = JobStatus.cancelled, datetime.now(UTC), "Annulée"
            return self.save(job)

    def recover_interrupted(self) -> int:
        """Au démarrage du worker : une tâche restée « running » a été interrompue (redémarrage)."""
        n = 0
        for job in self.list(limit=500):
            if job.status == JobStatus.running:
                job.status, job.finished_at = JobStatus.failed, datetime.now(UTC)
                job.error = job.step = "Interrompue par un redémarrage du service"
                self.save(job)
                n += 1
        return n

    def purge(self, keep_days: int = 30) -> None:
        limit = datetime.now(UTC) - timedelta(days=keep_days)
        for job in self.list(limit=10_000):
            if not job.active and job.created_at < limit:
                self._path(job.id).unlink(missing_ok=True)


class JobConflict(Exception):
    def __init__(self, job: Job):
        super().__init__(f"Une tâche identique est déjà en cours ({job.id})")
        self.job = job


class Progress:
    """Rapporteur d'avancement passé aux étapes de collecte. Écrit le fichier de la tâche à chaque étape."""

    def __init__(self, store: JobStore | None, job: Job | None):
        self.store, self.job = store, job

    def __call__(self, percent: int, step: str, level: str = "info") -> None:
        if self.job is None or self.store is None:
            return
        self.job.progress = max(self.job.progress, min(100, percent))
        self.job.step = step
        self.job.log.append({"at": datetime.now(UTC).isoformat(), "level": level, "msg": step})
        self.store.save(self.job)

    def warn(self, msg: str) -> None:
        if self.job is None or self.store is None:
            return
        self.job.log.append({"at": datetime.now(UTC).isoformat(), "level": "warning", "msg": msg})
        self.store.save(self.job)


def job_summary(job: Job) -> dict:
    data = json.loads(job.model_dump_json())
    data["active"] = job.active
    return data
