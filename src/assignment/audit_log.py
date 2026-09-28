"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input and monotonic start time keyed by request/user."""
        key = request_id or user_id or "anonymous"
        self._open[key] = time.monotonic()
        self._pending = getattr(self, "_pending", {})
        self._pending[key] = {"user_id": user_id or "anonymous", "input": str(text), "request_id": request_id}
        return key

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision and elapsed time."""
        key = request_id or user_id or "anonymous"
        start = self._open.pop(key, None)
        record = getattr(self, "_pending", {}).pop(key, {})
        record.update({
            "timestamp": utc_now_iso(), "user_id": user_id or record.get("user_id", "anonymous"),
            "output": str(text), "blocked": bool(blocked), "layer": layer,
            "latency_ms": round((time.monotonic() - start) * 1000, 3) if start is not None else None,
        })
        if request_id is not None:
            record["request_id"] = request_id
        self.logs.append(record)
        return record

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
