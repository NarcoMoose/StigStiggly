"""Job runner for mSCP compliance-script executions.

One job at a time, system-wide: scans write to shared audit plists/logs, so
concurrent runs are never allowed. Output lines are buffered in memory so any
number of SSE clients can attach (or re-attach) at any point during or after
the run.

Phase 2 only runs ``--check`` (non-destructive). The remediation path (Phase 3)
will reuse this runner with a different flag.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
SSE_PING_SECONDS = 15


class JobInProgress(Exception):
    pass


@dataclass
class Job:
    baseline: str
    kind: str  # "scan"
    command: list[str]
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    status: str = "running"  # running | succeeded | failed | error
    exit_code: int | None = None
    error: str | None = None
    started: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    lines: list[str] = field(default_factory=list)
    _cond: threading.Condition = field(default_factory=threading.Condition, repr=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "baseline": self.baseline,
            "kind": self.kind,
            "command": " ".join(self.command),
            "status": self.status,
            "exit_code": self.exit_code,
            "error": self.error,
            "started": self.started.isoformat(),
            "line_count": len(self.lines),
        }

    # -- producer side -----------------------------------------------------

    def _append(self, line: str) -> None:
        with self._cond:
            self.lines.append(ANSI_RE.sub("", line.rstrip("\n")))
            self._cond.notify_all()

    def _finish(self, status: str, exit_code: int | None = None, error: str | None = None) -> None:
        with self._cond:
            self.status = status
            self.exit_code = exit_code
            self.error = error
            self._cond.notify_all()

    def _run(self) -> None:
        try:
            proc = subprocess.Popen(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                self._append(line)
            code = proc.wait()
            self._finish("succeeded" if code == 0 else "failed", exit_code=code)
        except OSError as exc:
            self._append(f"error: {exc}")
            self._finish("error", error=str(exc))

    # -- consumer side -----------------------------------------------------

    def sse_stream(self, start: int = 0):
        """Yield Server-Sent Events: one `data:` message per output line, then
        a final `done` event. Safe to call for finished jobs (full replay)."""
        idx = max(start, 0)
        while True:
            with self._cond:
                if idx >= len(self.lines) and self.status == "running":
                    self._cond.wait(timeout=SSE_PING_SECONDS)
                chunk = self.lines[idx:]
                running = self.status == "running"
            for line in chunk:
                yield f"data: {json.dumps(line)}\n\n"
            idx += len(chunk)
            if not running and idx >= len(self.lines):
                yield f"event: done\ndata: {json.dumps(self.to_dict())}\n\n"
                return
            if not chunk:
                yield ": ping\n\n"  # keep the connection alive


class JobManager:
    """Holds the single current (or most recent) job."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._job: Job | None = None

    def current(self) -> Job | None:
        return self._job

    def get(self, job_id: str) -> Job | None:
        job = self._job
        return job if job and job.id == job_id else None

    def start(self, baseline: str, kind: str, command: list[str]) -> Job:
        with self._lock:
            if self._job and self._job.status == "running":
                raise JobInProgress(
                    f"a {self._job.kind} of '{self._job.baseline}' is already running"
                )
            job = Job(baseline=baseline, kind=kind, command=command)
            self._job = job
            threading.Thread(target=job._run, name=f"job-{job.id}", daemon=True).start()
            return job


def find_compliance_script(build_dir: Path, baseline_name: str) -> Path | None:
    """Locate the mSCP-generated compliance script for a baseline."""
    folder = build_dir / baseline_name
    exact = folder / f"{baseline_name}_compliance.sh"
    if exact.is_file():
        return exact
    hits = sorted(folder.glob("*_compliance.sh"))
    return hits[0] if hits else None


def set_exemption(plist_path: Path, rule_id: str, exempt: bool, reason: str | None) -> None:
    """Mark a rule exempt/not-exempt in the audit plist.

    Uses `defaults write ... -dict-add` (mSCP's documented mechanism) so the
    change merges into the rule's dict without clobbering `finding`, and stays
    coherent with the NSUserDefaults reads the compliance script performs.
    Raises subprocess.CalledProcessError on failure.
    """
    cmd = [
        "/usr/bin/defaults", "write", str(plist_path), rule_id,
        "-dict-add", "exempt", "-bool", "true" if exempt else "false",
    ]
    if exempt:
        cmd += ["exempt_reason", "-string", reason or ""]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
