"""Scan-history snapshots: one append-only JSONL file per baseline.

Snapshots are recorded opportunistically whenever the dashboard loads a
baseline whose ``lastComplianceCheck`` is newer than the latest recorded
entry — so history accrues no matter how a scan was run (dashboard,
terminal, MDM). This is StigStiggly's own data directory; system state is
never modified here.
"""

from __future__ import annotations

import json
import os
import pwd
from pathlib import Path

from .mscp_data import Baseline


def _chown_to_invoker(path: Path) -> None:
    """When running under sudo, hand snapshot files to the invoking user so
    later unprivileged sessions can keep appending to them."""
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() != 0 or not sudo_user:
        return
    try:
        rec = pwd.getpwnam(sudo_user)
        os.chown(path, rec.pw_uid, rec.pw_gid)
    except (KeyError, OSError):
        pass


def history_file(history_dir: Path, baseline_name: str) -> Path:
    return history_dir / f"{baseline_name}.jsonl"


def load_history(history_dir: Path, baseline_name: str) -> list[dict]:
    """Parsed snapshot entries, oldest first. Tolerates missing/corrupt lines."""
    path = history_file(history_dir, baseline_name)
    if not path.is_file():
        return []
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and entry.get("ts"):
            entries.append(entry)
    entries.sort(key=lambda e: e["ts"])
    return entries


def record_snapshot(history_dir: Path, baseline: Baseline) -> bool:
    """Append a snapshot if this scan isn't recorded yet. Returns True if written."""
    if not baseline.last_check:
        return False
    ts = baseline.last_check.isoformat()
    existing = load_history(history_dir, baseline.name)
    if any(e["ts"] == ts for e in existing):
        return False
    counts = baseline.counts
    entry = {
        "ts": ts,
        "pass": counts["pass"],
        "fail": counts["fail"],
        "exempt": counts["exempt"],
        "not_scanned": counts["not_scanned"],
        "pct": baseline.compliance_pct,
        "sev_fail": baseline.severity_fail,
        "failed_ids": sorted(r.id for r in baseline.rules if r.status == "fail"),
        "exempt_ids": sorted(r.id for r in baseline.rules if r.status == "exempt"),
    }
    history_dir.mkdir(parents=True, exist_ok=True)
    _chown_to_invoker(history_dir)
    path = history_file(history_dir, baseline.name)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry, separators=(",", ":")) + "\n")
    _chown_to_invoker(path)
    return True
