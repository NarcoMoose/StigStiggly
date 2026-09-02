"""Scan-history snapshots: one append-only JSONL file per baseline.

Snapshots are recorded opportunistically whenever the dashboard loads a
baseline whose ``lastComplianceCheck`` is newer than the latest recorded
entry — so history accrues no matter how a scan was run (dashboard,
terminal, MDM). This is StigStiggly's own data directory; system state is
never modified here.
"""

from __future__ import annotations

import json
import platform
from pathlib import Path

from .config import chown_to_invoker as _chown_to_invoker
from .mscp_data import Baseline


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
    by_status = lambda status: sorted(r.id for r in baseline.rules if r.status == status)
    entry = {
        "ts": ts,
        "os_version": platform.mac_ver()[0],  # host OS when the snapshot was recorded
        "pass": counts["pass"],
        "fail": counts["fail"],
        "exempt": counts["exempt"],
        "not_scanned": counts["not_scanned"],
        "pct": baseline.compliance_pct,
        "sev_fail": baseline.severity_fail,
        "failed_ids": by_status("fail"),
        "exempt_ids": by_status("exempt"),
        "pass_ids": by_status("pass"),
        "not_scanned_ids": by_status("not_scanned"),
    }
    history_dir.mkdir(parents=True, exist_ok=True)
    _chown_to_invoker(history_dir)
    path = history_file(history_dir, baseline.name)
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(entry, separators=(",", ":")) + "\n")
    _chown_to_invoker(path)
    return True


def diff_snapshots(older: dict, newer: dict) -> dict:
    """Compare two snapshot entries (chronological order expected).

    Buckets are mutually exclusive per rule. Entries written before the
    pass_ids/not_scanned_ids fields existed are still comparable for
    fail/exempt transitions; baseline membership changes (rules added or
    removed, e.g. after switching guidance branches) are only computed when
    both entries carry the full rule universe — indicated by ``complete``.
    """
    o_fail, n_fail = set(older.get("failed_ids") or ()), set(newer.get("failed_ids") or ())
    o_exempt, n_exempt = set(older.get("exempt_ids") or ()), set(newer.get("exempt_ids") or ())

    def universe(entry: dict) -> set | None:
        if entry.get("pass_ids") is None or entry.get("not_scanned_ids") is None:
            return None
        return (
            set(entry["pass_ids"]) | set(entry["not_scanned_ids"])
            | set(entry.get("failed_ids") or ()) | set(entry.get("exempt_ids") or ())
        )

    o_all, n_all = universe(older), universe(newer)
    complete = o_all is not None and n_all is not None
    added = sorted(n_all - o_all) if complete else None
    removed = sorted(o_all - n_all) if complete else None

    return {
        "older_ts": older.get("ts"),
        "newer_ts": newer.get("ts"),
        "os_change": (older.get("os_version"), newer.get("os_version"))
        if older.get("os_version") != newer.get("os_version")
        else None,
        "pct_delta": round((newer.get("pct") or 0) - (older.get("pct") or 0), 1),
        "newly_failing": sorted(n_fail - o_fail - o_exempt),
        "newly_passing": sorted((o_fail - n_fail - n_exempt) - set(removed or ())),
        "newly_exempt": sorted(n_exempt - o_exempt),
        "unexempted": sorted(o_exempt - n_exempt),
        "added_rules": added,
        "removed_rules": removed,
        "complete": complete,
    }
