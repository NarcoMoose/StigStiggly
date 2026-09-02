"""Device report: a versioned JSON summary for fleet/admin collection.

One document per device describing every discovered baseline's compliance
state. Designed to be shipped anywhere (cron + scp, MDM script, HTTP POST by
an external agent) and aggregated later — the future admin view consumes
these. Schema changes bump the `schema` version string.
"""

from __future__ import annotations

import platform
import subprocess
from datetime import datetime, timezone

from . import __version__
from .config import AppConfig
from .mscp_data import discover_baselines, load_repo_info

SCHEMA = "stigstiggly.device-report/1"


def _hardware_serial() -> str | None:
    try:
        out = subprocess.run(
            ["/usr/sbin/ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in out.splitlines():
        if "IOPlatformSerialNumber" in line and '"' in line:
            return line.split('"')[-2]
    return None


def build_report(cfg: AppConfig) -> dict:
    """Assemble the device report. Read-only; works unprivileged."""
    baselines = discover_baselines(cfg.prefs_dir, cfg.repo) if cfg.repo else []
    guidance = None
    if cfg.repo:
        info = load_repo_info(cfg.repo)
        guidance = {"version_label": info.version_label, "os_version": info.os_version}
    return {
        "schema": SCHEMA,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "app_version": __version__,
        "host": {
            "hostname": platform.node(),
            "os_version": platform.mac_ver()[0],
            "hardware_serial": _hardware_serial(),
        },
        "guidance": guidance,
        "baselines": [
            {
                "name": b.name,
                "title": b.title,
                "last_scan": b.last_check.isoformat() if b.last_check else None,
                "counts": b.counts,
                "compliance_pct": b.compliance_pct,
                "severity_fail": b.severity_fail,
                "failed_ids": sorted(r.id for r in b.rules if r.status == "fail"),
                "exempt": {
                    r.id: r.exempt_reason or "" for r in b.rules if r.status == "exempt"
                },
            }
            for b in baselines
        ],
    }
