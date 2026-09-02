"""First-run bootstrap (guidance-content download) and environment diagnostics.

Downloads the macos_security branch matching the host macOS as a GitHub
tarball — no git or developer tools required — into the managed data dir,
and provides the checks behind `stigstiggly doctor` and the web setup page.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from .config import chown_to_invoker, managed_content_dir

# macOS major version -> macos_security release branch
MACOS_BRANCHES = {
    "26": "tahoe",
    "15": "sequoia",
    "14": "sonoma",
    "13": "ventura",
    "12": "monterey",
    "11": "big_sur",
}
TARBALL_URL = "https://github.com/usnistgov/macos_security/archive/refs/heads/{branch}.tar.gz"


def host_macos_version() -> str:
    return platform.mac_ver()[0]


def branch_for_host() -> str | None:
    return MACOS_BRANCHES.get(host_macos_version().split(".")[0])


def content_url(branch: str) -> str:
    """Tarball URL for a branch; STIGSTIGGLY_CONTENT_URL overrides for testing."""
    return os.environ.get("STIGSTIGGLY_CONTENT_URL") or TARBALL_URL.format(branch=branch)


def download_guidance(branch: str, progress=lambda msg: None) -> Path:
    """Download and extract the guidance tarball for `branch`.

    Returns the extracted content root (contains rules/). Idempotent: an
    existing download for the branch is replaced atomically.
    """
    url = content_url(branch)
    dest = managed_content_dir() / f"macos_security-{branch}"
    progress(f"Downloading {url}")
    with tempfile.TemporaryDirectory(prefix="stigstiggly-bootstrap-") as tmp:
        tmp_path = Path(tmp)
        tarball = tmp_path / "content.tar.gz"
        with urllib.request.urlopen(url, timeout=60) as resp, tarball.open("wb") as out:
            shutil.copyfileobj(resp, out)
        progress(f"Downloaded {tarball.stat().st_size // 1024} KiB, extracting...")
        with tarfile.open(tarball) as tf:
            tf.extractall(tmp_path / "extract", filter="data")  # blocks path traversal
        roots = [p for p in (tmp_path / "extract").iterdir() if p.is_dir()]
        root = next((r for r in roots if (r / "rules").is_dir()), None)
        if root is None:
            raise RuntimeError(f"downloaded archive from {url} does not contain a rules/ directory")
        dest.parent.mkdir(parents=True, exist_ok=True)
        chown_to_invoker(dest.parent.parent)
        chown_to_invoker(dest.parent)
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(root), dest)
    _chown_tree(dest)
    progress(f"Guidance content installed at {dest}")
    return dest


def _chown_tree(root: Path) -> None:
    if os.geteuid() != 0 or not os.environ.get("SUDO_USER"):
        return
    chown_to_invoker(root)
    for path in root.rglob("*"):
        chown_to_invoker(path)


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


@dataclass
class Check:
    label: str
    status: str  # ok | warn | fail
    detail: str


def run_doctor(cfg) -> list[Check]:
    """Environment diagnostics for `stigstiggly doctor` and the setup page."""
    from .actions import find_compliance_script
    from .mscp_data import AUDIT_PLIST_RE, load_repo_info, load_rule_index

    checks: list[Check] = []
    add = lambda label, ok, detail, warn=False: checks.append(
        Check(label, "ok" if ok else ("warn" if warn else "fail"), detail)
    )

    add("Python", True, platform.python_version())
    add("macOS", True, host_macos_version() or "unknown")

    from .config import config_file

    cfg_path = config_file()
    add("Config file", cfg_path.is_file(), str(cfg_path) if cfg_path.is_file() else f"not written yet ({cfg_path})", warn=True)

    if cfg.repo is None:
        branch = branch_for_host()
        hint = f"run `stigstiggly setup` to download the '{branch}' guidance" if branch else "no known branch for this macOS version; pass --repo"
        add("Guidance content", False, f"none found — {hint}")
    else:
        info = load_repo_info(cfg.repo)
        add("Guidance content", True, f"{cfg.repo} (via {cfg.repo_source})")
        if info.matches_host is False:
            add("Guidance/OS match", False, f"guidance targets macOS {info.os_version}, host is {info.host_os}", warn=True)
        else:
            add("Guidance/OS match", True, f"guidance {info.os_version or '?'} / host {info.host_os or '?'}")
        rules = load_rule_index(cfg.repo)
        add("Rules indexed", bool(rules), f"{len(rules)} rules", warn=True)

        build_dir = cfg.build_dir or cfg.repo / "build"
        plists = sorted(cfg.prefs_dir.glob("org.*.audit.plist")) if cfg.prefs_dir.is_dir() else []
        names = [m.group("name") for p in plists if (m := AUDIT_PLIST_RE.match(p.name))]
        add("Scan results", bool(names), ", ".join(names) if names else f"no org.*.audit.plist in {cfg.prefs_dir} (run a scan)", warn=True)
        scripts = [n for n in names if find_compliance_script(build_dir, n)]
        add(
            "Compliance scripts", bool(scripts) or not names,
            f"found for: {', '.join(scripts)}" if scripts else f"none under {build_dir}", warn=True,
        )

    add("History dir", True, str(cfg.history_dir))
    add(
        "Privileges", cfg.can_act,
        "root — scans/remediation enabled" if cfg.can_act else "unprivileged — dashboard is read-only (use sudo for actions)",
        warn=True,
    )
    asciidoctor = shutil.which("asciidoctor") or _gem_asciidoctor(cfg.repo)
    add(
        "asciidoctor (optional)", bool(asciidoctor),
        asciidoctor or "not found — baseline-builder doc bundles will omit HTML/PDF", warn=True,
    )
    return checks


def _gem_asciidoctor(repo: Path | None) -> str | None:
    """mSCP clones often vendor asciidoctor via bundler; detect that too."""
    if repo and (repo / "mscp_gems" / "bin" / "asciidoctor").is_file():
        return str(repo / "mscp_gems" / "bin" / "asciidoctor")
    try:
        out = subprocess.run(
            ["gem", "list", "-i", "asciidoctor"], capture_output=True, text=True, timeout=10
        )
        return "asciidoctor (ruby gem)" if out.stdout.strip() == "true" else None
    except (OSError, subprocess.TimeoutExpired):
        return None
