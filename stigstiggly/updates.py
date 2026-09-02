"""Update awareness: is the app or the guidance content outdated?

Two lightweight checks against raw files (no API tokens, one GET each):
  * app      — version in the repo's pyproject.toml on main vs the running version
  * guidance — VERSION.yaml date on the matching macos_security branch vs local

Results are cached for a day in the data dir. Every network failure degrades
to "unknown" — the app never blocks or breaks offline. Disable entirely with
`update_check = false` in config.toml. If the project repo ever moves, point
`update_source` in config.toml at the new location (GitHub also redirects
renamed/moved repos indefinitely, so old installs keep working regardless).
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

import yaml

from . import __version__
from .bootstrap import MACOS_BRANCHES, http_open
from .config import chown_to_invoker, data_dir, load_config_file

DEFAULT_UPDATE_SOURCE = "https://github.com/NarcoMoose/StigStiggly"
GUIDANCE_SOURCE = "https://github.com/usnistgov/macos_security"
CACHE_TTL_SECONDS = 24 * 3600
_VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)
_lock = threading.Lock()


def _cache_file() -> Path:
    return data_dir() / "update_check.json"


def _raw_url(repo_url: str, ref: str, path: str) -> str:
    base = repo_url.rstrip("/")
    if base.startswith("https://github.com/"):
        owner_repo = base.removeprefix("https://github.com/")
        return f"https://raw.githubusercontent.com/{owner_repo}/{ref}/{path}"
    return f"{base}/{ref}/{path}"  # non-GitHub mirrors: expect raw layout or file:// (tests)


def _fetch(url: str) -> str | None:
    try:
        with http_open(url, timeout=6) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - any network/parse issue means "unknown"
        return None


def _version_tuple(version: str) -> tuple:
    parts = []
    for chunk in version.split("."):
        digits = re.match(r"\d+", chunk)
        parts.append(int(digits.group()) if digits else 0)
    return tuple(parts)


def _check_app(source: str) -> dict:
    text = _fetch(_raw_url(source, "main", "pyproject.toml"))
    match = _VERSION_RE.search(text) if text else None
    latest = match.group(1) if match else None
    return {
        "current": __version__,
        "latest": latest,
        "outdated": bool(latest) and _version_tuple(latest) > _version_tuple(__version__),
        "source": source,
    }


def _guidance_branch(local_os: str | None) -> str | None:
    if not local_os:
        return None
    return MACOS_BRANCHES.get(str(local_os).split(".")[0])


def _check_guidance(repo: Path | None) -> dict:
    result = {"current_date": None, "latest_date": None, "outdated": False, "branch": None}
    if repo is None:
        return result
    try:
        local = yaml.safe_load((repo / "VERSION.yaml").read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return result
    branch = _guidance_branch(local.get("os"))
    result["branch"] = branch
    result["current_date"] = str(local.get("date") or "") or None
    if not branch:
        return result
    text = _fetch(_raw_url(GUIDANCE_SOURCE, branch, "VERSION.yaml"))
    if not text:
        return result
    try:
        remote = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return result
    result["latest_date"] = str(remote.get("date") or "") or None
    if result["current_date"] and result["latest_date"]:
        result["outdated"] = result["latest_date"] > result["current_date"]
    return result


def _load_cache() -> dict | None:
    try:
        return json.loads(_cache_file().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def check_updates(repo: Path | None, force: bool = False) -> dict:
    """Return update status, refreshing the daily cache when stale or forced."""
    cfg = load_config_file()
    if cfg.get("update_check") is False:
        return {"disabled": True, "app": None, "guidance": None}
    with _lock:
        cache = _load_cache()
        if cache and not force:
            age = datetime.now(timezone.utc).timestamp() - cache.get("checked_at", 0)
            if age < CACHE_TTL_SECONDS and cache.get("app_version") == __version__:
                return cache
        source = str(cfg.get("update_source") or DEFAULT_UPDATE_SOURCE)
        result = {
            "disabled": False,
            "checked_at": datetime.now(timezone.utc).timestamp(),
            "app_version": __version__,
            "app": _check_app(source),
            "guidance": _check_guidance(repo),
        }
        try:
            path = _cache_file()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(result), encoding="utf-8")
            chown_to_invoker(path)
        except OSError:
            pass
        return result


def cached_updates() -> dict | None:
    """Non-blocking read of the last check (may be stale or None)."""
    return _load_cache()


def refresh_async(repo: Path | None) -> None:
    """Kick a background refresh if the cache is stale; never blocks callers."""
    cache = _load_cache()
    if cache:
        age = datetime.now(timezone.utc).timestamp() - cache.get("checked_at", 0)
        if age < CACHE_TTL_SECONDS and cache.get("app_version") == __version__:
            return
    threading.Thread(target=check_updates, args=(repo,), daemon=True).start()
