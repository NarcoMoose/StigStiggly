"""Application configuration: file-backed settings, path resolution, environment detection.

Precedence for every setting: CLI flag > environment > config file > default.
The config file lives at ``~/.config/stigstiggly/config.toml`` (invoking user's
home under sudo) and is written by ``stigstiggly setup`` / the web setup flow.
"""

from __future__ import annotations

import os
import platform
import pwd
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PREFS_DIR = Path("/Library/Preferences")
MANAGED_PREFS_DIR = Path("/Library/Managed Preferences")
DEFAULT_PORT = 8377
CONFIG_KEYS = ("repo", "build_dir", "history_dir", "prefs_dir", "port")


def _invoker_home() -> Path:
    """The invoking user's home — under sudo, SUDO_USER's home, not /var/root."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def chown_to_invoker(path: Path) -> None:
    """When running under sudo, hand files back to the invoking user so later
    unprivileged sessions can read and update them."""
    sudo_user = os.environ.get("SUDO_USER")
    if os.geteuid() != 0 or not sudo_user:
        return
    try:
        rec = pwd.getpwnam(sudo_user)
        os.chown(path, rec.pw_uid, rec.pw_gid)
    except (KeyError, OSError):
        pass


def config_dir() -> Path:
    xdg = os.environ.get("XDG_CONFIG_HOME")
    return (Path(xdg) if xdg else _invoker_home() / ".config") / "stigstiggly"


def data_dir() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME")
    return (Path(xdg) if xdg else _invoker_home() / ".local" / "share") / "stigstiggly"


def config_file() -> Path:
    return config_dir() / "config.toml"


def load_config_file() -> dict:
    """Read the config file. Unknown keys ignored; missing/corrupt file = {}."""
    try:
        data = tomllib.loads(config_file().read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return {k: data[k] for k in CONFIG_KEYS if k in data}


def save_config_file(values: dict) -> Path:
    """Merge `values` into the config file (simple TOML, known keys only)."""
    merged = {**load_config_file(), **{k: v for k, v in values.items() if k in CONFIG_KEYS and v is not None}}
    lines = ["# StigStiggly configuration (managed by `stigstiggly setup`)"]
    for key, value in merged.items():
        lines.append(f"port = {int(value)}" if key == "port" else f'{key} = "{value}"')
    path = config_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    chown_to_invoker(path.parent)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    chown_to_invoker(path)
    return path


def managed_content_dir() -> Path:
    """Where bootstrap-downloaded guidance content lives."""
    return data_dir() / "content"


def _looks_like_guidance(path: Path) -> bool:
    return (path / "rules").is_dir()


def resolve_repo(cli_repo: Path | None = None, file_cfg: dict | None = None) -> tuple[Path | None, str]:
    """Locate guidance content. Returns (path, source_description).

    Order: CLI flag > $STIGSTIGGLY_REPO > config file > bootstrap-managed
    content > legacy ~/Developer/macos_security guess.
    """
    file_cfg = load_config_file() if file_cfg is None else file_cfg
    candidates: list[tuple[Path, str]] = []
    if cli_repo:
        candidates.append((cli_repo.expanduser(), "--repo flag"))
    env = os.environ.get("STIGSTIGGLY_REPO")
    if env:
        candidates.append((Path(env).expanduser(), "$STIGSTIGGLY_REPO"))
    if file_cfg.get("repo"):
        candidates.append((Path(file_cfg["repo"]).expanduser(), str(config_file())))
    content = managed_content_dir()
    if content.is_dir():
        for entry in sorted(content.iterdir(), reverse=True):
            if _looks_like_guidance(entry):
                candidates.append((entry, "downloaded content"))
                break
    for home in dict.fromkeys([_invoker_home(), Path.home()]):
        candidates.append((home / "Developer" / "macos_security", "legacy default path"))

    for path, source in candidates:
        if _looks_like_guidance(path):
            return path.resolve(), source
    return None, "not found"


def default_history_dir() -> Path:
    return data_dir() / "history"


@dataclass(frozen=True)
class AppConfig:
    repo: Path | None  # None = setup mode: server guides the user to bootstrap
    repo_source: str = "unknown"
    prefs_dir: Path = DEFAULT_PREFS_DIR
    build_dir: Path | None = None  # defaults to <repo>/build
    history_dir: Path = field(default_factory=default_history_dir)
    host: str = "127.0.0.1"  # never expose beyond loopback
    port: int = DEFAULT_PORT
    debug: bool = False
    allow_unprivileged_actions: bool = False  # fixture testing only

    @property
    def can_act(self) -> bool:
        """Scan/remediation actions require root (or the explicit dev override)."""
        return os.geteuid() == 0 or self.allow_unprivileged_actions

    def validate(self) -> list[str]:
        problems = []
        if not self.prefs_dir.is_dir():
            problems.append(f"Preferences directory not found: {self.prefs_dir}")
        if self.debug and os.geteuid() == 0:
            problems.append("refusing to run --debug as root (the debugger allows code execution)")
        return problems


@dataclass(frozen=True)
class RepoInfo:
    """Guidance metadata from the repo's VERSION.yaml, checked against the host OS."""

    path: Path
    os_version: str | None = None
    version_label: str | None = None
    host_os: str = field(default_factory=lambda: platform.mac_ver()[0])

    @property
    def matches_host(self) -> bool | None:
        """True/False if both versions known (compared on major version), else None."""
        if not self.os_version or not self.host_os:
            return None
        return self.os_version.split(".")[0] == self.host_os.split(".")[0]
