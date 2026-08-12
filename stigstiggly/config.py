"""Application configuration and environment detection."""

from __future__ import annotations

import os
import platform
import pwd
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_PREFS_DIR = Path("/Library/Preferences")
MANAGED_PREFS_DIR = Path("/Library/Managed Preferences")
DEFAULT_PORT = 8377


def _invoker_home() -> Path:
    """The invoking user's home — under sudo, SUDO_USER's home, not /var/root."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return Path(pwd.getpwnam(sudo_user).pw_dir)
        except KeyError:
            pass
    return Path.home()


def default_repo() -> Path | None:
    """Best-guess location of the user's macos_security clone.

    Under sudo, HOME points at /var/root, so also check the invoking
    user's home (SUDO_USER) before giving up.
    """
    env = os.environ.get("STIGSTIGGLY_REPO")
    if env:
        return Path(env).expanduser()
    for home in dict.fromkeys([_invoker_home(), Path.home()]):
        guess = home / "Developer" / "macos_security"
        if guess.is_dir():
            return guess
    return None


def default_history_dir() -> Path:
    return _invoker_home() / ".local" / "share" / "stigstiggly" / "history"


@dataclass(frozen=True)
class AppConfig:
    repo: Path
    prefs_dir: Path = DEFAULT_PREFS_DIR
    build_dir: Path | None = None  # defaults to <repo>/build
    history_dir: Path = field(default_factory=default_history_dir)
    host: str = "127.0.0.1"  # never expose beyond loopback
    port: int = DEFAULT_PORT
    debug: bool = False
    allow_unprivileged_actions: bool = False  # fixture testing only

    @property
    def effective_build_dir(self) -> Path:
        return self.build_dir if self.build_dir else self.repo / "build"

    @property
    def can_act(self) -> bool:
        """Scan/remediation actions require root (or the explicit dev override)."""
        return os.geteuid() == 0 or self.allow_unprivileged_actions

    def validate(self) -> list[str]:
        problems = []
        if not (self.repo / "rules").is_dir():
            problems.append(
                f"{self.repo} does not look like a macos_security clone (no rules/ directory). "
                "Point --repo at your clone of https://github.com/usnistgov/macos_security"
            )
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
