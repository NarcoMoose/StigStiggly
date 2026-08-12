"""CLI entry point: `stigstiggly serve [--port N] [--repo PATH] [--prefs-dir PATH]`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import (
    DEFAULT_PORT,
    DEFAULT_PREFS_DIR,
    AppConfig,
    default_history_dir,
    default_repo,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigstiggly",
        description="Local web dashboard for mSCP (macOS Security Compliance Project) scan results.",
    )
    sub = parser.add_subparsers(dest="command")
    serve = sub.add_parser("serve", help="Start the dashboard (default command)")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port on 127.0.0.1 (default {DEFAULT_PORT})")
    serve.add_argument("--repo", type=Path, default=None, help="Path to your macos_security clone (default: ~/Developer/macos_security or $STIGSTIGGLY_REPO)")
    serve.add_argument(
        "--prefs-dir", type=Path, default=DEFAULT_PREFS_DIR,
        help="Directory scanned for org.*.audit.plist files (default /Library/Preferences; point at a fixture directory for testing)",
    )
    serve.add_argument(
        "--build-dir", type=Path, default=None,
        help="Directory containing <BASELINE>/<BASELINE>_compliance.sh scripts (default <repo>/build)",
    )
    serve.add_argument(
        "--history-dir", type=Path, default=None,
        help="Where scan-history snapshots are stored (default ~/.local/share/stigstiggly/history)",
    )
    serve.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    serve.add_argument(
        "--dev-allow-actions", action="store_true",
        help="Testing only: enable scan buttons without root (use with fixture --prefs-dir/--build-dir)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv.insert(0, "serve")  # make `serve` the default subcommand
    args = build_parser().parse_args(argv)

    repo = (args.repo or default_repo())
    if repo is None:
        print("error: could not locate a macos_security clone; pass --repo /path/to/macos_security", file=sys.stderr)
        return 2
    cfg = AppConfig(
        repo=repo.expanduser().resolve(),
        prefs_dir=args.prefs_dir.expanduser().resolve(),
        build_dir=args.build_dir.expanduser().resolve() if args.build_dir else None,
        history_dir=(args.history_dir.expanduser().resolve() if args.history_dir else default_history_dir()),
        port=args.port,
        debug=args.debug,
        allow_unprivileged_actions=args.dev_allow_actions,
    )
    problems = cfg.validate()
    if problems:
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        return 2

    from .server import create_app

    app = create_app(cfg)
    mode = "actions enabled" if cfg.can_act else "read-only (run with sudo to enable scans)"
    print(f"StigStiggly dashboard: http://{cfg.host}:{cfg.port}  (repo: {cfg.repo}, {mode})")
    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug)
    return 0


if __name__ == "__main__":
    sys.exit(main())
