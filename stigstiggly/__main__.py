"""CLI entry point: serve (default) / setup / doctor."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import (
    DEFAULT_PORT,
    DEFAULT_PREFS_DIR,
    AppConfig,
    config_file,
    default_history_dir,
    load_config_file,
    resolve_repo,
    save_config_file,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stigstiggly",
        description="Local web dashboard for mSCP (macOS Security Compliance Project) scan results.",
    )
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Start the dashboard (default command)")
    serve.add_argument("--port", type=int, default=None, help=f"Port on 127.0.0.1 (default {DEFAULT_PORT})")
    serve.add_argument("--repo", type=Path, default=None, help="Path to macos_security guidance content (overrides config file and bootstrap download)")
    serve.add_argument("--prefs-dir", type=Path, default=None, help="Directory scanned for org.*.audit.plist files (default /Library/Preferences; point at a fixture directory for testing)")
    serve.add_argument("--build-dir", type=Path, default=None, help="Directory containing <BASELINE>/<BASELINE>_compliance.sh scripts (default <repo>/build)")
    serve.add_argument("--history-dir", type=Path, default=None, help="Where scan-history snapshots are stored (default ~/.local/share/stigstiggly/history)")
    serve.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    serve.add_argument("--dev-allow-actions", action="store_true", help="Testing only: enable actions without root (use with fixture dirs)")

    setup = sub.add_parser("setup", help="Download guidance content for this macOS version and write the config file")
    setup.add_argument("--branch", default=None, help="macos_security branch to download (default: matched to host macOS)")
    setup.add_argument("--yes", "-y", action="store_true", help="Skip the confirmation prompt")

    sub.add_parser("doctor", help="Diagnose the environment and report what is missing")

    report = sub.add_parser("report", help="Print a device compliance report as JSON (for fleet collection)")
    report.add_argument("--output", "-o", type=Path, default=None, help="Write to a file instead of stdout")
    return parser


def _build_config(args) -> AppConfig:
    file_cfg = load_config_file()
    repo, source = resolve_repo(args.repo, file_cfg)

    def path_of(flag_value, key, default):
        if flag_value is not None:
            return flag_value.expanduser().resolve()
        if file_cfg.get(key):
            return Path(file_cfg[key]).expanduser()
        return default

    return AppConfig(
        repo=repo,
        repo_source=source,
        prefs_dir=path_of(args.prefs_dir, "prefs_dir", DEFAULT_PREFS_DIR),
        build_dir=path_of(args.build_dir, "build_dir", None),
        history_dir=path_of(args.history_dir, "history_dir", default_history_dir()),
        port=args.port if args.port is not None else int(file_cfg.get("port", DEFAULT_PORT)),
        debug=args.debug,
        allow_unprivileged_actions=args.dev_allow_actions,
    )


def cmd_serve(args) -> int:
    cfg = _build_config(args)
    problems = cfg.validate()
    if problems:
        for p in problems:
            print(f"error: {p}", file=sys.stderr)
        return 2

    from .server import create_app

    app = create_app(cfg)
    mode = "actions enabled" if cfg.can_act else "read-only (run with sudo to enable scans)"
    where = cfg.repo if cfg.repo else "no guidance content — setup mode"
    print(f"StigStiggly dashboard: http://{cfg.host}:{cfg.port}  (guidance: {where}, {mode})")
    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug)
    return 0


def cmd_setup(args) -> int:
    from .bootstrap import branch_for_host, download_guidance, host_macos_version

    branch = args.branch or branch_for_host()
    if branch is None:
        print(
            f"error: no known macos_security branch for macOS {host_macos_version()}; "
            "pass --branch explicitly (see https://github.com/usnistgov/macos_security/branches)",
            file=sys.stderr,
        )
        return 2
    existing, source = resolve_repo(None)
    if existing:
        print(f"Guidance content already available: {existing} (via {source})")
        print("Re-running setup will download a fresh copy and point the config file at it.")
    print(f"This will download the '{branch}' branch of usnistgov/macos_security (~15 MB)")
    print(f"into {Path.home() / '.local/share/stigstiggly/content'} and update {config_file()}.")
    if not args.yes:
        reply = input("Continue? [y/N] ").strip().lower()
        if reply not in ("y", "yes"):
            print("Aborted.")
            return 1
    try:
        dest = download_guidance(branch, progress=print)
    except Exception as exc:  # noqa: BLE001 - surface any network/extract failure plainly
        print(f"error: download failed: {exc}", file=sys.stderr)
        return 1
    save_config_file({"repo": str(dest)})
    print(f"Config written: {config_file()}")
    print("Setup complete — start the dashboard with: stigstiggly serve")
    return 0


def cmd_doctor(args) -> int:
    from .bootstrap import run_doctor

    cfg = _build_config(args)
    marks = {"ok": "✓", "warn": "!", "fail": "✗"}
    worst = 0
    for check in run_doctor(cfg):
        print(f" {marks[check.status]} {check.label:<22} {check.detail}")
        worst = max(worst, {"ok": 0, "warn": 0, "fail": 1}[check.status])
    return worst


def cmd_report(args) -> int:
    import json

    from .report import build_report

    cfg = _build_config(args)
    payload = json.dumps(build_report(cfg), indent=2)
    if args.output:
        args.output.write_text(payload + "\n", encoding="utf-8")
        print(f"Report written: {args.output}", file=sys.stderr)
    else:
        print(payload)
    return 0


def _fill_serve_defaults(args) -> None:
    """doctor/report reuse serve's flag structure for the shared config builder."""
    for attr in ("port", "repo", "prefs_dir", "build_dir", "history_dir"):
        if not hasattr(args, attr):
            setattr(args, attr, None)
    for attr in ("debug", "dev_allow_actions"):
        if not hasattr(args, attr):
            setattr(args, attr, False)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0].startswith("-"):
        argv.insert(0, "serve")  # make `serve` the default subcommand
    args = build_parser().parse_args(argv)

    if args.command == "setup":
        return cmd_setup(args)
    if args.command == "doctor":
        _fill_serve_defaults(args)
        return cmd_doctor(args)
    if args.command == "report":
        _fill_serve_defaults(args)
        return cmd_report(args)
    return cmd_serve(args)


if __name__ == "__main__":
    sys.exit(main())
