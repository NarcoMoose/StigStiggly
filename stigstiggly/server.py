"""Flask application: dashboard views over the mscp_data layer plus the
scan-job API (POST /baseline/<name>/scan, GET /job, GET /job/<id>/stream)."""

from __future__ import annotations

import csv
import io
import secrets
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, abort, jsonify, redirect, render_template, request, url_for

from . import __version__
from .actions import (
    JobInProgress,
    JobManager,
    build_rule_fix_script,
    find_compliance_script,
    rule_fix_blocked_reason,
    set_exemption,
)
from .bootstrap import branch_for_host, download_guidance, run_doctor
from .builder import (
    BuilderError,
    build_catalog,
    built_artifacts,
    bundle_zip,
    create_custom_baseline,
    find_template,
    generation_command,
    list_templates,
)
from .history import diff_snapshots, load_history, record_snapshot
from .report import build_report
from .config import AppConfig, save_config_file
from .mscp_data import (
    REFERENCE_LABELS,
    Baseline,
    discover_baselines,
    load_repo_info,
    split_fix,
)

DONUT_ORDER = ("pass", "exempt", "fail", "not_scanned")
STALE_AFTER_DAYS = 7


def donut_segments(baseline: Baseline) -> list[dict]:
    """SVG stroke segments for a donut chart (circumference normalized to 100)."""
    total = len(baseline.rules)
    if not total:
        return []
    counts = baseline.counts
    segments, offset = [], 25.0  # start at 12 o'clock
    for status in DONUT_ORDER:
        pct = counts[status] * 100.0 / total
        if pct:
            segments.append({"status": status, "pct": pct, "offset": offset})
            offset -= pct
    return segments


def trend_chart(history: list[dict], width: int = 640, height: int = 150) -> dict | None:
    """Geometry for the compliance-trend SVG (evenly spaced scans, y = 0-100%)."""
    pts = [e for e in history if isinstance(e.get("pct"), (int, float))]
    if len(pts) < 2:
        return None
    pad_l, pad_r, pad_t, pad_b = 38, 14, 12, 22
    span_x, span_y = width - pad_l - pad_r, height - pad_t - pad_b
    x = lambda i: pad_l + i * span_x / (len(pts) - 1)
    y = lambda pct: pad_t + (100 - pct) * span_y / 100
    dots = [
        {
            "x": round(x(i), 1),
            "y": round(y(e["pct"]), 1),
            "title": f"{e['ts'][:16].replace('T', ' ')} — {e['pct']}% ({e['pass']} pass / {e['fail']} fail"
            + (f" / {e['exempt']} exempt" if e.get("exempt") else "")
            + ")",
        }
        for i, e in enumerate(pts)
    ]
    return {
        "w": width,
        "h": height,
        "pad_l": pad_l,
        "right": width - pad_r,
        "points": " ".join(f"{d['x']},{d['y']}" for d in dots),
        "dots": dots,
        "gridlines": [{"pct": p, "y": round(y(p), 1)} for p in (100, 50, 0)],
        "first": pts[0]["ts"][:10],
        "last": pts[-1]["ts"][:10],
        "count": len(pts),
        "delta": round(pts[-1]["pct"] - pts[0]["pct"], 1),
    }


DIFF_BUCKETS = (
    ("newly_failing", "Newly failing", "fail"),
    ("newly_passing", "Newly passing", "pass"),
    ("newly_exempt", "Newly exempt", "exempt"),
    ("unexempted", "Exemption removed", "unexempt"),
    ("added_rules", "Added to baseline", "added"),
    ("removed_rules", "Removed from baseline", "removed"),
)


def build_comparison(history: list[dict], requested_ts: str | None) -> dict | None:
    """Diff of the latest snapshot against a chosen older one, shaped for the
    template: chip groups per transition plus the picker's option list."""
    if len(history) < 2:
        return None
    latest, candidates = history[-1], history[:-1]
    older = next((e for e in candidates if e["ts"] == requested_ts), candidates[-1])
    diff = diff_snapshots(older, latest)
    groups = [
        {"key": key, "label": label, "css": css, "ids": diff.get(key) or []}
        for key, label, css in DIFF_BUCKETS
    ]
    return {
        "diff": diff,
        "groups": [g for g in groups if g["ids"]],
        "options": [
            {"ts": e["ts"], "label": f"{e['ts'][:16].replace('T', ' ')} — {e['pct']}%"}
            for e in reversed(candidates)
        ],
        "selected_ts": older["ts"],
        "latest_label": latest["ts"][:16].replace("T", " "),
        "changed": any(g["ids"] for g in groups),
    }


def scan_age_days(baseline: Baseline) -> int | None:
    if not baseline.last_check:
        return None
    now = datetime.now(timezone.utc)
    last = baseline.last_check
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return max((now - last).days, 0)


def create_app(cfg: AppConfig) -> Flask:
    app = Flask(__name__)
    app.config["cfg"] = cfg
    csrf_token = secrets.token_hex(16)
    jobs = JobManager()
    allowed_hosts = {f"127.0.0.1:{cfg.port}", f"localhost:{cfg.port}"}
    # Guidance content can be installed at runtime via /setup, so the resolved
    # repo lives in mutable state rather than the frozen config.
    state = {"repo": cfg.repo, "source": cfg.repo_source}

    def repo() -> Path | None:
        return state["repo"]

    def build_dir() -> Path | None:
        if cfg.build_dir:
            return cfg.build_dir
        return state["repo"] / "build" if state["repo"] else None

    def setup_redirect():
        """Where GET pages land while no guidance content is available."""
        return redirect(url_for("setup_view")) if repo() is None else None

    def setup_error():
        """JSON guard for action endpoints while in setup mode."""
        if repo() is None:
            return jsonify(error="guidance content not set up — visit /setup first"), 503
        return None

    @app.before_request
    def guard_requests():
        # Defends against DNS-rebinding: only loopback host headers are served.
        if request.host not in allowed_hosts:
            abort(403, "bad Host header")
        # All state-changing requests must carry the per-run CSRF token.
        if request.method == "POST" and request.headers.get("X-CSRF-Token") != csrf_token:
            return jsonify(error="missing or invalid CSRF token"), 403

    @app.context_processor
    def inject_globals():
        bdir = build_dir()
        return {
            "cfg": cfg,
            "repo_info": load_repo_info(repo()) if repo() else None,
            "app_version": __version__,
            "scan_age_days": scan_age_days,
            "stale_after": STALE_AFTER_DAYS,
            "ref_label": lambda key: REFERENCE_LABELS.get(key, key.replace("_", " ").upper()),
            "can_act": cfg.can_act,
            "csrf_token": csrf_token,
            "find_script": (lambda name: find_compliance_script(bdir, name) if bdir else None),
            "build_dir_display": str(bdir) if bdir else "(unset)",
        }

    def get_baseline(name: str) -> Baseline:
        for b in discover_baselines(cfg.prefs_dir, repo()):
            if b.name == name:
                return b
        abort(404, f"No audit results found for baseline '{name}'")

    def snapshot(*baselines: Baseline) -> None:
        """Record history opportunistically; never let it break a page view."""
        for b in baselines:
            try:
                record_snapshot(cfg.history_dir, b)
            except OSError:
                pass

    @app.route("/")
    def overview():
        if (r := setup_redirect()) is not None:
            return r
        baselines = discover_baselines(cfg.prefs_dir, repo())
        snapshot(*baselines)
        return render_template(
            "overview.html",
            baselines=baselines,
            donut_segments=donut_segments,
        )

    @app.route("/baseline/<name>")
    def baseline_view(name: str):
        if (r := setup_redirect()) is not None:
            return r
        baseline = get_baseline(name)
        snapshot(baseline)
        history = load_history(cfg.history_dir, baseline.name)
        return render_template(
            "baseline.html",
            baseline=baseline,
            donut_segments=donut_segments,
            trend=trend_chart(history),
            comparison=build_comparison(history, request.args.get("compare")),
            rule_titles={r.id: r.title for r in baseline.rules},
        )

    @app.route("/baseline/<name>/export.csv")
    def export_csv(name: str):
        if (r := setup_redirect()) is not None:
            return r
        baseline = get_baseline(name)
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            ["rule_id", "title", "section", "status", "severity", "stig_ids", "exempt", "exempt_reason", "last_scan"]
        )
        last = baseline.last_check.isoformat() if baseline.last_check else ""
        for section in baseline.sections:
            for r in section.rules:
                writer.writerow(
                    [r.id, r.title, section.name, r.status, r.severity,
                     " ".join(r.stig_ids), "yes" if r.exempt else "no", r.exempt_reason or "", last]
                )
        stamp = (baseline.last_check or datetime.now(timezone.utc)).strftime("%Y%m%d")
        return Response(
            buf.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{name}_results_{stamp}.csv"'},
        )

    @app.route("/baseline/<name>/rule/<rule_id>")
    def rule_view(name: str, rule_id: str):
        if (r := setup_redirect()) is not None:
            return r
        baseline = get_baseline(name)
        rule = next((r for r in baseline.rules if r.id == rule_id), None)
        if rule is None:
            abort(404, f"Rule '{rule_id}' not found in baseline '{name}'")
        fix_parts = split_fix(rule.fix) if rule.fix else []
        fix_code = "\n".join(chunk for kind, chunk in fix_parts if kind == "code")
        rulefix_blocked = (
            rule_fix_blocked_reason(fix_code, rule.check, rule.result_value)
            if rule.status == "fail"
            else None
        )
        return render_template(
            "rule.html",
            baseline=baseline,
            rule=rule,
            fix_parts=fix_parts,
            rulefix_blocked=rulefix_blocked,
        )

    # -- action API ----------------------------------------------------------

    def start_script_job(name: str, kind: str, flag: str):
        if (err := setup_error()) is not None:
            return err
        if not cfg.can_act:
            return jsonify(error=f"{kind} requires root; restart with: sudo stigstiggly serve"), 403
        get_baseline(name)  # 404 if unknown
        bdir = build_dir()
        script = find_compliance_script(bdir, name)
        if script is None:
            return jsonify(error=f"no compliance script found under {bdir / name}"), 404
        try:
            job = jobs.start(name, kind, ["/bin/zsh", str(script), flag])
        except JobInProgress as exc:
            return jsonify(error=str(exc)), 409
        return jsonify(job=job.to_dict()), 202

    @app.route("/baseline/<name>/scan", methods=["POST"])
    def start_scan(name: str):
        return start_script_job(name, "scan", "--check")

    @app.route("/baseline/<name>/fix", methods=["POST"])
    def start_fix(name: str):
        return start_script_job(name, "fix", "--fix")

    @app.route("/baseline/<name>/rule/<rule_id>/fix", methods=["POST"])
    def start_rule_fix(name: str, rule_id: str):
        if (err := setup_error()) is not None:
            return err
        if not cfg.can_act:
            return jsonify(error="remediation requires root; restart with: sudo stigstiggly serve"), 403
        baseline = get_baseline(name)
        rule = next((r for r in baseline.rules if r.id == rule_id), None)
        if rule is None:
            return jsonify(error=f"rule '{rule_id}' not found in baseline '{name}'"), 404
        if rule.status != "fail":
            return jsonify(error=f"rule is '{rule.status}', not a failed rule — nothing to remediate"), 400
        fix_code = "\n".join(chunk for kind, chunk in split_fix(rule.fix) if kind == "code")
        blocked = rule_fix_blocked_reason(fix_code, rule.check, rule.result_value)
        if blocked:
            return jsonify(error=blocked), 400
        script = build_rule_fix_script(rule.id, fix_code, rule.check, rule.result_value, baseline.plist_path)
        try:
            job = jobs.start(name, "rulefix", ["/bin/zsh", str(script)])
        except JobInProgress as exc:
            script.unlink(missing_ok=True)
            return jsonify(error=str(exc)), 409
        return jsonify(job=job.to_dict()), 202

    @app.route("/baseline/<name>/rule/<rule_id>/exempt", methods=["POST"])
    def set_rule_exemption(name: str, rule_id: str):
        if (err := setup_error()) is not None:
            return err
        if not cfg.can_act:
            return jsonify(error="managing exemptions requires root; restart with: sudo stigstiggly serve"), 403
        baseline = get_baseline(name)
        rule = next((r for r in baseline.rules if r.id == rule_id), None)
        if rule is None:
            return jsonify(error=f"rule '{rule_id}' not found in baseline '{name}'"), 404
        if rule.finding is None:
            return jsonify(error="rule has no scan result; run a scan before managing exemptions"), 400
        body = request.get_json(silent=True) or {}
        exempt = bool(body.get("exempt"))
        reason = (body.get("reason") or "").strip()
        if exempt and not reason:
            return jsonify(error="an exemption reason is required"), 400
        try:
            set_exemption(baseline.plist_path, rule_id, exempt, reason)
        except subprocess.CalledProcessError as exc:
            return jsonify(error=f"defaults write failed: {exc.stderr.strip() or exc}"), 500
        return jsonify(ok=True, exempt=exempt, reason=reason if exempt else None)

    # -- baseline builder ------------------------------------------------------

    @app.route("/builder")
    def builder_index():
        if (r := setup_redirect()) is not None:
            return r
        templates = list_templates(repo())
        customs = [
            {"template": t, "build": built_artifacts(repo(), t.name)}
            for t in templates
            if t.custom
        ]
        return render_template(
            "builder.html",
            templates=[t for t in templates if not t.custom],
            customs=customs,
        )

    @app.route("/builder/new")
    def builder_new():
        if (r := setup_redirect()) is not None:
            return r
        template = find_template(repo(), request.args.get("template", ""))
        if template is None:
            abort(404, "unknown template baseline")
        return render_template(
            "builder_new.html",
            catalog=build_catalog(repo(), template),
        )

    @app.route("/builder/create", methods=["POST"])
    def builder_create():
        if (err := setup_error()) is not None:
            return err
        body = request.get_json(silent=True) or {}
        template = find_template(repo(), str(body.get("template", "")))
        if template is None:
            return jsonify(error="unknown template baseline"), 404
        try:
            baseline_path = create_custom_baseline(
                repo(),
                name=str(body.get("name", "")).strip(),
                title=str(body.get("title", "")).strip(),
                description=str(body.get("description", "")).strip(),
                template=template,
                rule_ids=[str(r) for r in body.get("rules") or []],
                odv_values={str(k): str(v) for k, v in (body.get("odvs") or {}).items()},
            )
        except BuilderError as exc:
            return jsonify(error=str(exc)), 400
        except OSError as exc:
            return jsonify(error=f"could not write baseline files: {exc}"), 500
        try:
            job = jobs.start(
                str(body.get("name")), "generate", generation_command(repo(), baseline_path)
            )
        except JobInProgress as exc:
            return jsonify(error=str(exc)), 409
        return jsonify(job=job.to_dict()), 202

    @app.route("/builder/bundle/<name>.zip")
    def builder_bundle(name: str):
        if (r := setup_redirect()) is not None:
            return r
        template = find_template(repo(), name)
        artifacts = built_artifacts(repo(), name)
        if template is None or not template.custom or artifacts is None:
            abort(404, f"no generated build found for '{name}' — create it in the builder first")
        info = load_repo_info(repo())
        payload = bundle_zip(repo(), name, info.version_label)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
        return Response(
            payload,
            mimetype="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{name}_bundle_{stamp}.zip"'},
        )

    # -- setup mode -----------------------------------------------------------

    @app.route("/setup")
    def setup_view():
        checks = run_doctor(replace(cfg, repo=repo(), repo_source=state["source"]))
        return render_template(
            "setup.html",
            checks=checks,
            branch=branch_for_host(),
            have_repo=repo() is not None,
        )

    @app.route("/setup/download", methods=["POST"])
    def setup_download():
        branch = branch_for_host()
        if branch is None:
            return jsonify(error="no known macos_security branch for this macOS version; pass --repo or use `stigstiggly setup --branch`"), 400
        try:
            dest = download_guidance(branch)
        except Exception as exc:  # noqa: BLE001 - report network/extract errors to the UI
            return jsonify(error=f"download failed: {exc}"), 502
        try:
            save_config_file({"repo": str(dest)})
        except OSError as exc:
            return jsonify(error=f"downloaded, but could not write config file: {exc}"), 500
        state["repo"], state["source"] = dest, "downloaded content"
        return jsonify(ok=True, path=str(dest))

    @app.route("/report.json")
    def device_report():
        # Works even in setup mode: collectors still get host identity.
        return jsonify(build_report(replace(cfg, repo=repo(), repo_source=state["source"])))

    @app.route("/job")
    def job_state():
        job = jobs.current()
        return jsonify(job=job.to_dict() if job else None)

    @app.route("/job/<job_id>/stream")
    def job_stream(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            abort(404, "unknown or expired job")
        start = request.args.get("from", 0, type=int)
        return Response(
            job.sse_stream(start),
            mimetype="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.errorhandler(404)
    def not_found(err):
        if request.path.startswith(("/job", "/baseline")) and request.method == "POST":
            return jsonify(error=err.description), 404
        return render_template("error.html", error=err), 404

    return app
