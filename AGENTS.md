# StigStiggly

Local web dashboard for visualizing mSCP (macOS Security Compliance Project) scan
results. Unprivileged mode is strictly read-only; running under sudo enables
scans, remediation, and exemption management from the dashboard.

## Setup

```sh
python3 -m venv .venv
.venv/bin/pip install -e .
```

## Run

```sh
.venv/bin/stigstiggly serve            # http://127.0.0.1:8377, read-only
sudo .venv/bin/stigstiggly serve       # scan actions enabled
.venv/bin/stigstiggly serve --debug    # auto-reload during development (refused as root)
```

Defaults: reads scan results from `/Library/Preferences/org.*.audit.plist`, rule
metadata from `~/Developer/macos_security` (override with `--repo` or `$STIGSTIGGLY_REPO`),
and compliance scripts from `<repo>/build/<BASELINE>/` (override with `--build-dir`).
Scan-history snapshots live in `~/.local/share/stigstiggly/history/` (override with
`--history-dir`).

## Testing without touching real system data

Point discovery at fixture directories; `--dev-allow-actions` enables the scan
buttons without root so the job pipeline can be exercised against the fake
compliance script in `tests/fixtures/build/`:

```sh
.venv/bin/stigstiggly serve --port 8378 \
  --prefs-dir tests/fixtures/prefs \
  --build-dir tests/fixtures/build \
  --repo tests/fixtures/repo \
  --history-dir /tmp/stig-history-test \
  --dev-allow-actions
```

(`tests/fixtures/repo/` is a synthetic guidance repo whose demo rules use
echo-based checks/fixes, so even per-rule remediation is harmless there. Omit
`--repo` to test display against the real macos_security metadata instead.)

## Verify

```sh
.venv/bin/python -m compileall stigstiggly            # syntax check
curl -s http://127.0.0.1:8377/ | grep -c baseline-card # smoke test while serving
```

## Architecture notes

- `mscp_data.py` — read layer. Joins audit plists with rule YAMLs from the
  macos_security clone; resolves `$ODV` via the baseline's `parent_values`;
  custom/rules overrides rules/. Never writes anything.
- `actions.py` — single-job runner (`JobManager`); scans/remediation shell out to
  mSCP's own generated `*_compliance.sh` (`--check` / `--fix`, both verified
  non-interactive: the script's `ask()` auto-confirms when `$fix` is set). Output
  lines buffered so SSE clients can attach/re-attach mid-run. One job at a time,
  system-wide. Never reimplement fix logic — always mSCP's own script.
- Exemptions (`set_exemption`) use mSCP's documented mechanism:
  `defaults write <plist> <rule> -dict-add exempt -bool ... exempt_reason -string ...`
  — merges without clobbering `finding`, coherent with the NSUserDefaults suite
  reads the compliance script performs. Un-exempting sets `exempt=false` (a stale
  `exempt_reason` may remain; both this UI and the script ignore it).
- `server.py` — Flask app factory; all views server-rendered (Jinja), charts are
  inline SVG, no frontend build step and no CDN dependencies. Action API:
  `POST /baseline/<name>/scan`, `POST /baseline/<name>/fix`,
  `POST /baseline/<name>/rule/<id>/exempt`, `GET /job`, `GET /job/<id>/stream` (SSE).
- Remediation UX: confirmation modal lists the exact failed non-exempt rules and
  the command; after a fix job succeeds the client automatically chains a fresh
  `--check` scan so displayed results reflect post-fix state.
- Per-rule remediation (`POST /baseline/<name>/rule/<id>/fix`): builds a
  self-deleting zsh script from the rule's own ODV-resolved YAML fix/check
  (commands stay verbatim NIST content; only orchestration is ours): apply fix,
  re-run the rule's check, update the audit plist (`finding=false`) only if the
  check returns the expected value (exit 3 otherwise, plist untouched). Refused
  for rules without shell fixes, without automatable checks, or whose fix needs
  compliance-script context vars ($CURRENT_USER — see `SCRIPT_CONTEXT_VARS`).
  Only rules in status `fail` qualify (pass/exempt/not_scanned are 400s). No
  follow-up scan is chained; the page just reloads. Tested via the synthetic
  repo in `tests/fixtures/repo/` (echo-based rules; never touches real state).
- Security posture: binds 127.0.0.1 only, Host-header allowlist (DNS-rebinding
  defense), per-run CSRF token required on every POST, `--debug` refused as root.
- Compliance % formula mirrors the mSCP compliance script: (pass + exempt) / scanned.
- `history.py` — append-only JSONL snapshot per baseline (counts, per-status rule
  id lists, host OS version), recorded opportunistically on page load whenever
  `lastComplianceCheck` is new, so history accrues even for scans run outside the
  dashboard. Under sudo, files are chown'd to `SUDO_USER` so unprivileged sessions
  can keep appending. The baseline page renders a trend line (server-side SVG)
  once 2+ scans exist. `diff_snapshots(older, newer)` computes scan-to-scan
  transitions (newly failing/passing/exempt, baseline membership changes, OS
  version change); tolerates pre-enrichment entries that lack pass/not_scanned
  ids via its `complete` flag.
- Scan comparison UI: "Changes since" card on the baseline page (below the trend
  line) — latest scan vs. a picked older snapshot (`?compare=<ts>`, default:
  previous). Renders transition chip groups linking to rule pages, a pct-delta
  badge, and an OS-version-change banner when the host OS differs between the
  two snapshots.
- CSV export: `GET /baseline/<name>/export.csv` — one row per rule with section,
  status, severity, STIG IDs, and exemption info.
