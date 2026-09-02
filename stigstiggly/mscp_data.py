"""Read layer: discover mSCP audit results and join them with rule metadata.

Data sources (all read-only):
  * ``<prefs_dir>/org.<baseline>.audit.plist``   -- scan results written by the
    mSCP-generated compliance script (``finding`` bool per rule, plus optional
    ``exempt`` / ``exempt_reason`` keys).
  * ``/Library/Managed Preferences/org.<baseline>.audit.plist`` -- MDM-managed
    exemptions, overlaid when present (mirrors the compliance script, which
    reads exemptions through NSUserDefaults).
  * ``<repo>/rules/**/*.yaml`` and ``<repo>/custom/rules/**/*.yaml`` -- rule
    metadata (title, severity, STIG IDs, check/fix text). Custom rules win.
  * ``<repo>/baselines/<name>.yaml`` -- section grouping and ODV parent values.
  * ``<repo>/sections/<key>.yaml``   -- human-readable section names.
"""

from __future__ import annotations

import plistlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import yaml

from .config import MANAGED_PREFS_DIR, RepoInfo

AUDIT_PLIST_RE = re.compile(r"^org\.(?P<name>.+)\.audit\.plist$")
SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}
STATUSES = ("pass", "fail", "exempt", "not_scanned")

REFERENCE_LABELS = {
    "disa_stig": "DISA STIG",
    "srg": "SRG",
    "cci": "CCI",
    "cce": "CCE",
    "800-53r5": "NIST 800-53r5",
    "800-53r4": "NIST 800-53r4",
    "800-171r3": "NIST 800-171r3",
    "cis": "CIS",
    "cmmc": "CMMC",
    "indigo": "BSI Indigo",
}


@dataclass
class RuleMeta:
    """Static metadata parsed from a rule YAML file."""

    id: str
    title: str
    discussion: str
    check: str
    fix: str
    result_expected: str
    result_raw: str  # bare expected value for verification (e.g. "1"), pre-ODV
    severity: str | None
    references: dict[str, list[str]]
    tags: list[str]
    mobileconfig: bool
    odv: dict
    source: Path

    @property
    def stig_ids(self) -> list[str]:
        return self.references.get("disa_stig", [])


@dataclass
class RuleStatus:
    """One rule's state within a specific baseline scan."""

    id: str
    status: str  # pass | fail | exempt | not_scanned
    finding: bool | None
    exempt: bool
    exempt_reason: str | None
    section_key: str
    meta: RuleMeta | None
    check: str = ""  # ODV-resolved copies for display
    fix: str = ""
    result_expected: str = ""
    result_value: str = ""  # ODV-resolved bare expected value, for verification

    @property
    def title(self) -> str:
        return self.meta.title if self.meta else self.id

    @property
    def severity(self) -> str:
        return (self.meta.severity if self.meta else None) or "n/a"

    @property
    def stig_ids(self) -> list[str]:
        return self.meta.stig_ids if self.meta else []


@dataclass
class Section:
    key: str
    name: str
    description: str
    rules: list[RuleStatus] = field(default_factory=list)


@dataclass
class Baseline:
    """A discovered baseline: scan results joined with guidance metadata."""

    name: str
    plist_path: Path
    title: str
    description: str
    parent_values: str | None
    last_check: datetime | None
    sections: list[Section]
    yaml_found: bool

    @property
    def rules(self) -> list[RuleStatus]:
        return [r for s in self.sections for r in s.rules]

    @property
    def counts(self) -> dict[str, int]:
        c = dict.fromkeys(STATUSES, 0)
        for r in self.rules:
            c[r.status] += 1
        return c

    @property
    def scanned_total(self) -> int:
        c = self.counts
        return c["pass"] + c["fail"] + c["exempt"]

    @property
    def compliance_pct(self) -> float | None:
        """Mirror the mSCP script formula: (compliant + exempt) / scanned."""
        total = self.scanned_total
        if not total:
            return None
        c = self.counts
        return round((c["pass"] + c["exempt"]) * 100 / total, 1)

    @property
    def severity_fail(self) -> dict[str, int]:
        """Failed-rule counts keyed by severity, ordered high -> low -> n/a."""
        out: dict[str, int] = {}
        fails = [r for r in self.rules if r.status == "fail"]
        for sev in sorted({r.severity for r in fails}, key=lambda s: SEVERITY_RANK.get(s, 99)):
            out[sev] = sum(1 for r in fails if r.severity == sev)
        return out


# --------------------------------------------------------------------------
# Repo parsing (cached per repo path; rule YAMLs only re-read when they change)
# --------------------------------------------------------------------------

_rule_index_cache: dict[Path, tuple[float, dict[str, RuleMeta]]] = {}


def _load_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError, UnicodeDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_repo_info(repo: Path) -> RepoInfo:
    data = _load_yaml(repo / "VERSION.yaml")
    return RepoInfo(
        path=repo,
        os_version=str(data["os"]) if data.get("os") else None,
        version_label=data.get("version"),
    )


def _parse_rule_file(path: Path) -> RuleMeta | None:
    data = _load_yaml(path)
    rule_id = data.get("id")
    if not rule_id:
        return None
    refs = {
        key: [str(v) for v in vals]
        for key, vals in (data.get("references") or {}).items()
        if isinstance(vals, list)
    }
    result = data.get("result")
    result_raw = ""
    if isinstance(result, dict):
        result_expected = ", ".join(f"{k}: {v}" for k, v in result.items())
        if result:
            first = next(iter(result.values()))
            result_raw = ("1" if first else "0") if isinstance(first, bool) else str(first)
    else:
        result_expected = str(result) if result else ""
    return RuleMeta(
        id=str(rule_id),
        title=data.get("title") or str(rule_id),
        discussion=(data.get("discussion") or "").strip(),
        check=(data.get("check") or "").strip(),
        fix=(data.get("fix") or "").strip(),
        result_expected=result_expected,
        result_raw=result_raw,
        severity=data.get("severity"),
        references=refs,
        tags=[str(t) for t in data.get("tags") or []],
        mobileconfig=bool(data.get("mobileconfig")),
        odv=data.get("odv") if isinstance(data.get("odv"), dict) else {},
        source=path,
    )


def load_rule_index(repo: Path) -> dict[str, RuleMeta]:
    """Index all rule YAMLs by rule id. custom/rules overrides rules/."""
    files = [
        f
        for f in sorted(repo.glob("rules/**/*.yaml")) + sorted(repo.glob("custom/rules/**/*.yaml"))
        if not f.name.startswith("._")  # AppleDouble metadata files
    ]
    newest = max((f.stat().st_mtime for f in files), default=0.0)
    cached = _rule_index_cache.get(repo)
    if cached and cached[0] == newest:
        return cached[1]
    index: dict[str, RuleMeta] = {}
    for f in files:  # later (custom) entries overwrite earlier ones
        meta = _parse_rule_file(f)
        if meta:
            index[meta.id] = meta
    _rule_index_cache[repo] = (newest, index)
    return index


def load_sections(repo: Path) -> dict[str, tuple[str, str]]:
    """Map section key -> (name, description) from <repo>/sections/*.yaml."""
    out: dict[str, tuple[str, str]] = {}
    for f in repo.glob("sections/*.yaml"):
        data = _load_yaml(f)
        if data.get("name"):
            out[f.stem.lower()] = (data["name"], (data.get("description") or "").strip())
    return out


def _find_baseline_yaml(repo: Path, name: str) -> Path | None:
    exact = repo / "baselines" / f"{name}.yaml"
    if exact.is_file():
        return exact
    for f in repo.glob("baselines/*.yaml"):  # tolerant fallback
        if f.stem.lower() == name.lower():
            return f
    return None


# --------------------------------------------------------------------------
# Scan results
# --------------------------------------------------------------------------


def _read_audit_plist(path: Path) -> tuple[dict[str, dict], datetime | None]:
    """Return ({rule_id: entry_dict}, last_check). Tolerates unreadable files."""
    try:
        with path.open("rb") as fp:
            data = plistlib.load(fp)
    except (OSError, plistlib.InvalidFileException):
        return {}, None
    results = {k: v for k, v in data.items() if isinstance(v, dict)}
    last = data.get("lastComplianceCheck")
    if isinstance(last, str):
        try:
            last = datetime.strptime(last, "%Y-%m-%d %H:%M:%S%z")
        except ValueError:
            last = None
    return results, last if isinstance(last, datetime) else None


def resolve_odv(text: str, odv: dict, parent_values: str | None) -> str:
    """Substitute $ODV with the baseline's organization-defined value."""
    if "$ODV" not in text or not odv:
        return text
    value = odv.get(parent_values) if parent_values else None
    if value is None:
        value = odv.get("recommended")
    return text.replace("$ODV", str(value)) if value is not None else text


def _build_rule_status(
    rule_id: str,
    entry: dict | None,
    managed_entry: dict | None,
    section_key: str,
    meta: RuleMeta | None,
    parent_values: str | None,
) -> RuleStatus:
    exempt_source = managed_entry if managed_entry is not None else (entry or {})
    exempt = bool(exempt_source.get("exempt"))
    exempt_reason = exempt_source.get("exempt_reason")
    if entry is None:
        status, finding = "not_scanned", None
    else:
        finding = bool(entry.get("finding"))
        status = "pass" if not finding else ("exempt" if exempt else "fail")
    rs = RuleStatus(
        id=rule_id,
        status=status,
        finding=finding,
        exempt=exempt,
        exempt_reason=str(exempt_reason) if exempt_reason else None,
        section_key=section_key,
        meta=meta,
    )
    if meta:
        rs.check = resolve_odv(meta.check, meta.odv, parent_values)
        rs.fix = resolve_odv(meta.fix, meta.odv, parent_values)
        rs.result_expected = resolve_odv(meta.result_expected, meta.odv, parent_values)
        rs.result_value = resolve_odv(meta.result_raw, meta.odv, parent_values)
    return rs


def load_baseline(plist_path: Path, repo: Path) -> Baseline:
    match = AUDIT_PLIST_RE.match(plist_path.name)
    name = match.group("name") if match else plist_path.stem
    results, last_check = _read_audit_plist(plist_path)
    managed: dict[str, dict] = {}
    managed_path = MANAGED_PREFS_DIR / plist_path.name
    if managed_path != plist_path and managed_path.is_file():
        managed, _ = _read_audit_plist(managed_path)

    rule_index = load_rule_index(repo)
    section_names = load_sections(repo)
    baseline_yaml = _find_baseline_yaml(repo, name)
    data = _load_yaml(baseline_yaml) if baseline_yaml else {}
    parent_values = data.get("parent_values")
    remaining = dict(results)
    sections: list[Section] = []

    for prof in data.get("profile") or []:
        key = str(prof.get("section", ""))
        display, desc = section_names.get(key.lower(), (key.replace("_", " ").title(), ""))
        section = Section(key=key, name=display, description=desc)
        for rule_id in prof.get("rules") or []:
            section.rules.append(
                _build_rule_status(
                    rule_id, remaining.pop(rule_id, None), managed.get(rule_id),
                    key, rule_index.get(rule_id), parent_values,
                )
            )
        sections.append(section)

    if remaining:  # scanned rules missing from the baseline definition
        extra = Section(
            key="other",
            name="Other Scanned Rules" if data else "Scanned Rules",
            description="" if not data else "Rules present in the scan results but not in the baseline definition (baseline YAML may be out of date).",
        )
        for rule_id in sorted(remaining):
            extra.rules.append(
                _build_rule_status(
                    rule_id, remaining[rule_id], managed.get(rule_id),
                    "other", rule_index.get(rule_id), parent_values,
                )
            )
        sections.append(extra)

    return Baseline(
        name=name,
        plist_path=plist_path,
        title=data.get("title") or name,
        description=(data.get("description") or "").strip(),
        parent_values=parent_values,
        last_check=last_check,
        sections=sections,
        yaml_found=baseline_yaml is not None,
    )


def discover_baselines(prefs_dir: Path, repo: Path) -> list[Baseline]:
    """Find every org.*.audit.plist in prefs_dir and load it as a Baseline."""
    plists = sorted(p for p in prefs_dir.glob("org.*.audit.plist") if AUDIT_PLIST_RE.match(p.name))
    return [load_baseline(p, repo) for p in plists]


# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------

_FIX_BLOCK_RE = re.compile(r"\[source,[^\]]*\]\s*\n-{4,}\n(.*?)\n-{4,}", re.DOTALL)


def split_fix(fix_text: str) -> list[tuple[str, str]]:
    """Split a rule's asciidoc fix into [('code'|'text', chunk), ...] for display."""
    parts: list[tuple[str, str]] = []
    pos = 0
    for m in _FIX_BLOCK_RE.finditer(fix_text):
        before = fix_text[pos : m.start()].strip()
        if before:
            parts.append(("text", before))
        parts.append(("code", m.group(1).strip()))
        pos = m.end()
    tail = fix_text[pos:].strip()
    if tail:
        parts.append(("text", tail))
    return parts
