"""Baseline builder: create tailored mSCP baselines and generate their artifacts.

StigStiggly never generates compliance content itself — it writes baseline and
custom-rule YAMLs following mSCP's own conventions (custom/baselines/,
custom/rules/ with `odv: {custom: ...}` overrides) and shells out to the
repo's `scripts/generate_guidance.py` for the actual script/profile/doc
generation.

ODV determinism: generated baselines always use ``parent_values: custom`` and
every selected rule that defines ODVs gets a custom-rule override carrying the
value shown in the builder UI (user-edited or the template's default). This
pins generate_guidance's resolution order (parent_values > custom >
recommended) to exactly what the user saw.
"""

from __future__ import annotations

import io
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import yaml

from .config import chown_to_invoker
from .mscp_data import RuleMeta, load_rule_index, _load_yaml

BASELINE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{1,63}$")

# rules/<dir>/ -> canonical mSCP section key (sections/<key>.yaml)
SECTION_FOR_DIR = {
    "audit": "auditing",
    "auth": "authentication",
    "icloud": "icloud",
    "os": "macos",
    "pwpolicy": "passwordpolicy",
    "system_settings": "systemsettings",
    "supplemental": "supplemental",
}
SECTION_ORDER = ["auditing", "authentication", "icloud", "macos", "passwordpolicy", "systemsettings", "supplemental"]
SECTION_NAMES = {
    "auditing": "Auditing",
    "authentication": "Authentication",
    "icloud": "iCloud",
    "macos": "macOS",
    "passwordpolicy": "Password Policy",
    "systemsettings": "System Settings",
    "supplemental": "Supplemental",
}


@dataclass
class TemplateInfo:
    name: str
    title: str
    rule_count: int
    path: Path
    custom: bool


def _baseline_files(repo: Path) -> list[tuple[Path, bool]]:
    stock = [(p, False) for p in sorted(repo.glob("baselines/*.yaml"))]
    custom = [(p, True) for p in sorted(repo.glob("custom/baselines/*.yaml"))]
    return [(p, c) for p, c in stock + custom if not p.name.startswith("._")]


def template_rule_ids(path: Path) -> list[str]:
    data = _load_yaml(path)
    return [str(r) for prof in data.get("profile") or [] for r in prof.get("rules") or []]


def list_templates(repo: Path) -> list[TemplateInfo]:
    out = []
    for path, custom in _baseline_files(repo):
        data = _load_yaml(path)
        out.append(
            TemplateInfo(
                name=path.stem,
                title=str(data.get("title") or path.stem),
                rule_count=len(template_rule_ids(path)),
                path=path,
                custom=custom,
            )
        )
    return out


def find_template(repo: Path, name: str) -> TemplateInfo | None:
    return next((t for t in list_templates(repo) if t.name == name), None)


def _section_key(meta: RuleMeta) -> str:
    return SECTION_FOR_DIR.get(meta.source.parent.name, "macos")


def _odv_default(meta: RuleMeta, parent_values: str | None):
    """The ODV value the template would resolve to (parent_values > recommended)."""
    if not meta.odv:
        return None
    for key in (parent_values, "custom", "recommended"):
        if key and key in meta.odv:
            return meta.odv[key]
    return None


def build_catalog(repo: Path, template: TemplateInfo) -> dict:
    """Everything the rule-picker page needs, grouped by canonical section."""
    template_data = _load_yaml(template.path)
    parent_values = template_data.get("parent_values")
    selected = set(template_rule_ids(template.path))
    index = load_rule_index(repo)

    groups: dict[str, list[dict]] = {}
    all_tags: set[str] = set()
    for meta in index.values():
        all_tags.update(meta.tags)
        odv = None
        if meta.odv:
            default = _odv_default(meta, parent_values)
            odv = {"hint": str(meta.odv.get("hint", "")), "default": "" if default is None else str(default)}
        groups.setdefault(_section_key(meta), []).append(
            {
                "id": meta.id,
                "title": meta.title,
                "severity": meta.severity or "n/a",
                "tags": meta.tags,
                "in_template": meta.id in selected,
                "odv": odv,
            }
        )

    keys = SECTION_ORDER + sorted(set(groups) - set(SECTION_ORDER))
    sections = [
        {"key": key, "name": SECTION_NAMES.get(key, key.title()), "rules": sorted(groups[key], key=lambda r: r["id"])}
        for key in keys
        if key in groups
    ]
    return {
        "template": {"name": template.name, "title": template.title, "parent_values": parent_values},
        "sections": sections,
        "tags": sorted(all_tags),
        "selected_count": len(selected),
    }


class BuilderError(ValueError):
    pass


def create_custom_baseline(
    repo: Path,
    name: str,
    title: str,
    description: str,
    template: TemplateInfo,
    rule_ids: list[str],
    odv_values: dict[str, str],
) -> Path:
    """Write custom-rule ODV overrides and the baseline YAML. Returns baseline path."""
    if not BASELINE_NAME_RE.match(name):
        raise BuilderError("baseline name must be 2-64 chars: letters, digits, - and _")
    stock_names = {t.name for t in list_templates(repo) if not t.custom}
    if name in stock_names:
        raise BuilderError(f"'{name}' is a stock mSCP baseline name; choose another")
    index = load_rule_index(repo)
    unknown = [r for r in rule_ids if r not in index]
    if unknown:
        raise BuilderError(f"unknown rules: {', '.join(unknown[:5])}")
    if not rule_ids:
        raise BuilderError("select at least one rule")

    template_data = _load_yaml(template.path)
    parent_values = template_data.get("parent_values")

    # Pin ODVs via custom-rule overrides (mSCP convention).
    custom_rules_dir = repo / "custom" / "rules"
    custom_rules_dir.mkdir(parents=True, exist_ok=True)
    for rid in rule_ids:
        meta = index[rid]
        if not meta.odv:
            continue
        raw = odv_values.get(rid, "")
        value = raw if str(raw).strip() != "" else _odv_default(meta, parent_values)
        if value is None:
            continue
        default = _odv_default(meta, parent_values)
        if isinstance(default, int) and str(value).lstrip("-").isdigit():
            value = int(value)
        override_path = custom_rules_dir / f"{rid}.yaml"
        existing = _load_yaml(override_path) if override_path.is_file() else {}
        odv_block = dict(existing.get("odv") or {})
        odv_block["custom"] = value
        payload = {**existing, "id": rid, "odv": odv_block}
        override_path.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
        chown_to_invoker(override_path)

    sections: dict[str, list[str]] = {}
    for rid in sorted(set(rule_ids)):
        sections.setdefault(_section_key(index[rid]), []).append(rid)
    keys = [k for k in SECTION_ORDER if k in sections] + sorted(set(sections) - set(SECTION_ORDER))

    # generate_guidance.py requires "<part>: <subtitle>" titles (it splits on ':')
    full_title = title or f"{name} (custom baseline)"
    if ":" not in full_title:
        os_version = str(_load_yaml(repo / "VERSION.yaml").get("os") or "").strip()
        prefix = f"macOS {os_version}" if os_version else "Custom Baseline"
        full_title = f"{prefix}: {full_title}"

    baseline = {
        "title": full_title,
        "description": (description or f"Custom baseline '{name}' created with StigStiggly, "
                        f"based on {template.name}.") + "\n",
        "authors": template_data.get("authors") or "|===\n|Created with StigStiggly\n|===\n",
        "parent_values": "custom",
        "profile": [{"section": key, "rules": sections[key]} for key in keys],
    }
    baselines_dir = repo / "custom" / "baselines"
    baselines_dir.mkdir(parents=True, exist_ok=True)
    chown_to_invoker(custom_rules_dir.parent)
    chown_to_invoker(baselines_dir)
    path = baselines_dir / f"{name}.yaml"
    path.write_text(yaml.safe_dump(baseline, sort_keys=False, width=100), encoding="utf-8")
    chown_to_invoker(path)
    return path


def generation_command(repo: Path, baseline_path: Path) -> list[str]:
    """Run mSCP's own generator: compliance script, profiles, xls."""
    return [
        sys.executable,
        str(repo / "scripts" / "generate_guidance.py"),
        str(baseline_path.resolve()),
        "-s",
        "-p",
        "-x",
    ]


def built_artifacts(repo: Path, name: str) -> dict | None:
    """Summary of a generated build dir (None if generation never ran)."""
    build = repo / "build" / name
    if not build.is_dir():
        return None
    script = build / f"{name}_compliance.sh"
    files = [p for p in build.rglob("*") if p.is_file() and not p.name.startswith("._")]
    return {
        "path": build,
        "script": script if script.is_file() else None,
        "file_count": len(files),
        "mtime": datetime.fromtimestamp(max((p.stat().st_mtime for p in files), default=0), tz=timezone.utc),
    }


def bundle_zip(repo: Path, name: str, guidance_label: str | None) -> bytes:
    """Zip the generated build directory plus a build-info manifest."""
    build = repo / "build" / name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(build.rglob("*")):
            if path.is_file() and not path.name.startswith("._"):
                zf.write(path, f"{name}/{path.relative_to(build)}")
        info = (
            f"Baseline: {name}\n"
            f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
            f"Guidance: {guidance_label or 'unknown'}\n"
            f"Created with StigStiggly + mSCP generate_guidance.py\n\n"
            f"Apply on a target machine:\n"
            f"  sudo zsh {name}/{name}_compliance.sh --check   # scan\n"
            f"  sudo zsh {name}/{name}_compliance.sh --fix     # remediate failed rules\n"
            f"Install configuration profiles from {name}/mobileconfigs/ via MDM or manually.\n"
        )
        zf.writestr(f"{name}/BUILD_INFO.txt", info)
    return buf.getvalue()
