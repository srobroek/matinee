#!/usr/bin/env python3
"""Project status discovery for the /speckit.status-report.show command.

Discovers project structure and artifact existence, counts task completion, and
writes a fresh {SPECS_DIR}/spec-status.md on every run.

Usage: get_project_status.py [OPTIONS]

OPTIONS:
  --json              Output in JSON format (default: text)
  --feature <name>    Focus on specific feature (name, number prefix, or path)
  --help, -h          Show this help message

This is the python runtime variant. It is behaviour-for-behaviour equivalent to
scripts/bash/get-project-status.sh and scripts/powershell/Get-ProjectStatus.ps1;
tests/test-status.sh asserts all three agree.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Sequential prefixes are three digits or more (001-, 1000-); --timestamp
# features are prefixed YYYYMMDD-HHMMSS.
FEATURE_RE = re.compile(r"^\d{3}\d*-")
NUMBER_PREFIX_RE = re.compile(r"^(\d{3}\d*)-")
TASK_TOTAL_RE = re.compile(r"^\s*- \[[ xX]\]")
TASK_DONE_RE = re.compile(r"^\s*- \[[xX]\]")

ARTIFACTS = {
    "has_spec": "spec.md",
    "has_plan": "plan.md",
    "has_tasks": "tasks.md",
    "has_research": "research.md",
    "has_data_model": "data-model.md",
    "has_quickstart": "quickstart.md",
    "has_contracts": "contracts",
    "has_checklists": "checklists",
}


def git(*args: str, cwd: Path | None = None) -> str | None:
    """Run a git command, returning stripped stdout or None on any failure."""
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
        )
    except (OSError, ValueError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.strip() or None


def find_repo_root(start: Path) -> Path | None:
    """Walk up looking for a .git or .specify directory."""
    for candidate in [start, *start.parents]:
        if (candidate / ".git").is_dir() or (candidate / ".specify").is_dir():
            return candidate
    return None


def get_project_name(repo_root: Path) -> str:
    package_json = repo_root / "package.json"
    if package_json.is_file():
        try:
            name = json.loads(package_json.read_text(encoding="utf-8")).get("name")
            if isinstance(name, str) and name:
                return name
        except (OSError, ValueError):
            pass

    pyproject = repo_root / "pyproject.toml"
    if pyproject.is_file():
        try:
            match = re.search(
                r'^name\s*=\s*"([^"]+)"',
                pyproject.read_text(encoding="utf-8"),
                re.MULTILINE,
            )
            if match:
                return match.group(1)
        except OSError:
            pass

    return repo_root.name


def check_exists(path: Path) -> bool:
    """True for an existing file, or a directory with at least one entry."""
    if path.is_file():
        return True
    if path.is_dir():
        try:
            return any(path.iterdir())
        except OSError:
            return False
    return False


def count_tasks(tasks_file: Path) -> tuple[int, int]:
    if not tasks_file.is_file():
        return 0, 0
    try:
        lines = tasks_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0, 0
    total = sum(1 for line in lines if TASK_TOTAL_RE.match(line))
    completed = sum(1 for line in lines if TASK_DONE_RE.match(line))
    return total, completed


def read_feature_json(repo_root: Path) -> str:
    """Read .specify/feature.json's feature_directory, or '' if unavailable."""
    feature_json = repo_root / ".specify" / "feature.json"
    if not feature_json.is_file():
        return ""
    try:
        data = json.loads(feature_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    value = data.get("feature_directory") if isinstance(data, dict) else None
    return value if isinstance(value, str) else ""


def match_feature(identifier: str, features: list[str]) -> str | None:
    """Exact name first, then leading number prefix.

    A branch name may abbreviate the directory name, so the prefix is the
    fallback rather than the primary match.
    """
    if not identifier:
        return None
    if identifier in features:
        return identifier
    match = NUMBER_PREFIX_RE.match(identifier)
    if not match:
        return None
    prefix = match.group(1) + "-"
    for feature in features:
        if feature.startswith(prefix):
            return feature
    return None


def resolve_current_feature(
    repo_root: Path, current_branch: str, features: list[str]
) -> tuple[str | None, str | None]:
    """Mirror spec-kit's own precedence from scripts/bash/common.sh.

    SPECIFY_FEATURE_DIRECTORY, then .specify/feature.json, then SPECIFY_FEATURE,
    then the git branch as a legacy fallback. The branch is no longer
    authoritative in spec-kit 1.0.x.
    """
    env_dir = os.environ.get("SPECIFY_FEATURE_DIRECTORY")
    if env_dir:
        identifier, source = Path(env_dir.rstrip("/\\")).name, "env"
    else:
        feature_json_dir = read_feature_json(repo_root)
        if feature_json_dir:
            identifier = Path(feature_json_dir.rstrip("/\\")).name
            source = "feature.json"
        elif os.environ.get("SPECIFY_FEATURE"):
            identifier, source = os.environ["SPECIFY_FEATURE"], "env"
        elif current_branch:
            identifier, source = current_branch, "branch"
        else:
            return None, None

    resolved = match_feature(identifier, features)
    return (resolved, source) if resolved else (None, None)


def resolve_target(target: str, specs_dir: Path, features: list[str]) -> str:
    """Resolve a user-supplied feature identifier, or exit 1 if unknown."""
    if (specs_dir / target).is_dir():
        return target
    if Path(target).is_dir():
        return Path(target).name
    if target.isdigit():
        prefix = f"{int(target):03d}-"
        for feature in features:
            if feature.startswith(prefix):
                return feature
    else:
        for feature in features:
            if target in feature:
                return feature
    print(f"Error: Feature not found: {target}", file=sys.stderr)
    raise SystemExit(1)


def implement_cell(feature: dict) -> str:
    if not feature["has_tasks"]:
        return "-"
    total = feature["tasks_total"]
    if total == 0:
        return "○ Ready"
    completed = feature["tasks_completed"]
    if completed == total:
        return "✓ Complete"
    return f"● {completed}/{total} ({completed * 100 // total}%)"


def write_status_file(
    path: Path, project_name: str, repo_root: Path, has_git: bool, features: list[dict]
) -> None:
    commit = git("rev-parse", "HEAD", cwd=repo_root) if has_git else None
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    col = max([len("Feature"), *(len(f["name"]) for f in features)])
    lines = [
        "# Spec-Driven Development Status",
        f"<!-- spec-status: project={project_name} commit={commit or ''} updated={timestamp} -->",
        "",
        f"| {'Feature'.ljust(col)} | Specify | Plan | Tasks | Implement |",
        f"|{'-' * (col + 2)}|---------|------|-------|-----------|",
    ]

    for feature in features:
        cells = [
            "✓" if feature[key] else "-"
            for key in ("has_spec", "has_plan", "has_tasks")
        ]
        lines.append(
            f"| {feature['name'].ljust(col)} | {cells[0].ljust(7)} | "
            f"{cells[1].ljust(4)} | {cells[2].ljust(5)} | "
            f"{implement_cell(feature).ljust(9)} |"
        )

    if not features:
        lines.append(f"| {'(none)'.ljust(col)} |         |      |       |           |")

    lines.append("")

    # Machine-readable per-feature metadata as HTML comments
    for feature in features:
        fields = " ".join(
            f"{key}={str(feature[key]).lower()}" for key in ARTIFACTS
        )
        lines.append(
            f"<!-- feature: {feature['name']} {fields} "
            f"tasks_total={feature['tasks_total']} "
            f"tasks_completed={feature['tasks_completed']} "
            f"checklist_files={','.join(feature['checklist_files'])} -->"
        )

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="get_project_status.py",
        description=(
            "Discover project structure and artifact existence for "
            "/speckit.status-report.show."
        ),
    )
    parser.add_argument("--json", action="store_true", help="Output in JSON format")
    parser.add_argument("--feature", help="Focus on specific feature")
    parser.add_argument("positional", nargs="?", help=argparse.SUPPRESS)
    # Unrecognized flags are ignored rather than fatal. The command exposes
    # --all and --verbose to users, but those are the agent's to interpret, not
    # this script's; forwarding them must not turn a status query into an error.
    args, _ignored = parser.parse_known_args()
    positional = args.positional or ""
    if positional.startswith("-"):
        positional = ""
    target_feature = args.feature or positional

    # ── Resolve repository root ───────────────────────────────────────────────
    script_dir = Path(__file__).resolve().parent
    git_root = git("rev-parse", "--show-toplevel")
    if git_root:
        repo_root, has_git = Path(git_root), True
        # symbolic-ref works in a repo with no commits, where rev-parse prints
        # "HEAD" and exits non-zero. Keep rev-parse for detached HEAD.
        current_branch = (
            git("symbolic-ref", "--short", "HEAD")
            or git("rev-parse", "--abbrev-ref", "HEAD")
            or "unknown"
        )
    else:
        found = find_repo_root(script_dir)
        if found is None:
            print("Error: Could not determine repository root.", file=sys.stderr)
            return 1
        repo_root, has_git, current_branch = found, False, ""

    specs_dir = repo_root / "specs"
    if not specs_dir.is_dir() and (repo_root / ".specify" / "specs").is_dir():
        specs_dir = repo_root / ".specify" / "specs"

    memory_dir = repo_root / ".specify" / "memory"
    if not memory_dir.is_dir() and (repo_root / "memory").is_dir():
        memory_dir = repo_root / "memory"

    constitution_path = memory_dir / "constitution.md"
    project_name = get_project_name(repo_root)
    is_feature_branch = bool(FEATURE_RE.match(current_branch))
    status_file = specs_dir / "spec-status.md"

    names = sorted(
        entry.name
        for entry in (specs_dir.iterdir() if specs_dir.is_dir() else [])
        if entry.is_dir() and FEATURE_RE.match(entry.name)
    )

    current_feature, feature_source = resolve_current_feature(
        repo_root, current_branch, names
    )

    # ── Per-feature data collection ───────────────────────────────────────────
    features = []
    for name in names:
        feature_dir = specs_dir / name
        checklists_dir = feature_dir / "checklists"
        checklist_files = (
            sorted(p.name for p in checklists_dir.glob("*.md") if p.is_file())
            if check_exists(checklists_dir)
            else []
        )
        total, completed = count_tasks(feature_dir / "tasks.md")

        feature = {"name": name, "path": str(feature_dir), "is_current": name == current_feature}
        feature.update(
            {key: check_exists(feature_dir / rel) for key, rel in ARTIFACTS.items()}
        )
        feature["tasks_total"] = total
        feature["tasks_completed"] = completed
        feature["checklist_files"] = checklist_files
        features.append(feature)

    if specs_dir.is_dir() or features:
        write_status_file(status_file, project_name, repo_root, has_git, features)

    resolved_target = resolve_target(target_feature, specs_dir, names) if target_feature else ""

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        print(
            json.dumps(
                {
                    "project": project_name,
                    "repo_root": str(repo_root),
                    "specs_dir": str(specs_dir),
                    "cache_file": str(status_file),
                    "has_git": has_git,
                    "branch": current_branch,
                    "is_feature_branch": is_feature_branch,
                    "constitution": {
                        "exists": constitution_path.is_file(),
                        "path": str(constitution_path),
                    },
                    "feature_count": len(features),
                    "current_feature": current_feature,
                    "feature_source": feature_source,
                    # What the caller asked for, falling back to whatever
                    # feature the project is currently on.
                    "target_feature": resolved_target or current_feature,
                    "features": features,
                },
                separators=(",", ":"),
            )
        )
        return 0

    print("Status Report Discovery")
    print("========================")
    print()
    print(f"Project: {project_name}")
    print(f"Root: {repo_root}")
    print(f"Specs: {specs_dir}")
    print(f"Status File: {status_file}")
    print(f"Git: {str(has_git).lower()}")
    print(f"Branch: {current_branch}")
    print(f"Feature Branch: {str(is_feature_branch).lower()}")
    print(f"Current Feature: {current_feature or '(none)'}")
    print(f"Feature Source: {feature_source or '(none)'}")
    print(f"Constitution: {str(constitution_path.is_file()).lower()} ({constitution_path})")
    print()

    if resolved_target:
        print(f"Target Feature: {resolved_target}")
        print()

    print(f"Features ({len(features)}):")
    print()

    if not features:
        print("  (none)")
        return 0

    for feature in features:
        print(f"  Name: {feature['name']}")
        print(f"  Path: {feature['path']}")
        print(f"  Current: {str(feature['is_current']).lower()}")
        print("  Artifacts:")
        for key, rel in ARTIFACTS.items():
            label = rel + "/" if key in ("has_contracts", "has_checklists") else rel
            print(f"    {label}: {str(feature[key]).lower()}")
        print(f"  Tasks: {feature['tasks_completed']}/{feature['tasks_total']}")
        if feature["checklist_files"]:
            print(f"    checklist_files: {', '.join(feature['checklist_files'])}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
