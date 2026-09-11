#!/usr/bin/env python3
"""Cross-tool hook with several roles, branched on `tool_name`.

PreToolUse (Write|Edit|MultiEdit|apply_patch): DENY writes to
specs/*/tasks.md when the repo has an active beads workspace. Also DENY writes to
specs/<feature>/spec.md when that feature has no poured molecule root tagged to its
spec directory. tasks.md is never authored under the beads workflow -- task state
lives in beads. A spec.md is written only after its molecule exists. The deny reason
carries the full replacement workflow so the agent self-corrects without a human
(hook-guard policy: deny is agent-facing, never "ask").

PreToolUse (Bash): ADVISORY ONLY -- a command string referencing a
specs/*/tasks.md path gets a non-blocking additionalContext note (task state
lives in beads). A write-shaped command targeting spec.md is denied by the same
molecule precondition; reads stay allowed. No redirect parsing beyond the existing
conservative write-shape detection.

PreToolUse (Skill): ADVISORY ONLY -- invoking speckit-implement gets a
non-blocking note that /speckit.implement is deprecated in beads repos; route
through the agent-assign chain instead.

DELIBERATE DESIGN CHOICE, do not change: a bare-string `tool_input` has no path
to judge, so it ALLOWS rather than denying -- the deny needs a specific named
path. This is documented and pinned by
packages/speckit/tests/test_speckit_tasks_guard.py ("string-form tool_input allows").

Self-gating (never rely on the matcher): exits 0 silently when the payload is
empty, `bd` is missing, the target path is not a guarded SpecKit artifact, or
the repo has no active beads workspace (`bd where` fails).
"""
from __future__ import annotations

import sys

SPEC_DENY_REASON = (
    "blocked by speckit: specs/{feature}/spec.md is write-protected until its "
    "feature molecule exists in the active beads workspace. Pour one first with "
    "`bd mol pour <profile> --var feature={feature}`; choose one of the supported "
    "profiles: `speckit-basic`, `speckit-lean`, or `speckit-feature`. Then tag the "
    "root with `bd update <root-id> --spec-id {feature} --metadata "
    "'{{\"spec_dir\":\"specs/{feature}\"}}'`. Reads remain allowed."
)

# Only `sys` at module scope. This hook is bound to Write/Edit/MultiEdit/Bash/
# Skill/apply_patch and runs on most tool calls in a SpecKit beads repo, so the
# cheap substring bail in main() must precede any import.
DENY_REASON = (
    "blocked by speckit (task state lives in beads, tasks.md is never "
    "authored): this repo has an active beads workspace, so specs/*/tasks.md is "
    "read-only legacy and must not be written or created. Create implementation "
    "tasks as beads under the feature molecule's implement step instead: bd "
    'create "<group>" -t feature --parent <implement-step-id> --spec-id <NNN-slug>` '
    'per coherent unit of work, then `bd '
    'create "T00N <title>" --parent <feature-id> --spec-id <NNN-slug> -t '
    "task; wire ordering with bd dep add <later-id> <earlier-id>; bulk-create "
    "with bd create -f <tmpfile>.md (write the temp file OUTSIDE specs/). Then "
    "work the tasks via bd ready -> bd update <id> --claim -> bd close <id> "
    '--reason "...". Find the implement step with bd mol current '
    "<molecule-root-id>. "
    "IF A SKILL DEMANDED tasks.md: 13 of the installed skills call "
    "check-prerequisites.sh --require-tasks, which prints \"ERROR: tasks.md not "
    "found -- Run /speckit-tasks first\" and exits 1. That precondition cannot "
    "be satisfied here and is not meant to be: skip the script and read task "
    "state from beads instead, with bd list --spec <NNN-slug>. Do not create "
    "tasks.md to get past the check -- that is the one move this guard exists to "
    "stop."
)

BASH_ADVICE = (
    "SPECKIT: tasks.md is not authored in beads repos; task state lives "
    "in beads: bd ready / bd update <id> --claim / bd close <id> --reason. If "
    "reading legacy tasks.md for migration, that's fine. If a skill's "
    "check-prerequisites.sh --require-tasks just failed: that check cannot pass "
    "here -- skip it and read bd list --spec <NNN-slug> instead."
)

IMPLEMENT_ADVICE = (
    "SPECKIT: /speckit.implement is deprecated in beads repos; route "
    "through the agent-assign chain instead (/speckit.agent-assign.assign -> "
    "validate -> execute), working the molecule steps via bd mol current / bd "
    "ready / bd update --claim / bd close."
)

def is_spec_md(path: str) -> bool:
    """Whether `path` is a SpecKit feature spec: specs/<feature>/spec.md."""
    import fnmatch

    normalized = path.replace("\\", "/")
    return fnmatch.fnmatchcase(normalized, "specs/*/spec.md") or fnmatch.fnmatchcase(
        normalized, "*/specs/*/spec.md"
    )


def spec_feature(path: str) -> str:
    """Extract the feature slug from a specs/<feature>/spec.md path."""
    import re

    normalized = path.replace("\\", "/")
    match = re.search(r"(?:^|/)specs/([^/]+)/spec\.md$", normalized)
    return match.group(1) if match else ""

def poured_molecule_for_spec(cwd: str, feature: str) -> bool:
    """Whether the active workspace has a molecule root tagged to this spec dir."""
    import json
    import subprocess

    if not feature:
        return False
    try:
        result = subprocess.run(
            [
                "bd",
                "-C",
                cwd,
                "list",
                "--all",
                "--flat",
                "--type",
                "molecule",
                "--metadata-field",
                f"spec_dir=specs/{feature}",
                "--json",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        )
        if result.returncode != 0:
            return False
        records = json.loads(result.stdout)
        if not isinstance(records, list):
            return False
        return any(
            isinstance(record, dict)
            and record.get("issue_type") == "molecule"
            and isinstance(record.get("metadata"), dict)
            and record["metadata"].get("spec_dir") == f"specs/{feature}"
            for record in records
        )
    except (OSError, subprocess.SubprocessError, TypeError, ValueError):
        return False


def writes_tasks_md(command: str) -> bool:
    """Whether a shell command writes to a specs/*/tasks.md path.

    Conservative by construction: it answers yes only on a recognised write
    shape, so an unrecognised command falls through to the advisory rather than
    to a wrong deny. Reads stay allowed because a brownfield migration has to
    read the legacy file.

    Recognised writes, each verified against the shapes the first user of this
    package used to bypass the Write/Edit deny:

      >  >>          redirect, including `1>` and `&>`
      tee            with or without -a
      cp mv          when the path is the destination
      sed -i         in-place edit
      truncate       explicit size change
      python -c      any interpreter opening the path for writing

    `dd of=` and `install` are included because they are ordinary file writers,
    not because anyone reached for them.
    """
    import re

    # A redirect anywhere before the path. `[0-9]*&?>` covers `>`, `>>`, `1>`,
    # `2>>`, `&>`; the path may be quoted, so quotes are permitted between.
    if re.search(r"[0-9]*&?>>?\s*['\"]?[^|;&]*specs/[^|;&]*/tasks\.md", command, re.DOTALL):
        return True

    # A writing utility naming the path as an argument. The path may appear
    # anywhere after the utility, since flags vary.
    writers = (
        r"\btee\b", r"\bsed\b\s+[^|;&]*-i", r"\btruncate\b", r"\bdd\b[^|;&]*\bof=",
        r"\binstall\b", r"\bcp\b", r"\bmv\b", r"\bpython3?\b[^|;&]*-c",
        r"\bperl\b[^|;&]*-[a-z]*e", r"\bawk\b[^|;&]*>", r"\btouch\b",
    )
    for w in writers:
        if re.search(w + r"[^|;&]*specs/[^|;&]*/tasks\.md", command, re.DOTALL):
            return True
    return False


def writes_spec_md(command: str) -> bool:
    """Whether a shell command writes to a specs/*/spec.md path."""
    import re

    if re.search(r"[0-9]*&?>>?\s*['\"]?[^|;&]*specs/[^|;&]*/spec\.md", command, re.DOTALL):
        return True
    writers = (
        r"\btee\b", r"\bsed\b\s+[^|;&]*-i", r"\btruncate\b", r"\bdd\b[^|;&]*\bof=",
        r"\binstall\b", r"\bcp\b", r"\bmv\b", r"\bpython3?\b[^|;&]*-c",
        r"\bperl\b[^|;&]*-[a-z]*e", r"\bawk\b[^|;&]*>", r"\btouch\b",
    )
    return any(re.search(w + r"[^|;&]*specs/[^|;&]*/spec\.md", command, re.DOTALL) for w in writers)


def spec_feature_from_command(command: str) -> str:
    """Extract a feature slug from a shell command's specs/*/spec.md path."""
    import re

    match = re.search(
        r"(?<![A-Za-z0-9_.-])specs/([^/\s'\";&|]+)/spec\.md(?:$|[\s'\";&|])",
        command,
    )
    return match.group(1) if match else ""


def is_tasks_md(path: str) -> bool:
    """Whether `path` is a SpecKit tasks file: specs/<feature>/tasks.md at any
    depth, relative or absolute."""
    import fnmatch

    return fnmatch.fnmatchcase(path, "specs/*/tasks.md") or fnmatch.fnmatchcase(
        path, "*/specs/*/tasks.md"
    )


def beads_active(cwd: str) -> bool:
    """Whether bd resolves an active workspace for this directory."""
    import shutil
    import subprocess

    if shutil.which("bd") is None:
        return False
    try:
        return (
            subprocess.run(
                ["bd", "-C", cwd, "where"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=10,
            ).returncode
            == 0
        )
    except (subprocess.SubprocessError, OSError):
        return False


def extract(payload: str) -> dict:
    """Parse the payload; tool_input may be an object or a bare string.

    A bare-string tool_input is the historical bypass shape: `.tool_input.command
    // .tool_input` throws on a string in jq. Here it simply yields no file_path,
    skill, or command -- which, per the documented design choice, means allow.
    """
    import json

    data = json.loads(payload)
    if not isinstance(data, dict):
        return {}
    tool_input = data.get("tool_input")
    file_path = ""
    skill_name = ""
    command = ""
    if isinstance(tool_input, dict):
        raw_path = tool_input.get("file_path") or tool_input.get("path")
        file_path = raw_path if isinstance(raw_path, str) else ""
        raw_skill = tool_input.get("skill")
        skill_name = raw_skill if isinstance(raw_skill, str) else ""
        raw_cmd = tool_input.get("command")
        command = raw_cmd if isinstance(raw_cmd, str) else ""

    event = data.get("hook_event_name")
    tool_name = data.get("tool_name") or data.get("tool")
    cwd = data.get("cwd")
    return {
        "event": event if isinstance(event, str) else "",
        "tool_name": tool_name if isinstance(tool_name, str) else "",
        "file_path": file_path,
        "skill_name": skill_name,
        "cwd": cwd if isinstance(cwd, str) else "",
        "command": command,
    }


def patch_paths(patch: str) -> list[str]:
    """Every file header in a Codex apply_patch body: `*** Update/Add/Delete
    File: <path>`."""
    import re

    return re.findall(r"^\*\*\* (?:Update|Add|Delete) File: (.*)$", patch, re.MULTILINE)


def deny(reason: str = DENY_REASON) -> None:
    import json

    json.dump(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sys.stdout,
    )


def deny_spec(feature: str) -> None:
    deny(SPEC_DENY_REASON.format(feature=feature))


def advise(event: str, context: str) -> None:
    import json

    json.dump(
        {"hookSpecificOutput": {"hookEventName": event, "additionalContext": context}},
        sys.stdout,
    )


def main() -> int:
    payload = sys.stdin.read()
    if not payload:
        return 0
    # Cheap pre-parse bail: every branch below acts on a guarded artifact or a
    # speckit-implement skill invocation; anything else needs no inspection.
    if (
        "tasks.md" not in payload
        and "spec.md" not in payload
        and "speckit.implement" not in payload
        and "speckit-implement" not in payload
    ):
        return 0

    import shutil

    if shutil.which("bd") is None:
        return 0

    try:
        data = extract(payload)
    except (ValueError, TypeError):
        return 0

    tool_name = data["tool_name"]
    if not tool_name:
        # Bare-string tool_input (legacy shape), or no tool_name at all: allow.
        return 0

    if data["event"] != "PreToolUse":
        return 0

    import os

    cwd = data["cwd"]
    if not cwd or not os.path.isdir(cwd):
        cwd = os.getcwd()

    if tool_name in ("Write", "Edit", "MultiEdit"):
        path = data["file_path"]
        if is_tasks_md(path):
            if not beads_active(cwd):
                return 0
            deny()
            return 0
        if is_spec_md(path):
            feature = spec_feature(path)
            if not beads_active(cwd) or poured_molecule_for_spec(cwd, feature):
                return 0
            deny_spec(feature)
        return 0

    if tool_name in ("apply_patch", "functions.apply_patch"):
        for path in patch_paths(data["command"]):
            if is_tasks_md(path):
                if not beads_active(cwd):
                    return 0
                deny()
                return 0
            if is_spec_md(path):
                feature = spec_feature(path)
                if not beads_active(cwd) or poured_molecule_for_spec(cwd, feature):
                    continue
                deny_spec(feature)
                return 0
        return 0

    if tool_name == "Bash":
        # A Bash command touching specs/*/tasks.md is legitimate when it READS
        # (migration reads, greps, cat) and is the documented bypass when it
        # WRITES. Spec writes use the same conservative writer detection but
        # require a molecule root tagged to the feature first.
        import re

        command = data["command"]
        if re.search(r"specs/.*/tasks\.md", command, re.DOTALL):
            if not beads_active(cwd):
                return 0
            if writes_tasks_md(command):
                deny()
                return 0
            advise("PreToolUse", BASH_ADVICE)
            return 0
        feature = spec_feature_from_command(command) if writes_spec_md(command) else ""
        if feature:
            if not beads_active(cwd) or poured_molecule_for_spec(cwd, feature):
                return 0
            deny_spec(feature)
        return 0

    if tool_name == "Skill":
        haystack = f"{data['skill_name']} {data['command']}"
        if "speckit-implement" in haystack or "speckit.implement" in haystack:
            if not beads_active(cwd):
                return 0
            advise("PreToolUse", IMPLEMENT_ADVICE)
        return 0

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException:
        # Fail open: an unreadable payload or an unexpected exception allows
        # rather than blocking.
        raise SystemExit(0)
