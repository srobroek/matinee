#!/usr/bin/env python3
"""Inject per-command guidance when a SpecKit command fires.

One script for three events, because the same command arrives differently depending on
how it was invoked and which runtime is running:

  UserPromptExpansion   a typed `/speckit.x`, caught BEFORE it expands   Claude only
  UserPromptSubmit      the raw prompt, for anything reaching it another way
  PreToolUse:Skill      a programmatic skill invocation

Claude gets all three. Codex has no UserPromptExpansion (its documented workaround is
parsing the command text in UserPromptSubmit), so it gets the other two.

ADVISORY, WITH ONE EXCEPTION. Every entry emits `additionalContext` and lets the
command run. The exception is `taskstoissues`, which is denied: its whole output is a
second task tracker, so there is no version of running it that is correct here.

WHY A HOOK AT ALL, GIVEN THE STEERING SAYS MOST OF THIS. The first end-to-end run of
this package read the steering and still hand-rolled a spec outside the molecule, then
hit the tasks.md deny after doing the analysis. Always-loaded context competes with
everything else in the window; an instruction attached to the firing command arrives
while the decision is still cheap.

Fails open on everything unverifiable: an unparsable payload, an unknown command, a
missing instruction table. A guard that cannot identify the command has nothing to say.
"""

from __future__ import annotations

import sys

# Only `sys` at module scope. This runs on every prompt submission in a project that
# installs it, and the hook contract puts a per-call budget ahead of tidy imports;
# everything else is imported inside the function that reaches it, after the cheap
# bail below has already returned for most payloads.

_EVENTS = ("UserPromptExpansion", "UserPromptSubmit", "PreToolUse")


def _as_str(value: object) -> str:
    """Coerce a non-string to "" so a malformed payload no-ops rather than crashing.

    Carried over from the retired speckit-dag-hooks dispatcher, which learned that
    `command_name` arrives as a dict or list often enough to matter.
    """
    return value if isinstance(value, str) else ""


def normalize(tail: str) -> str:
    """Reduce a command tail to the dotted form the instruction table is keyed by.

    BOTH SEPARATORS ARE REAL. spec-kit 0.13.4 installs its commands hyphenated --
    `/speckit-specify`, and `/speckit-git-commit` for a subcommand -- while its own
    skill bodies refer to them in prose with dots (`speckit.git.commit`). Earlier
    versions used the dotted form as the invocation. Verified against a live
    `specify init --integration claude`: the deployed skill is named
    `speckit-specify`, and no dotted command exists on disk.

    Matching only one separator makes this hook a silent no-op on the very runtime it
    ships for, so both normalize to dots. No instruction key contains a hyphen, so
    the collapse cannot mis-route: `speckit-review-code` becomes `review.code`, which
    is deliberately absent from the table and stays silent either way.
    """
    return tail.strip("./-").replace("-", ".")


def parse_slash(text: str) -> str:
    """Pull the command out of prompt text containing `/speckit-x-y` or `/speckit.x.y`."""
    import re

    m = re.search(r"/speckit[.-]([a-z][a-z0-9.-]*)", text)
    return normalize(m.group(1)) if m else ""


def resolve_command(event: str, payload: dict) -> str:
    """Extract the SpecKit command, minus its `speckit` prefix.

    Each event carries it somewhere different. These field names are verified against
    the retired dispatcher that shipped in this repository's predecessor package:
    `command_name` at the top level for an expansion, `prompt` for a submission.
    """
    if event == "UserPromptExpansion":
        raw = _as_str(payload.get("command_name"))
        # An expansion may arrive with or without the leading slash.
        if raw.startswith("/"):
            return parse_slash(raw)
        for prefix in ("speckit.", "speckit-"):
            if raw.startswith(prefix):
                return normalize(raw[len(prefix) :])
        return ""

    if event == "UserPromptSubmit":
        return parse_slash(_as_str(payload.get("prompt")))

    if event == "PreToolUse":
        tool_input = payload.get("tool_input")
        if not isinstance(tool_input, dict):
            return ""
        # A Claude Skill call names the skill; the deployed skills are `speckit-x-y`.
        skill = _as_str(tool_input.get("skill"))
        for prefix in ("speckit-", "speckit."):
            if skill.startswith(prefix):
                return normalize(skill[len(prefix) :])
        # Codex may carry no skill field at all, so fall back to the prompt.
        return parse_slash(_as_str(tool_input.get("prompt")))

    return ""


def lookup(command: str) -> tuple[str, str]:
    """Return (kind, text) for a command: ("deny"|"advise"|"", text).

    Tries the command as given, then progressively shorter dotted prefixes, so
    `review.run.something` still finds a `review.run` entry and `bugfix.report`
    resolves without needing every subcommand enumerated.
    """
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from speckit_instructions import DENIED, INSTRUCTIONS
    except Exception:  # noqa: BLE001
        # An absent or unreadable table is not a reason to interrupt the command.
        return "", ""

    parts = command.split(".")
    for stop in range(len(parts), 0, -1):
        key = ".".join(parts[:stop])
        if key in DENIED:
            return "deny", DENIED[key]
        if key in INSTRUCTIONS:
            return "advise", INSTRUCTIONS[key]
    return "", ""


def emit(event: str, kind: str, text: str) -> None:
    import json

    if kind == "deny":
        # Only PreToolUse carries a permission decision. On a prompt event the same
        # refusal has to travel as context, because there is no tool call to stop.
        if event == "PreToolUse":
            out = {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": text,
                }
            }
        else:
            out = {
                "hookSpecificOutput": {
                    "hookEventName": event,
                    "additionalContext": "DO NOT RUN THIS COMMAND. " + text,
                }
            }
    else:
        out = {
            "hookSpecificOutput": {
                "hookEventName": event,
                "additionalContext": text,
            }
        }
    print(json.dumps(out))


def main() -> int:
    import json

    payload_text = sys.stdin.read()
    if not payload_text.strip():
        return 0
    try:
        payload = json.loads(payload_text)
    except ValueError:
        return 0
    if not isinstance(payload, dict):
        return 0

    event = _as_str(payload.get("hook_event_name"))
    if event not in _EVENTS:
        return 0

    command = resolve_command(event, payload)
    if not command:
        return 0

    kind, text = lookup(command)
    if not kind:
        return 0

    emit(event, kind, text)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:
        # Fail open: a dispatcher defect must not block a command.
        sys.exit(0)
