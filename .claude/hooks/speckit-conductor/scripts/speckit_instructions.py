#!/usr/bin/env python3
"""Per-command instructions the SpecKit dispatcher injects.

Data, not logic: the dispatcher resolves a command name and looks it up here. Adding
a command is an edit to this table.

WHY A TABLE RATHER THAN STEERING ALONE. Steering is always-loaded context an agent may
or may not act on; the first end-to-end run of this package read the steering and
still hand-rolled a spec outside the molecule. An instruction attached to the moment a
command fires arrives when the decision is still cheap.

WHAT EARNS AN ENTRY. Only a command where the advice is specific and load-bearing:
where work starts and a pour decision applies, where the command writes an artifact a
guard denies, or where findings have somewhere particular to go. 62 SpecKit skills
install with spec-kit; a generic "you are in a molecule" note on all of them trains an
agent to ignore the channel.

DENY IS THE EXCEPTION. One command is refused outright rather than advised, because
its whole output is a second task tracker.
"""

from __future__ import annotations

# Where the profiles live, named once. The instruction points at the directory rather
# than listing profiles, so adding a formula does not touch this file.
_PROFILES = (
    "Profiles live in the package's formulas/ directory; read them with "
    "`bd cook <name>` and choose by two facts: is a human present to resolve the "
    "three approval gates (`--var autonomous=yes` if not), and is the agent-assign "
    "extension installed (`--var agent_assign=no` if not)."
)

# The replacement for a tasks.md write, spelled out once.
_TASKS_REDIRECT = (
    "Task state lives in beads and specs/*/tasks.md is read-only legacy here, so a "
    "write to it is denied. Create the work under the molecule's implement step "
    "instead, GROUPED under features: one `bd create \"<group>\" -t feature "
    "--parent <implement-step-id> --spec-id <NNN-slug>` per coherent unit of work "
    "(what ships and reviews together, grouped by file ownership), then "
    "`bd create \"<title>\" --parent <feature-id> --spec-id <NNN-slug> -t task`, "
    "ordering with `bd dep add <later> <earlier>`. "
    "Find the implement step with `bd mol current <molecule-root-id>`."
)

# command -> instruction text. Keys match the resolved command with the `speckit.`
# prefix stripped and dots preserved, e.g. `review.run`.
INSTRUCTIONS: dict[str, str] = {
    # --- entry points: a pour decision applies ------------------------------
    "specify": (
        _PROFILES
        + "\n\nIf a molecule already exists for this feature, work it instead: "
        "`bd ready --unassigned --json`."
    ),
    "constitution": (
        "The constitution is project-scoped and outlives every feature, so it needs "
        "no molecule. Do not pour one for it.\n\n"
        "It is authority rather than advice: later phases judge work against it, and "
        "`converge` treats a violation of a MUST principle as its highest-severity "
        "finding. So record the choices it encodes where they survive -- a "
        "`decision` bead per hard-to-reverse choice (`bd create \"<choice>\" "
        "--type decision`), which the adr-as-beads package renders into docs/adr/ "
        "once closed."
    ),
    "roadmap.write": (
        "`roadmap.write` is project-scoped like the constitution, so it needs no "
        "molecule. The per-feature halves are `/speckit.roadmap.brief` before "
        "implement and `/speckit.roadmap.debrief` after, which do belong to one.\n\n"
        "The roadmap is forward-looking and re-sequenced as plans change, so it is "
        "not the record of a decision. When the roadmap moves because a choice was "
        "made, record the choice separately: `bd create \"<choice>\" "
        "--type decision`."
    ),
    "tinyspec": (
        "tinyspec is the route for a change that needs no lifecycle, so it is "
        "deliberately outside the DAG. Do not pour a molecule for it. If the change "
        "turns out to need phases, stop and pour a feature molecule instead of "
        "growing tinyspec into one: `bd mol pour <profile> --var feature=<NNN-slug>`."
    ),
    "bugfix.report": (
        "bugfix is a route, not a phase. Two shapes, and they differ in what exists "
        "already:\n"
        "- a defect found DURING an active spec: bond a bugfix molecule onto the "
        "running molecule's implement step with `bd mol bond`; specs/<feature>/bugs/ "
        "is already there.\n"
        "- a defect in shipped code with NO active spec: the report needs a feature "
        "directory to live in, so create the spec dir first, then run the loop.\n\n"
        "Either way the patch step writes tasks.md, which is denied. " + _TASKS_REDIRECT
    ),
    "brownfield.bootstrap": (
        "An existing codebase usually carries a legacy specs/*/tasks.md. Reading it "
        "is fine and expected for migration; writing it is denied. Import its "
        "contents once as beads -- `bd create -f <tmpfile>.md` with the temp file "
        "OUTSIDE specs/ -- then treat tasks.md as read-only history."
    ),
    # --- commands whose write is denied -------------------------------------
    "cleanup": (
        "TWO THINGS, and the second is the one that gets skipped.\n\n"
        "1. This command creates tasks for medium issues and analysis for large "
        "ones. " + _TASKS_REDIRECT + "\n\n"
        "2. cleanup is the closeout sweep, and it must not close a molecule that "
        "still has outstanding work. Route by the severity this command already "
        "grades:\n"
        "- small, scout-rule fixable: fix in place and close the step.\n"
        "- medium, approach still holds: reopen the implement subtree. Create "
        "children under the implement step and route them through "
        "`/speckit.agent-assign.assign` then `.execute`.\n"
        "- large, the approach itself is wrong: bond an iterate molecule "
        "(`/speckit.iterate.define` then `.apply`) onto the current step.\n\n"
        "A DAG cannot express going back, so a loop-back is bonded work rather than "
        "an edge: bond it, and hold cleanup open until it closes. Letting sync, "
        "retro, and final-checkpoint proceed with medium-or-worse findings "
        "outstanding produces a molecule that reports done while carrying known "
        "defects.\n\n"
        "Not this command's job: spec satisfied but code incomplete. That is a "
        "`verify` verdict of PARTIAL or NOT_FOUND, and it routes to `converge`.\n\n"
        "Also sweep the molecule itself: list open steps under the root, close what "
        "is genuinely done with a reason, and resolve or explicitly abandon dangling "
        "gates. An abandoned molecule leaves its unreached steps and gates open "
        "forever, and nothing else collects them."
    ),
    "cleanup.run": (
        "Same rules as `/speckit.cleanup`: the tasks.md write is denied, so create "
        "findings as children of the implement step with `bd create --parent "
        "<implement-step-id>`; and a medium-or-worse finding routes back to "
        "`/speckit.agent-assign.assign` or a bonded `/speckit.iterate.define` rather "
        "than closing the molecule."
    ),
    "converge": (
        "converge appends a Convergence phase to tasks.md, and that is its ONLY "
        "write, so it cannot function here unadapted. " + _TASKS_REDIRECT + "\n\n"
        "It also reads tasks.md to compute the next task id and phase number; with "
        "no such file, number the new beads after the highest existing "
        "implement-step child.\n\n"
        "Its four gap types route differently: `missing` and `partial` become new "
        "task beads, `contradicts` is the highest severity when it violates a "
        "constitution MUST, and `unrequested` is surfaced for review rather than "
        "deleted."
    ),
    "iterate.apply": (
        "iterate.apply rewrites spec, plan, and tasks. The first two are ordinary "
        "edits; the tasks half is denied. " + _TASKS_REDIRECT
    ),
    "reconcile.run": (
        "reconcile appends remediation tasks to tasks.md, which is denied. "
        + _TASKS_REDIRECT
        + "\n\nIt also surgically edits spec.md and plan.md to match the code, which "
        "is sometimes exactly backwards. Confirm which side is authoritative before "
        "letting it rewrite the spec."
    ),
    "refine.propagate": (
        "refine.propagate pushes spec changes into tasks.md, which is denied. "
        + _TASKS_REDIRECT
    ),
    # --- findings have somewhere to go --------------------------------------
    "analyze": (
        "Task state comes from `bd list --spec <NNN-slug>`, not tasks.md.\n\n"
        "RUN THIS INLINE. Do not hand it to a subagent: a delegated child does not "
        "inherit this project's working directory, and three autonomous runs each "
        "had one analyze the WRONG REPOSITORY and report confident findings about "
        "files the feature never touched -- one called the feature under test \"a "
        "phantom\". A wrong answer here is worse than no answer, because it reads "
        "as authoritative. The formula marks this step interactive for that "
        "reason. It also returned long after the step had closed, so its output "
        "arrived too late to act on.\n\n"
        "Carry an unresolved finding on an escalation wisp, and encode the "
        "resolution into spec.md or plan.md before burning it. A finding that lives "
        "only in this command's output is lost when the turn ends."
    ),
    "review.run": (
        "Actionable defects route by kind rather than all to one place:\n"
        "- a defect in code that exists: bond a fix-findings molecule with "
        "`bd mol bond mol-speckit-fix-findings <this-step-id>`.\n"
        "- a requirement never built (a `verify` verdict of NOT_FOUND or PARTIAL): "
        "route to `converge`, because fix-findings is spec-safe and only repairs "
        "code that is already there."
    ),
    "qa.run": (
        "A QA failure is a code defect, so it routes to a bonded fix-findings "
        "molecule rather than into tasks.md: `bd mol bond "
        "mol-speckit-fix-findings <this-step-id>`. Record the failing case on the "
        "step's bead with `bd note <id>` so the fix has something to verify against."
    ),
    "retro.run": (
        "The learnings are in the beads, not only in the files. A retro that reads "
        "spec.md and plan.md alone misses everything the workflow actually "
        "recorded.\n\n"
        "Read: `bd list --spec <NNN-slug> --status all --json` for what happened, "
        "the close reasons on each step for why, comments on escalation wisps for "
        "what was contested, and any `decision` beads created during the run.\n\n"
        "A `decision` bead is also the input to an architecture decision record. "
        "Check whether any deserves promoting: the adr-as-beads package renders a "
        "closed decision bead into docs/adr/, so the retro is the moment to close "
        "one that has been left `deferred`."
    ),
}

# Refused rather than advised. The value is the deny reason.
DENIED: dict[str, str] = {
    "taskstoissues": (
        "taskstoissues converts specs/*/tasks.md into GitHub issues, and both ends "
        "of that are wrong here: the input file is read-only legacy, and the output "
        "is a second task tracker competing with beads for the same work.\n\n"
        "Work state lives in beads. To surface a bead for a human, link the existing "
        "issue with `bd update <id> --external-ref gh-<number>` rather than "
        "generating issues from a file the workflow does not maintain."
    ),
}
