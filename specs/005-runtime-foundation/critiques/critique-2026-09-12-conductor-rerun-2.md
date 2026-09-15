# Critique Rerun 2: Runtime Foundation

**Date**: 2026-09-12  
**Feature**: [spec.md](../spec.md)  
**Plan**: [plan.md](../plan.md)  
**Verdict**: PROCEED

## Scope and evidence

This independent rerun checks only the affected requirements and cross-artifact coverage in
`spec.md`, `plan.md`, `contracts/configuration.md`, `data-model.md`, `quickstart.md`,
`checklists/foundation.md`, and the named Beads tasks T004, T015, T016, T018, T020, T021,
T024, TASK-SEC-007, T043, and T044. It does not claim implementation completion.

The parent-supplied prose gate passed after remediation with score 80.8/100, 0 errors, 159
warnings, 73 suggestions, and 4.553 warnings per 100 words. This rerun did not treat that
aggregate as evidence for the requirements; the cited artifact text and Beads contracts are
the evidence below.

## Reported contradiction revalidation

| Contradiction | Evidence | Result |
|---|---|---|
| Four-field failure projection versus extra source detail | `spec.md:157-161` requires only code, static summary, redacted source, and static next action. `spec.md:180-186` limits failure source to a redacted file origin or fixed layer class. `contracts/configuration.md:125-137` and `data-model.md:138-150` repeat the closed four-field shape and exclude raw paths, values, parser excerpts, OS errors, dynamic strings, and rejected secrets. | **Closed.** Unknown-key failures expose `config.key_unknown` plus only the permitted redacted origin or fixed layer class; they do not identify or echo the unknown key and do not add a fifth field. |
| Preflight versus typed deserialization and merge ordering | `spec.md:172-177` requires a bounded TOML-aware preflight before typed deserialization. `contracts/configuration.md:90-106` states that preflight-rejected documents cannot deserialize, permits `config.syntax_invalid` from typed TOML parsing after a passing preflight, and says no failure reaches merge. `data-model.md:124-136,167-175` and `plan.md:160-173` preserve the same sequence. | **Closed.** Only lexical-preflight rejections must remain before typed deserialization. A typed TOML syntax failure is an allowed later rejection; neither kind reaches merge. |
| Spec 016 ownership versus the foundation slice | `spec.md:242-243` assigns published packaging and end-to-end installation to spec 016. `plan.md:132-136` assigns packaging, installation, release, and upgrade behavior to spec 016 and says it adds no product crate. `quickstart.md:51-68` limits this slice to architecture/compatibility acceptance and absence of later-spec commands. | **Closed.** The reviewed foundation requirements retain the CLI baseline and private runtime seam without claiming spec 016 product behavior. |

No new contradiction was found in the reviewed scope.

## Cross-artifact and Beads coverage

- **T004 — `matinee-mol-hyr.3.2`**: defines exactly four safe diagnostic fields, discards raw
  OS/parser errors, and forbids unknown-key text in the type and acceptance contract.
- **T015 — `matinee-mol-hyr.3.6`**: distinguishes `config.key_unknown` from descriptor-class
  rejection, requires redacted source only, rejects non-`non_secret` classes, and returns no
  partial state.
- **T016 — `matinee-mol-hyr.3.7`**: its corrected description now references both TASK-SEC-003 and
  TASK-SEC-006. It covers exact and one-over byte, assignment, depth, and scalar limits plus
  pathological 1 MiB inputs; the acceptance remains scoped to preflight-rejected documents,
  which do not deserialize, merge, or create product state.
- **T018 — `matinee-mol-hyr.3.9`**: covers user/project provenance redaction and negative
  cases for unknown-key text, raw paths, OS errors, values, parser excerpts, and secrets.
- **T020 — `matinee-mol-hyr.3.11`**: requires bounded TOML lexical state for strings, escapes,
  comments, arrays, inline tables, and headers before typed deserialization; exact-limit
  inputs pass and one-over/pathological inputs do not reach deserialization or merge.
- **T021 — `matinee-mol-hyr.3.12`**: validates unknown, protected-source, material-class, and
  typed-value failures after preflight and before merge, with distinct stable failures and no
  partial result.
- **T024 — `matinee-mol-hyr.3.15`**: requires static summaries/actions and redacted sources
  through the closed four-field projection, discarding raw errors, paths, values, excerpts,
  and secret material.
- **TASK-SEC-007 — `matinee-mol-hyr.3.30`**: requires exhaustive negative rendering cases
  for unreadable, changed, escaped, oversized, malformed, duplicate, unknown,
  source-forbidden, secret-forbidden, limit, and invalid-value failures. Its acceptance
  requires exactly the four fields, unknown-key non-disclosure, and no product-state
  mutation.
- **T043 — `matinee-mol-hyr.2.6`**: maps every FR-005-001 through FR-005-020, SC-005-001
  through SC-005-007, and TASK-SEC-001 through TASK-SEC-008 to exact recorded commands or
  scenarios and observed outcomes, including preflight ordering and unknown-key redaction.
- **T044 — `matinee-mol-hyr.2.7`**: confirms all eight security controls and requires
  `validation.md` evidence for their exact cases, including four-field failures and
  unknown-key non-disclosure.

The relevant dependency edges also preserve the intended order: T020 follows T019, T021
follows T020, TASK-SEC-007 follows TASK-SEC-006, T043 depends on the quickstart and security
proof tasks, and T044 depends on T043 and the security cases. All implementation and
acceptance tasks remain open, so these are requirements and task-contract checks only.

## Checklist outcome

The independent-reviewer markers now pass for all four assigned criteria in
`checklists/foundation.md`:

- **CHK008 — `[x]` at line 23**: the contract table maps unknown, duplicate, syntax,
  excessive, source-forbidden, and secret-class failures to stable codes, while the complete-
  result/no-partial-state rules establish fail-all behavior (`spec.md:147-190`,
  `contracts/configuration.md:78-121`, `data-model.md:178-186`; T015/T016/T020/T021/T024/
  TASK-SEC-007).
- **CHK011 — `[x]` at line 26**: the four public fields are closed and all raw disclosure
  channels are excluded (`spec.md:157-161,180-186`, `contracts/configuration.md:125-137`,
  `data-model.md:138-150`; T004/T018/T024/TASK-SEC-007).
- **CHK022 — `[x]` at line 43**: every structured-failure path has the redacted-source,
  non-disclosure, and no-mutation requirements (`spec.md:147-169,180-190`,
  `contracts/configuration.md:69-79,125-137`, `data-model.md:178-186`; T004/T015/T016/T018/
  T020/T021/T024/TASK-SEC-007).
- **CHK023 — `[x]` at line 44**: all twenty functional requirements have user-story
  acceptance scenarios or measurable success criteria, with T043 owning the exact
  command/scenario traceability record (`spec.md:36-104,130-192,214-233`; T043).

The foundation checklist result is **25/25 criteria passed**. The markers indicate
requirements quality, not implementation completion.

## Findings and verdict

No new actionable requirements or task-contract finding was identified. The prior non-blocking
workflow-status recommendation remains: `spec.md:7` still says `Ready for planning` while a
plan and implementation graph exist. After the human gates permit the next workflow state,
the project may update that label; this does not contradict the reviewed requirements and is
outside this assignment's allowed edits.

The human gates `matinee-mol-tra` and `matinee-mol-bv9` remain external blockers. This report
does not resolve or bypass them.

**FINAL VERDICT: PROCEED** for requirements-quality review. Implementation remains subject to
those human gates and to observed proof recorded by T043/T044.
