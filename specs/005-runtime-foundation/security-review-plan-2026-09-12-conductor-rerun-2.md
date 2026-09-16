---
document_type: security-review
review_type: plan
assessment_date: 2026-09-12
codebase_analyzed: matinee/specs/005-runtime-foundation
total_files_analyzed: 16
total_findings: 0
overall_risk: NONE
critical_count: 0
high_count: 0
medium_count: 0
low_count: 0
informational_count: 0
owasp_categories: []
cwe_ids: [CWE-22, CWE-178, CWE-200, CWE-367, CWE-400]
asvs_requirements: []
mitre_techniques: []
field_summaries:
  document_type: "Always 'security-review'. Allows indexers to skip non-review documents."
  review_type: "Which command generated this document: audit, branch, staged, plan, tasks, followup, or export."
  assessment_date: "ISO 8601 date the review was performed (YYYY-MM-DD)."
  overall_risk: "Highest severity tier with active findings (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL), or NONE when no active findings exist."
  critical_count: "Number of Critical findings (CVSS 9.0-10.0)."
  high_count: "Number of High findings (CVSS 7.0-8.9)."
  medium_count: "Number of Medium findings (CVSS 4.0-6.9)."
  low_count: "Number of Low findings (CVSS 0.1-3.9)."
  informational_count: "Number of Informational findings."
  owasp_categories: "OWASP Top 10 2025 categories (A01-A10) that have at least one finding."
  cwe_ids: "CWE identifiers referenced in this document."
  asvs_requirements: "ASVS v4.0 requirements mapped to findings."
  mitre_techniques: "MITRE ATT&CK techniques applicable to findings."
  finding_id: "Unique finding identifier (SEC-NNN) for cross-referencing and task linkage."
  location: "Artifact or code path and line number supporting the finding (path/to/artifact:line)."
  owasp_category: "OWASP Top 10 2025 category for this finding (AXX:2025-Name)."
  cwe: "Common Weakness Enumeration identifier with short name (CWE-NNN: Name)."
  cvss_score: "CVSS v3.1 base score (0.0-10.0). 9.0+=Critical, 7.0-8.9=High, 4.0-6.9=Medium, 0.1-3.9=Low."
  security_task: "Security task ID for backlog tracking and remediation follow-up (TASK-SEC-NNN). Supports legacy spec_kit_task as alias."
---

# Security Plan Review: Runtime Foundation, Conductor Rerun 2

## Executive summary

This independent rerun revalidated the corrected spec 005 plan, configuration contract,
data model, supporting security history, critique rerun, and the authoritative Beads graph.
The review is limited to disclosure and parser-boundary security plus the requested task
wording and spec-016 boundary.

The corrections hold:

- An unknown-key failure has exactly four public fields: `code`, `summary`, `source`, and
  `next_action`. The code is the fixed `config.key_unknown`; the summary and next action
  are static code-selected templates; and the source is only a redacted file origin or a
  fixed layer class. The rejected key token cannot enter any field, and no fifth field is
  introduced.
- A single bounded TOML-aware lexical preflight runs over no more than the 1 MiB file
  bound before typed deserialization. Excess assignments, dotted-key depth, duplicate
  keys, and overlong text are rejected at that boundary. A document that passes preflight
  may still produce `config.syntax_invalid` during typed TOML parsing, and no failure may
  reach merge.
- `TASK-SEC-006`, `TASK-SEC-007`, T016, T020, T043, and T044 now describe compatible
  implementation and evidence obligations. T016's corrected description references both
  the historical `TASK-SEC-003` control and the new `TASK-SEC-006` proof task, while its
  acceptance remains scoped to preflight-rejected documents.
- Spec 016 is explicitly limited to packaging, installation, release, upgrade,
  compatibility, and acceptance. It adds no product crate or unfinished product surface.

No active design finding remains. The verdict is **PASS** for this security plan review.
This is not implementation sign-off: the implementation and evidence beads remain open,
and T043/T044 must record observed proof before feature acceptance.

## Scope and evidence reviewed

### Feature and governing artifacts (10)

- `specs/005-runtime-foundation/spec.md`
- `specs/005-runtime-foundation/plan.md`
- `specs/005-runtime-foundation/research.md`
- `specs/005-runtime-foundation/data-model.md`
- `specs/005-runtime-foundation/contracts/configuration.md`
- `specs/005-runtime-foundation/quickstart.md`
- `specs/005-runtime-foundation/checklists/foundation.md`
- `.specify/memory/constitution.md`
- `.specify/memory/roadmap.md`
- `specs/AGENTS.md` and repository `AGENTS.md`

### Historical review artifacts (5)

- `specs/005-runtime-foundation/security-review.md`
- `specs/005-runtime-foundation/security-review-followup.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor-rerun.md`
- `specs/005-runtime-foundation/critiques/critique-2026-09-12-conductor-rerun.md`

The Beads records were queried separately and are not counted as files above. No
`tasks.md` was read or recreated; the graph under `matinee-mol-hyr` is authoritative.
The feature graph contains 47 task descendants covering T001-T044, including the three
new security tasks. The security-review memory index and Architecture Guard integration
are unavailable in this checkout; neither was treated as evidence or silently treated as
validation.

## Authoritative Beads scope

The following records were inspected directly:

| Bead | Security-relevant wording and dependency evidence |
|---|---|
| `matinee-mol-hyr.3.29` / TASK-SEC-006 | Requires pathological, exact-limit, and one-over-limit cases for bounded lexical preflight, no typed deserialization or merge for rejected inputs, bounded counters over at most 1 MiB, stable closed failure, and no product-state mutation. It is a real task bead under the runtime feature. |
| `matinee-mol-hyr.3.30` / TASK-SEC-007 | Requires exhaustive negative rendering cases for unreadable, changed, escaped, oversized, malformed, duplicate, unknown, source-forbidden, secret-forbidden, limit, and invalid-value failures. Its acceptance requires exactly the four fields, no unknown-key text, no raw disclosure, and no mutation. It depends on TASK-SEC-006. |
| `matinee-mol-hyr.3.7` / T016 | The corrected description references both TASK-SEC-003 and TASK-SEC-006. Its acceptance requires every preflight-rejected document to fail before typed deserialization, with no merge or product-state mutation. The historical reference does not weaken the new proof task. |
| `matinee-mol-hyr.3.11` / T020 | Requires a bounded scanner for strings, escapes, comments, arrays, inline tables, and table headers; exact-limit inputs pass, and one-over/pathological documents rejected by lexical preflight never reach deserialization or merge. |
| `matinee-mol-hyr.2.6` / T043 | Requires exact commands/scenarios and observed outcomes for FR/SC and TASK-SEC-001 through TASK-SEC-008, including preflight and `config.key_unknown` redaction. Its direct dependencies include TASK-SEC-006, TASK-SEC-007, and TASK-SEC-008. |
| `matinee-mol-hyr.2.7` / T044 | Requires exact acceptance cases and observed results for all eight security tasks. Its acceptance explicitly requires `config.key_unknown` with only a redacted layer or source and no unknown-key text. It depends on T043 and the security/control cases, including TASK-SEC-006 and TASK-SEC-007. |

These records are open implementation or acceptance work. Their acceptance text is
contract evidence, not evidence that implementation or validation has already occurred.

## Disclosure and parser-boundary review

### Unknown-key disclosure — pass

The unknown-key contract is closed at every relevant layer:

- `spec.md:166-169` requires `config.key_unknown`, a redacted layer or source, and no
  echo or identification of the unaccepted key. `spec.md:180-186` further restricts a
  failure source to a redacted file origin or fixed layer class and excludes key tokens,
  raw paths, values, and OS error text.
- `contracts/configuration.md:69-76` separates successful provenance (which may name an
  accepted key) from the failure-source projection. For `config.key_unknown`, only a
  redacted file origin or fixed layer class is allowed.
- `contracts/configuration.md:125-137` closes the public failure shape to exactly
  `code`, `summary`, `source`, and `next_action`. `summary` and `next_action` are static
  templates selected solely by code; raw OS errors, paths, values, rejected secret
  material, parser excerpts, and dynamic strings cannot enter them. `code` is selected
  from the closed table, so it is the fixed `config.key_unknown`, not an input token.
- `data-model.md:138-150` repeats the four-field schema and states that the unknown key
  cannot enter the source or failure value. `data-model.md:178-186` requires one closed
  failure, no merge, and no raw disclosure in either terminal outcome.
- `TASK-SEC-007` and T044 require negative cases that inspect the complete rendered
  result, not only ordinary provenance. T016's prerequisite T015 also requires no
  unknown-key text and no partial state.

This satisfies the requested non-disclosure rule: exactly the fixed code plus safe
source information is exposed through the four-field failure, with no fifth field and no
unknown-key token in any field.

### Bounded preflight and typed syntax failures — pass

The parser boundary is explicit and internally consistent:

- `spec.md:172-177` caps each file at 1 MiB and requires a TOML-aware lexical preflight
  over no more than those bytes before typed deserialization. It rejects more than 100
  assignments, more than four dotted-key segments, text over 4,096 Unicode scalar
  values, and duplicate keys, with deterministic exact-limit, one-over, and pathological
  outcomes.
- `contracts/configuration.md:81-106` requires the byte bound first, then one bounded
  preflight that understands strings, escapes, comments, arrays, inline tables, table
  headers, and dotted keys. It explicitly says preflight-rejected documents cannot reach
  typed deserialization, while a passing document may produce `config.syntax_invalid`
  during typed TOML parsing. No failure reaches merge.
- `data-model.md:124-136` requires bounded counters and lexical state, rejects a limit
  violation immediately, and permits typed parsing to emit `config.syntax_invalid` only
  after preflight passes. `data-model.md:167-175` places this sequence in the state
  machine and rejects syntax-invalid, unknown, source-forbidden, secret-forbidden, and
  invalid descriptor values before resolution; `data-model.md:178-186` makes no-merge and
  closed-failure terminal invariants.
- `plan.md:160-173` orders byte enforcement, lexical preflight, typed parsing, provenance,
  merge, and closed rendering in that order. The plan does not incorrectly require every
  syntax error to be found lexically; typed TOML parsing remains the permitted source of
  `config.syntax_invalid`.
- T020, T016, and TASK-SEC-006 use the same rejected-before-deserialization acceptance
  boundary. TASK-SEC-007 covers malformed and limit failures in the complete closed
  renderer. T043/T044 require exact commands, scenarios, and observed outcomes for these
  controls.

The design therefore bounds resource work before typed deserialization without confusing
lexical-limit rejection with typed TOML syntax failure.

## Task wording and traceability review

| Area | Result | Evidence |
|---|---|---|
| TASK-SEC-006 | Pass | `matinee-mol-hyr.3.29` names pathological, exact-limit, and one-over-limit preflight cases and requires no deserialization, merge, or product state for rejected inputs. |
| TASK-SEC-007 | Pass | `matinee-mol-hyr.3.30` names every required negative failure family and requires exactly four public fields plus unknown-key non-disclosure and raw-disclosure absence. |
| T016 | Pass after correction | `matinee-mol-hyr.3.7` now references both the historical TASK-SEC-003 control and TASK-SEC-006; its acceptance is specifically about preflight-rejected inputs and remains compatible with the new security task. |
| T020 | Pass | `matinee-mol-hyr.3.11` gives the scanner's TOML lexical forms and the exact/one-over/pathological preflight boundary. |
| T043 | Pass | `matinee-mol-hyr.2.6` requires all eight security-task mappings, exact observed outcomes, and `config.key_unknown` redaction evidence; it directly depends on TASK-SEC-006/007/008. |
| T044 | Pass | `matinee-mol-hyr.2.7` requires confirmation of all eight security tasks and explicitly repeats the no-unknown-key-text rule. |

No task wording leaves the parser boundary or four-field disclosure boundary to an
ambiguous implementation choice.

## Spec 016 and public-surface boundary — pass

`plan.md:127-136` states that specs 006-015 add their assigned product behavior and that
spec 016 owns packaging, installation, release, and upgrade behavior while adding no
product crate. `.specify/memory/roadmap.md:255-266` independently scopes spec 016 to
package metadata, registry/release artifacts, extension delivery, upgrades, rollback,
compatibility, quickstart, journey acceptance, and performance baselines. It does not
assign a runtime product surface to spec 005 or add a new crate.

The foundation's own public-surface rule remains explicit: `spec.md:130-145` and
`spec.md:232-233` prohibit commands, modes, tools, endpoints, or extensions owned by
specs 006-016 until their implementations land. The clarification therefore adds no
unreviewed product surface and does not weaken the parser or disclosure boundaries.

## Historical reconciliation

The five original security findings remain closed in design, with implementation proof
pending:

- containment-before-read and zero-read escaped/link cases;
- platform-aware identity, pre/post snapshots, and the accepted same-user replacement
  threat-model boundary;
- bounded configuration input and parser ordering;
- redacted provenance and closed failures; and
- platform-aware environment-name comparison.

The three conductor residual findings are also closed in the current design:

- TASK-SEC-006 and T020/T016 now make the pre-deserialization boundary and pathological
  proof explicit;
- TASK-SEC-007 and T024/T018 close every rendered failure field; and
- TASK-SEC-008/T030/T036 provide exact lock identity and pairwise non-collision proof.

No historical finding is being suppressed merely because an older report says it was
closed; each conclusion above is supported by current artifact text and current Beads
acceptance text.

## Residual risks and acceptance conditions

These are implementation or governance conditions, not active plan findings:

1. T020, TASK-SEC-006, TASK-SEC-007, T043, and T044 remain open. The plan review cannot
   claim that scanner instrumentation, negative disclosure tests, or validation evidence
   already exist. T043 and T044 must preserve exact commands/scenarios and observed
   outcomes in `validation.md` before acceptance.
2. The approved local threat model excludes an active same-user process that replaces a
   file during the check/read window (`research.md:94-97`; `data-model.md:119-122`). The
   snapshot design is not a claim of race-proofing beyond that boundary.
3. `checklists/foundation.md:7-10` defines requirements-quality markers, not
   implementation behavior. Its checks cannot substitute for TASK-SEC-006/007 or
   T043/T044 evidence.
4. Architecture Guard and the security-review memory index were unavailable in this
   checkout; their skipped status is recorded rather than treated as validation.
5. The two human gates reported for this repository remain outside this review. This
   report does not resolve, bypass, or force-close either human gate.

## Severity summary

| Severity | Count | Finding IDs |
|---|---:|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Informational | 0 | — |

## Final verdict

**PASS — security plan review.** The corrected plan and authoritative Beads wording now
state and connect the required parser-boundary, closed-failure, and public-surface
controls. Unknown-key text cannot enter any of the four public failure fields by the
specified contract; syntax-invalid may arise at typed parsing after bounded preflight,
and no failure reaches merge. This PASS is limited to plan and task-contract quality;
implementation acceptance remains contingent on the open implementation and evidence
beads and on the human gates.

No new durable security finding was identified, so no memory capture is proposed.

| specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor-rerun-2.md | plan | 2026-09-12 | NONE | C:0 H:0 M:0 L:0 | |
