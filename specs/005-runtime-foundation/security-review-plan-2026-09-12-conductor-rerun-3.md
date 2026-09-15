---
document_type: security-review
review_type: plan
assessment_date: 2026-09-12
codebase_analyzed: matinee/specs/005-runtime-foundation
total_files_analyzed: 17
total_findings: 0
overall_risk: NONE
critical_count: 0
high_count: 0
medium_count: 0
low_count: 0
informational_count: 0
owasp_categories: []
cwe_ids: [CWE-200, CWE-400]
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

# Security Plan Review: Runtime Foundation, Conductor Rerun 3

## Executive summary

This independent rerun adversarially reviews configuration-classification collisions in
spec 005. It covers the current specification, plan, configuration contract, data model,
quickstart, checklist state (without editing it), governing constitution and roadmap,
historical security reports, the latest critique rerun, and the authoritative Beads task
contracts. It does not inspect or claim implementation behavior.

The contract has one unambiguous classification order for a parsed assignment:
**descriptor presence, material class, source permission, then value validity**. Earlier
file-level gates (readability, file identity, byte bound, bounded TOML-aware preflight,
duplicate detection, and typed syntax parsing) reject before descriptor classification when
they apply. Every rejection is one terminal structured failure; nothing reaches merge or
product-state mutation.

The adversarial collision matrix below found no active plan or task-contract finding. The
verdict is **PASS** for this plan review, conditional only on the already-required future
implementation and observed acceptance evidence. This report does not resolve or bypass
the open human gates `matinee-mol-tra` and `matinee-mol-bv9`.

## Scope and evidence reviewed

### Current planning artifacts (7)

- `specs/005-runtime-foundation/spec.md`
- `specs/005-runtime-foundation/plan.md`
- `specs/005-runtime-foundation/research.md`
- `specs/005-runtime-foundation/data-model.md`
- `specs/005-runtime-foundation/contracts/configuration.md`
- `specs/005-runtime-foundation/quickstart.md`
- `specs/005-runtime-foundation/checklists/foundation.md`

The checklist is a requirements-quality gate, not implementation evidence, and was not
edited by this review.

### Governing and repository artifacts (4)

- `.specify/memory/constitution.md`
- `.specify/memory/roadmap.md`
- `AGENTS.md`
- `specs/AGENTS.md`

### Historical/security artifacts (6)

- `specs/005-runtime-foundation/security-review.md`
- `specs/005-runtime-foundation/security-review-followup.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor-rerun.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor-rerun-2.md`
- `specs/005-runtime-foundation/critiques/critique-2026-09-12-conductor-rerun-2.md`

The security-review field registry was also consulted at
`.specify/extensions/security-review/docs/field-registry.md`; it is not counted in the
feature-artifact total above. The feature security-memory index and Architecture Guard
integration are unavailable in this checkout and were not treated as evidence.

### Authoritative Beads contracts

The task source is the `matinee-mol-hyr` graph; no `tasks.md` was used or recreated. The
relevant records inspected directly were:

- `matinee-mol-hyr.3.2` / T004: exactly four safe diagnostic fields; raw operating-system
  and parser errors are discarded; unknown-key text is forbidden.
- `matinee-mol-hyr.3.6` / T015: descriptor lookup precedes material class, source policy,
  and value checks; an unregistered reserved key is `config.key_unknown`; only a
  registered protected descriptor is `config.source_forbidden`; only a registered
  secret-class descriptor is `config.secret_forbidden`; no key text or partial state.
- `matinee-mol-hyr.3.7` / T016: exact and one-over byte, assignment, depth, and scalar
  limits plus pathological 1 MiB cases; preflight rejection is before typed parsing,
  merge, and product state.
- `matinee-mol-hyr.3.11` / T020: bounded TOML lexical state for strings, escapes,
  comments, arrays, inline tables, headers, and dotted keys; duplicate and limit cases
  do not reach typed deserialization or merge.
- `matinee-mol-hyr.3.12` / T021: ordered descriptor lookup, material-class validation,
  source authorization, and typed-value validation after preflight and before merge;
  returns the first of `config.secret_forbidden`, `config.source_forbidden`, or
  `config.value_invalid` with no partial result.
- `matinee-mol-hyr.3.15` / T024: static summaries/actions and closed redacted sources;
  raw errors, paths, values, parser excerpts, and secret material are discarded.
- `matinee-mol-hyr.3.16` / T025: all-or-failure configuration result with no filesystem
  mutation.
- `matinee-mol-hyr.3.30` / TASK-SEC-007: exhaustive negative rendering cases for
  malformed, duplicate, unknown, source-forbidden, secret-forbidden, limit, and invalid
  value failures, including classification precedence and unknown-key non-disclosure.
- `matinee-mol-hyr.2.6` / T043: exact command/scenario and observed-outcome mapping for
  FR-005-001 through FR-005-020, SC-005-001 through SC-005-007, and TASK-SEC-001 through
  TASK-SEC-008, including classification precedence and unknown-key redaction.
- `matinee-mol-hyr.2.7` / T044: exact acceptance cases and observed results for all eight
  security tasks, including unregistered-reserved versus registered-protected cases,
  config.key_unknown redaction, and closed failure shape.

All cited implementation and acceptance beads remain open. Their wording is contract
coverage, not evidence that implementation or validation already exists.

## Adversarial classification collision matrix

The controlling text is `spec.md:166-171,174-192`,
`contracts/configuration.md:43-65,76-86,97-113,115-144`, and
`data-model.md:124-189`. `plan.md:160-173` repeats the same ordering and places the
matrix in the implementation sequence.

| Collision or input | Earlier gate / classification | Exactly one expected code | Disclosure and merge result |
|---|---|---|---|
| Unregistered reserved key (`state_dir`, `daemon.endpoint`, `principal.native`, or `extension.development_identity`) from project or environment, before its owning specification registers it | Descriptor is absent; source policy is not consulted | `config.key_unknown` | `source` is only a redacted file origin or fixed layer class; the key token is absent from every field; no partial environment and no merge |
| Registered protected descriptor from prohibited project or environment source | Descriptor exists, class is `non_secret`, then source authorization fails before value validation | `config.source_forbidden` | Four closed fields only; source is redacted/fixed; raw value/path/error absent; no merge |
| Registered secret-class descriptor (`opaque_secret_reference` or `secret_material`) from an allowed user/CLI source | Material class fails before source permission and value validation | `config.secret_forbidden` | It cannot become a valid user/CLI setting; rejected material is not rendered; no merge |
| Registered secret-class descriptor from a prohibited source and with an invalid value | Material class still precedes source and value checks | `config.secret_forbidden` (not `config.source_forbidden` or `config.value_invalid`) | One closed failure, no class/value/source detail that discloses input; no merge |
| Registered ordinary `non_secret` descriptor from an allowed source with wrong type or failed normalization | Descriptor and material class pass; source authorization passes; value check fails | `config.value_invalid` | Static summary/action and closed source only; invalid value and raw parser/OS text absent; no merge |
| Registered protected descriptor from a prohibited source with an invalid value | Source authorization precedes value validation | `config.source_forbidden` (not `config.value_invalid`) | No partial merge; no raw value or path disclosure |
| Duplicate key, including a duplicate whose key would otherwise be unknown, protected, or secret-class | Bounded TOML-aware preflight precedes typed deserialization and descriptor classification | `config.key_duplicate` | Duplicate is rejected before typed parse/classification; exactly one closed failure; no merge or product-state mutation |
| Assignment/depth/text limit or pathological 1 MiB input, even if it contains a classification collision | File-byte bound and bounded lexical preflight precede typed deserialization | `config.file_too_large` for over-byte input, otherwise `config.limit_exceeded` | Preflight rejection cannot reach typed deserialization or merge; bounded counters and no product state |
| Malformed TOML that passes lexical preflight, including an assignment that would otherwise collide with classification | Typed TOML parse fails before descriptor validation | `config.syntax_invalid` | Parser excerpts, raw input, paths, and OS errors cannot enter any field; no merge |

The table tests precedence adversarially rather than treating each error family in
isolation. In particular, an unregistered reserved key cannot be upgraded to
`config.source_forbidden` by placing it in a prohibited source; a secret-class descriptor
cannot be downgraded to source-forbidden or invalid-value by choosing a prohibited source
or malformed value; and a duplicate/preflight rejection cannot be bypassed by embedding a
protected, secret, unknown, or invalid assignment.

## One-code, closed-failure, and no-partial-merge proof

The four artifacts agree on the terminal invariant:

1. `spec.md:157-161` requires one closed failure with only stable code, static summary,
   redacted source, and static next action, before product-state mutation.
2. `spec.md:166-192` fixes descriptor-first classification, the reserved-key unknown rule,
   secret-class rejection, and raw-disclosure exclusions.
3. `contracts/configuration.md:47-52` explicitly states the classification order;
   `:85-86` says the resolver returns a complete result or one structured failure, never a
   partial environment; `:111-113` makes preflight rejection precede typed parsing and
   merge; and `:132-144` closes all four rendered fields and covers every listed failure.
4. `data-model.md:131-136,167-177,181-189` makes the preflight and descriptor ordering
   state-machine transitions explicit, and requires exactly one closed failure, no merge,
   no mutation, and no raw paths, values, errors, or rejected secrets in either terminal
   outcome.
5. T004, T015, T021, T024, T025, TASK-SEC-006, TASK-SEC-007, T043, and T044 carry these
   obligations into implementation and observed acceptance evidence.

The contract therefore provides one stable public code per attempted resolution and does
not expose a second field for the rejected key, source-policy rationale, parser excerpt,
or value. Successful provenance may name accepted keys, but failure projection may not name
an unaccepted key. The implementation still must demonstrate that its traversal uses the
specified order and returns the first failure rather than accumulating or partially merging
assignments.

## Secure patterns confirmed

- Reserved names remain unknown until an owning specification registers a descriptor;
  source trust cannot turn an unregistered name into a protected setting.
- Material class is descriptor-owned and closed. Spec 005 accepts only `non_secret` and
  never guesses secret status from raw key or value text.
- Source authorization occurs before value validation, preventing a prohibited source from
  using an invalid value to reach a later diagnostic or normalization path.
- Duplicate and resource-limit rejection occurs before typed deserialization; typed syntax
  rejection is separately allowed only after a passing preflight. Neither reaches merge.
- Failure projection has exactly four fields, static code-selected templates, and only a
  redacted file origin or fixed layer-class source. Unknown-key text, raw values, raw
  paths, parser excerpts, and operating-system errors are excluded.
- The resolved environment is complete-or-failure and resolution creates no product state.
- The source-policy and descriptor registry are the only authority for accepted keys and
  source permissions; no heuristic fallback is specified.

## Residual risk and acceptance conditions

No active plan or task-contract finding was identified. The following residuals are not
findings in this plan review:

1. **Implementation proof pending.** T019/T020/T021/T022/T024/T025/T037 and TASK-SEC-006/
   TASK-SEC-007 remain open. T043 and T044 must record exact commands/scenarios and
   observed outcomes for the matrix, including collision pairs where an invalid value,
   prohibited source, secret class, unknown descriptor, duplicate, or preflight failure
   compete. The plan's PASS is not implementation sign-off.
2. **Human gates remain external blockers.** `matinee-mol-tra` and `matinee-mol-bv9` are
   open human gates. This review neither resolves nor force-closes them.
3. **Threat-model boundary remains accepted.** The documented active same-user process
   that replaces a file during filesystem checks remains outside the local threat model
   (`research.md:94-97`; `data-model.md:119-122`). This does not weaken the classification
   contract and is not counted as an active finding.
4. **Checklist is separate evidence.** `checklists/foundation.md` currently retains
   unchecked independent-review markers for CHK007, CHK008, CHK012, and CHK023 at the time
   of this review. This report did not edit that file, and no checklist marker is treated
   as implementation proof. The critique owner controls those edits.
5. **Unavailable integrations.** The feature security-memory index and Architecture Guard
   integration were unavailable in this checkout; neither was silently treated as passed.

## Severity summary

| Severity | Count | Finding IDs |
|---|---:|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Informational | 0 | — |

## Final verdict

**PASS — security plan review.** The current spec, plan, contract, data model, quickstart,
and authoritative Beads task graph define a single fail-closed classification order:
descriptor presence, material class, source permission, value validity. Earlier duplicate,
byte/structural-preflight, and typed-syntax gates are also separated and cannot reach merge.
The adversarial collision matrix confirms the intended stable codes, closed four-field
projection, no raw disclosure, and no partial merge for each requested collision.

This PASS is limited to plan and task-contract quality. T043/T044 and the open implementation
beads must supply observed proof, and the two human gates remain unresolved external blockers.
No durable memory capture is proposed because no new active security finding was identified.

| specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor-rerun-3.md | plan | 2026-09-12 | NONE | C:0 H:0 M:0 L:0 | |
