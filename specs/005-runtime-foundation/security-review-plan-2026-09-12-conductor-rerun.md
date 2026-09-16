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

# Security Plan Review: Runtime Foundation, Conductor Rerun

## Executive summary

This fresh review re-evaluates the amended spec 005 plan, supporting contracts, prior
security reviews, constitution boundaries, and the authoritative Beads implementation
DAG. The three residual gaps identified by the prior conductor pass are now explicitly
specified and assigned to implementation-and-evidence tasks:

- bounded TOML-aware lexical preflight before typed deserialization (`TASK-SEC-006`);
- a closed four-field failure projection with negative non-disclosure cases
  (`TASK-SEC-007`); and
- exact, non-hashed, non-truncated lock identity with pairwise collision evidence
  (`TASK-SEC-008`).

The earlier SEC-001 through SEC-005 controls are also present in the current artifacts and
are connected to concrete implementation or contract tasks. No active design finding
remains. The verdict is **PASS** for the security plan. This is not implementation
sign-off: all implementation tasks remain open, and T043/T044 must record observed proof
before feature acceptance.

## Scope and evidence reviewed

### Current feature artifacts

- `specs/005-runtime-foundation/spec.md` (FR-005-001 through FR-005-020, edge cases,
  success criteria, and material-class policy)
- `specs/005-runtime-foundation/plan.md` (technical context, constitution checks,
  implementation sequence, and dependency gate)
- `specs/005-runtime-foundation/research.md` (dependency MSRV and path-threat model)
- `specs/005-runtime-foundation/data-model.md` (identity, snapshot, preflight, and
  failure state machine)
- `specs/005-runtime-foundation/contracts/configuration.md` (source policy, limits,
  failure codes, and public projection)
- `specs/005-runtime-foundation/quickstart.md` (contract and dependency acceptance
  commands)
- `specs/005-runtime-foundation/checklists/foundation.md` (requirements-quality
  checklist; not implementation evidence)
- `.specify/memory/constitution.md` and `.specify/memory/roadmap.md`

### Historical security evidence

- `specs/005-runtime-foundation/security-review.md` (original SEC-001 through SEC-005)
- `specs/005-runtime-foundation/security-review-plan-2026-09-11-rerun.md`
- `specs/005-runtime-foundation/security-review-followup.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor.md` (the
  immediately preceding residual SEC-001 through SEC-003 findings)

The security-review memory index and Architecture Guard integration are not present in
this checkout. They were not treated as evidence or as a blocker.

## Authoritative Beads graph review

The authoritative implementation graph is `matinee-mol-hyr`; no `tasks.md` was used or
recreated. A fresh `bd` inspection found **47 task nodes** (T001-T044, including the
security tasks) and **71 task-to-task blocking edges** beneath the feature graph. The
security tasks are actual task beads, not title-only placeholders:

| Bead | Actual description and acceptance evidence |
|---|---|
| `matinee-mol-hyr.3.10` / T019 | Defines typed key descriptors, `material_class`, the closed 100-key registry, and `state_dir` ownership. Its acceptance requires only `non_secret` production descriptors, deterministic `config.secret_forbidden` for fixture secret classes, and no raw-text heuristic classification. |
| `matinee-mol-hyr.3.11` / T020 | Implements the 1 MiB read and TOML-aware preflight for duplicate keys, 100 assignments, four dotted segments, and 4,096-scalar text values before deserialization. Acceptance requires bounded TOML lexical state, exact-limit success, and one-over/pathological inputs never reaching deserialization or merge. |
| `matinee-mol-hyr.3.12` / T021 | Validates unknown keys, protected sources, descriptor material classes, and typed values after preflight and before merge; acceptance requires distinct stable failures, redacted source, and no partial result. |
| `matinee-mol-hyr.3.15` / T024 | Implements provenance and failure projection through the closed four-field schema; acceptance requires static summaries/actions and disposal of raw OS errors, paths, values, parser excerpts, and secret material. |
| `matinee-mol-hyr.3.16` / T025 | Assembles the all-or-failure result without filesystem mutation. |
| `matinee-mol-hyr.3.19` / T028 | Tests escaped and implicit-linked project files and asserts zero file reads. |
| `matinee-mol-hyr.3.20` / T029 | Tests project-file replacement and post-read identity mismatch. |
| `matinee-mol-hyr.3.21` / T030 | Tests 100-root isolation, alias convergence, exact lock-identity non-collision, missing-home, inaccessible-directory, and zero mutation; acceptance requires pairwise-disjoint state paths and lock identities. |
| `matinee-mol-hyr.3.23` / T032 | Implements absolute lexical normalization and longest-existing-ancestor discovery. |
| `matinee-mol-hyr.3.24` / T033 | Implements platform file identity and native case/Unicode comparison. |
| `matinee-mol-hyr.3.25` / T034 | Validates project containment and link type before opening the file. |
| `matinee-mol-hyr.3.26` / T035 | Captures and rechecks project-file identity, type, length, and change marker. |
| `matinee-mol-hyr.3.27` / T036 | Derives exact lock identity; acceptance prohibits hashing and truncation. |
| `matinee-mol-hyr.3.28` / T037 | Integrates bounded configuration, closed failures, and validated paths through one all-or-failure `resolve_environment` seam. |
| `matinee-mol-hyr.3.29` / TASK-SEC-006 | Requires pathological, exact-limit, and one-over-limit cases proving bounded preflight rejects excessive assignments, depth, duplicate keys, and overlong Unicode text before typed deserialization, returns a closed failure, and leaves no product state. It blocks on T018 and the runtime feature. |
| `matinee-mol-hyr.3.30` / TASK-SEC-007 | Requires exhaustive negative rendering cases for unreadable, changed, escaped, oversized, malformed, duplicate, unknown, source-forbidden, secret-forbidden, limit-exceeded, and invalid-value failures. Acceptance requires exactly code, static safe summary, redacted source, and static safe next action, with all raw disclosures and mutation absent. It blocks on TASK-SEC-006. |
| `matinee-mol-hyr.3.31` / TASK-SEC-008 | Requires alias convergence and pairwise non-collision across 100 distinct canonical roots, with exact lock identity and no product state. It blocks on T030 and T036. |
| `matinee-mol-hyr.2.2` / T039 | Requires a Rust 1.85 `--locked` workspace gate over direct and transitive dependencies, recording the Cargo.lock checksum, locked tree, licenses, and advisory output in `validation.md`. |
| `matinee-mol-hyr.2.6` / T043 | Requires FR/SC and TASK-SEC-001 through TASK-SEC-008 mappings to exact commands/scenarios and observed outcomes, including preflight, failure non-disclosure, exact lock identity, dependency provenance, and the performance decision. Its blocking dependencies include TASK-SEC-006, -007, and -008. |
| `matinee-mol-hyr.2.7` / T044 | The corrected title now reads `T044 Confirm TASK-SEC-001 through TASK-SEC-008 from specs/005-runtime-foundation/`. Its description requires the exact acceptance cases for all eight security tasks and observed results in `validation.md`; its blocking dependencies include TASK-SEC-006, -007, and -008 plus the original security cases. |

The direct dependency lists confirm both traceability tasks depend on all three new
security tasks: `matinee-mol-hyr.2.6` lists `.3.29`, `.3.30`, and `.3.31`;
`matinee-mol-hyr.2.7` lists the same three. The three new tasks are children of
`matinee-mol-hyr.3`, and their implementation ordering is explicit (`.3.29` before
`.3.30`; `.3.31` after T030/T036). This is an actual DAG link review, not an inference
from task titles.

## Historical finding reconciliation

| Historical finding | Current evidence | Status |
|---|---|---|
| Original SEC-001: project configuration could be read before containment validation (`security-review.md`, prior report lines 66-79) | `spec.md:154-168`; `data-model.md:160-169`; `contracts/configuration.md:14-17`; T028/T034 (`matinee-mol-hyr.3.19`, `.3.25`) require containment and link checks before read and zero-read escape cases. | **Closed in design; implementation proof pending T028/T034/T043/T044.** |
| Original SEC-002: path identity omitted platform equivalence and replacement checks (prior report lines 81-95) | `research.md:88-101`; `data-model.md:73-95,109-122`; T029/T033/T035 (`.3.20`, `.3.24`, `.3.26`) require platform identity, native comparison, pre/post snapshots, and changed-file rejection. | **Closed in design.** The same-user active replacement attacker remains an explicitly accepted threat-model boundary (`research.md:94-97`; `data-model.md:119-122`). |
| Original SEC-003: unbounded configuration input (prior report lines 97-110) | `spec.md:169-174`; `contracts/configuration.md:74-98`; `plan.md:159-171`; T020/T016 (`.3.11`, `.3.7`) and TASK-SEC-006 require bounded preflight before deserialization. | **Closed in design; implementation proof pending.** |
| Original SEC-004: provenance could expose absolute paths (prior report lines 112-124) | `spec.md:177-181`; `contracts/configuration.md:62-69`; `data-model.md:137-148`; T024/T018 (`.3.15`, `.3.9`) require safe projections and negative cases. | **Closed in design.** |
| Original SEC-005: Windows environment-name comparison was undefined (prior report lines 126-138) | `spec.md:175-176`; `contracts/configuration.md:22-24`; T017/T023 (`.3.8`, `.3.14`) normalize platform identity before key mapping and duplicate detection. | **Closed in design.** |
| Conductor residual SEC-001: resource limits lacked a bounded parser boundary (`security-review-plan-2026-09-12-conductor.md:137-179`) | `contracts/configuration.md:83-98`; `data-model.md:124-135`; `plan.md:161-170`; T020 and TASK-SEC-006 explicitly require one bounded TOML-aware preflight before typed deserialization and test exact/one-over/pathological inputs. | **Closed in design.** |
| Conductor residual SEC-002: safe provenance did not cover every rendered error field (`security-review-plan-2026-09-12-conductor.md:181-215`) | `contracts/configuration.md:117-128`; `data-model.md:137-148`; T024 and TASK-SEC-007 require exactly four public fields and exhaustive negative cases for every listed failure class. | **Closed in design.** |
| Conductor residual SEC-003: lock identity lacked a dedicated collision acceptance case (`security-review-plan-2026-09-12-conductor.md:217-249`) | `spec.md:148-153`; `data-model.md:85-107`; `quickstart.md:45-49`; T030/T036 and TASK-SEC-008 require exact identity, alias convergence, and pairwise non-collision across 100 roots. | **Closed in design.** |

## Security control review

### Descriptor-owned secret classification — pass

The material class is descriptor-owned and closed: `non_secret`,
`opaque_secret_reference`, or `secret_material` (`data-model.md:16-42`). The production
registry accepts only `non_secret`; the other two classes fail with
`config.secret_forbidden`, including fixture registries, and arbitrary raw text is never
classified heuristically (`spec.md:182-187`; `contracts/configuration.md:47-58`). T019 and
T021 carry these rules into implementation and distinguish descriptor rejection from typed
value validation. This satisfies the constitution's least-privilege and redaction
boundaries (`constitution.md:43-53`).

### Bounded TOML-aware lexical preflight — pass

The byte cap and structural limits are explicit (`spec.md:169-174`; `contracts/configuration.md:74-98`). The contract and data model require a single bounded preflight that understands
strings, escapes, comments, arrays, inline tables, table headers, and dotted keys, so
syntax in text/comments cannot inflate structural counts (`contracts/configuration.md:83-98`;
`data-model.md:124-135`). The plan places this preflight before typed deserialization
(`plan.md:159-170`), and T020/TASK-SEC-006 make the no-deserialization/no-merge boundary an
acceptance criterion. This closes the parser resource-boundary residual; implementation
must still prove it through T043/T044.

### Closed four-field failures and redaction — pass

The failure contract is closed to exactly `code`, `summary`, `source`, and `next_action`,
with code-selected static templates and a redacted source (`contracts/configuration.md:100-128`).
The data model discards OS errors after code selection and excludes raw paths, values,
rejected secret material, parser excerpts, and dynamic strings (`data-model.md:137-148`).
T024/T018 and TASK-SEC-007 require exhaustive negative cases and no product-state mutation.
The former provenance-only SEC-004 is therefore extended to all rendered failure fields.

### Exact lock identity — pass

The specification requires the exact canonical root identity in the lock identity, without
hashing or truncation, and requires equivalent roots to converge while distinct roots
remain distinct (`spec.md:148-153`). The resolved environment and path invariants repeat
this requirement (`data-model.md:85-107`), and the plan places it in the platform-path
stage (`plan.md:174-185`). T036 defines the construction; T030 and TASK-SEC-008 require
alias convergence and pairwise distinction across 100 roots. The acceptance surface is
now explicit rather than an untested invariant.

### Containment, TOCTOU boundary, and no mutation — pass with stated residual

Containment and link type are checked before opening an implicit project file
(`spec.md:154-168`; `contracts/configuration.md:14-17`; `data-model.md:160-169`). The file
snapshot captures identity, type, length, and change marker before parsing and rechecks
them after reading (`data-model.md:109-122`); T028/T029/T034/T035 provide direct task
coverage. Resolution returns one complete environment or one failure and creates no files
or directories (`contracts/configuration.md:60-72`; `data-model.md:175-182`; T025/T030/T037).

The accepted residual is narrow and explicit: an active same-user process that replaces a
file between filesystem checks is outside the local threat model (`research.md:94-97`;
`data-model.md:119-122`). This is not a claim that the implementation is race-proof, and
it is not an active plan finding.

### Rust 1.85 dependency provenance — pass pending executable evidence

The plan fixes Rust 1.85 as the minimum and selects `serde`, `toml`, `directories`, and
`tempfile` (`plan.md:14-19`). Research correctly avoids relying solely on metadata:
`toml` 1.1.6 declares Rust 1.85, while `directories` 6.0.0 does not declare an MSRV, so
compatibility must be proven by compiling the lockfile-selected direct and transitive
graph (`research.md:78-87`). T039's actual acceptance requires `--locked`, the Cargo.lock
checksum, dependency tree, license data, and advisory output; T043 explicitly maps this
provenance to observed validation. No dependency design gap remains, but no implementation
or CI evidence is claimed by this plan review.

### Constitution and public-surface boundaries — pass

The plan records pre- and post-design constitution checks with no exception
(`plan.md:53-79`). It preserves local ownership and rejects lower-trust protected values,
unknown keys, unsafe paths, and sensitive diagnostics (`plan.md:57-68`). The runtime slice
adds no network, browser-control, daemon, MCP, extension, or workflow surface, consistent
with the scope boundary (`spec.md:129-145`; `plan.md:127-147`; `constitution.md:68-86`).
No constitution principle is violated and no exception is required.

## Residual risks and acceptance conditions

No active security finding or required plan remediation remains. The following are
implementation/acceptance conditions, not findings:

1. All implementation and verification beads under `matinee-mol-hyr` are still open.
   T043 and T044 must not be satisfied by titles or planned commands; they must preserve
   exact commands/scenarios and observed outcomes for all eight security tasks.
2. The same-user active replacement process remains outside the local threat model as
   documented above. Any future expansion of the threat model must replace the snapshot
   design with stronger handle-based or equivalent protections before claiming stronger
   race guarantees.
3. `checklists/foundation.md:7-10` explicitly says checklist markers are requirements
   quality, not implementation behavior. Its unchecked security items (especially
   CHK018-CHK022 at `checklists/foundation.md:36-43`) must not be cited as implementation
   evidence. This report does not edit or mark that checklist.
4. Architecture Guard and the security-review memory index were unavailable in this
   checkout. Their absence is recorded, not silently treated as validation.

## Severity summary

| Severity | Count | Finding IDs |
|---|---:|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 0 | — |
| Low | 0 | — |
| Informational | 0 | — |

## Final verdict

**PASS — security plan review.** The amended plan and authoritative Beads graph now state
and connect the controls needed to close SEC-001 through SEC-005 and the three residual
conductor findings. No active design finding requires remediation. This PASS applies to
requirements and task-contract quality only; implementation acceptance remains contingent
on the open T001-T044 work and the observed evidence required by T043/T044.

No new durable security finding was identified, so no memory capture is proposed.

| specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor-rerun.md | plan | 2026-09-12 | NONE | C:0 H:0 M:0 L:0 | |
