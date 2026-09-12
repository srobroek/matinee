---
document_type: security-review
review_type: plan
assessment_date: 2026-09-12
codebase_analyzed: matinee/specs/005-runtime-foundation
total_files_analyzed: 19
total_findings: 3
overall_risk: MEDIUM
critical_count: 0
high_count: 0
medium_count: 1
low_count: 2
informational_count: 0
owasp_categories: [A02, A06, A10]
cwe_ids: [CWE-200, CWE-367, CWE-400]
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

# Security Plan Review: Runtime Foundation, Conductor Pass

## Executive summary

This is a fresh plan-and-task security review of the runtime-foundation artifacts and the
authoritative Beads graph under `matinee-mol-hyr`. The deleted `tasks.md` was not used as
a task source. The design has strong controls for source authorization, containment,
platform-aware identity, file replacement detection, redaction of normal provenance,
dependency MSRV compatibility, and no product-state mutation.

Three residual design or evidence gaps remain:

- **One Medium**: resource limits are numerically specified, but the plan does not make
the parser boundary and structural preflight guarantee precise enough to bound parsing
work before deserialization.
- **Two Low**: failure serialization does not explicitly prohibit raw OS paths in every
error field, and lock-identity uniqueness is an invariant without a dedicated acceptance
case.

There are no Critical or High findings and no implemented code was reviewed. The verdict
is **CONDITIONAL PROCEED**: implementation may continue, but the three remediation tasks
below must be added to the authoritative graph and evidenced before the feature is
accepted. The existing `TASK-SEC-001` through `TASK-SEC-005` controls remain required;
they are not suppressed by the prior follow-up report.

## Scope and evidence reviewed

### Planning and contract artifacts (8)

- `specs/005-runtime-foundation/spec.md`
- `specs/005-runtime-foundation/plan.md`
- `specs/005-runtime-foundation/research.md`
- `specs/005-runtime-foundation/data-model.md`
- `specs/005-runtime-foundation/contracts/configuration.md`
- `specs/005-runtime-foundation/quickstart.md`
- `specs/005-runtime-foundation/checklists/foundation.md`
- `specs/005-runtime-foundation/checklists/requirements.md`

### Security and critique history (6)

- `specs/005-runtime-foundation/security-review.md`
- `specs/005-runtime-foundation/security-review-plan-2026-09-11-rerun.md`
- `specs/005-runtime-foundation/security-review-followup.md`
- `specs/005-runtime-foundation/critiques/critique-2026-09-11.md`
- `specs/005-runtime-foundation/critiques/critique-2026-09-11-rerun.md`
- `specs/005-runtime-foundation/critiques/critique-2026-09-11-followup.md`

### Governing and repository guidance (5)

- `.specify/memory/constitution.md`
- `.specify/memory/roadmap.md`
- `.specify/extensions/security-review/docs/field-registry.md`
- `AGENTS.md`
- `specs/AGENTS.md`

The feature security-memory index referenced by the extension is absent, and no
Architecture Guard integration is present in this checkout. Those integrations were
skipped and are reported rather than treated as security evidence.

## Authoritative Beads graph reviewed

The current graph is the source of implementation work:

- `matinee-mol-hyr` is the open implement feature.
- Its three direct children are open: `matinee-mol-hyr.1` (preserve released CLI),
  `matinee-mol-hyr.2` (compatibility and acceptance), and `matinee-mol-hyr.3` (local
  runtime environment).
- The three feature children contain the `T001`-`T044` task beads. Relevant controls
  include `matinee-mol-hyr.3.10`/T020 (bounded TOML reads and duplicates),
  `.3.11`/T021 (unknown/depth/value/source/secret rejection), `.3.15`/T024
  (provenance projection), `.3.16`/T025 (all-or-failure result), `.3.19`/T028
  (escaped and linked project files are not read), `.3.20`/T029 (replacement and
  post-read mismatch), `.3.21`/T030 (isolation and zero mutation), `.3.23`/T032
  (lexical normalization and existing ancestor), `.3.24`/T033 (platform identity and
  native comparison), `.3.25`/T034 (containment and link type before open),
  `.3.26`/T035 (file snapshot), and `.3.27`/T036 (derived lock identity).
- `matinee-mol-hyr.2.6`/T043 owns FR/SC-to-validation traceability and
  `.2.7`/T044 owns confirmation of `TASK-SEC-001` through `TASK-SEC-005`.
- All of these implementation and verification beads are still open. Their acceptance
  text requires observable evidence; task titles alone are not proof of a security
  control.

The earlier `matinee-mol-0mu` task-decomposition bead is closed with the explicit reason
that decomposition migrated to this graph. No deleted `tasks.md` was consulted.

## Severity summary

| Severity | Count | Finding IDs |
|---|---:|---|
| Critical | 0 | — |
| High | 0 | — |
| Medium | 1 | SEC-001 |
| Low | 2 | SEC-002, SEC-003 |
| Informational | 0 | — |

## Findings

### SEC-001 — Structural resource limits are not tied to a bounded parser boundary

- **Severity**: Medium (CVSS not assigned to an unimplemented design gap)
- **Evidence provenance**: statically-reviewed
- **Location**: `contracts/configuration.md:63-73`; `plan.md:154-159`;
  `data-model.md:133-138`; Beads `matinee-mol-hyr.3.10`/T020,
  `matinee-mol-hyr.3.11`/T021, and `matinee-mol-hyr.3.7`/T016
- **OWASP**: A10:2025 Mishandling of Exceptional Conditions; A06:2025 Insecure Design
- **CWE**: CWE-400: Uncontrolled Resource Consumption
- **Security task**: TASK-SEC-006 (required graph addition)
- **Historical status**: The earlier SEC-003 finding was design-closed by the
  follow-up because the byte, key, depth, and scalar limits were added. This is a
  narrower revalidation gap about enforcement order and parser behavior, not a claim
  that the numeric limits disappeared.

The contract correctly caps a file at 1 MiB and specifies 100 accepted keys, four
 dotted-key segments, and 4,096 Unicode scalar values. It also says the byte limit is
checked before TOML parsing and the remaining limits before merge. The plan and graph,
however, do not specify how structural limits are enforced while parsing, nor whether
the parser can first materialize an arbitrarily large set of unknown keys, a deeply
nested document, or oversized scalar text within the 1 MiB envelope. T020's title
requires bounded reads and duplicate detection before deserialization, while T021
places depth, value length, unknown-key, and secret rejection in a later task; the
contract does not define the required preflight or parser configuration that connects
those statements.

A hostile project can therefore force disproportionate parser allocation or recursion
before the resolver reaches the documented rejection path. The file-byte cap reduces
but does not eliminate this ambiguity. This weakens the resource-exhaustion guarantee
and makes a secure implementation choice implicit.

**Required remediation**

Add `TASK-SEC-006` under the runtime-resolution feature and make it a prerequisite for
the acceptance task. It must define one of the following and test it at the boundary:

1. a parser/loader with explicit bounded total entries, nesting, and scalar limits; or
2. a bounded lexical preflight that rejects duplicate keys, total key count, dotted
   depth, and scalar length before deserialization.

The task must include exact-at-limit and one-over-limit cases plus a pathological
1 MiB document containing unknown/deep/repeated keys. T020, T021, and T016 should
reference the same enforcement contract, and T044 must record its evidence.

### SEC-002 — Safe provenance does not explicitly cover all rendered error fields

- **Severity**: Low (CVSS not assigned to an unimplemented design gap)
- **Evidence provenance**: statically-reviewed
- **Location**: `contracts/configuration.md:50-60, 91-92`; `data-model.md:141-147`;
  Beads `matinee-mol-hyr.3.2`/T004, `.3.9`/T018, and `.3.15`/T024
- **OWASP**: A02:2025 Security Misconfiguration
- **CWE**: CWE-200: Exposure of Sensitive Information to an Unauthorized Actor
- **Security task**: TASK-SEC-007 (required graph addition)
- **Historical status**: The earlier SEC-004 finding was design-closed for ordinary
  provenance projections. This finding covers error summaries and next actions, which
  the earlier remediation did not enumerate.

The contract provides a good redacted-origin model: user paths are relative to `~`,
project paths are relative to the project root, and argument provenance is an argument
name rather than an argument value. It also requires a failure code, summary, failed
source, and safe next action. It does not explicitly prohibit an implementation from
embedding an `std::io` error string, the raw path supplied to a failing open, or a
secret-bearing value in the summary or next-action text. `data-model.md` likewise
requires redacted terminal provenance but does not define the serialized failure
surface. T004, T018, and T024 name safe fields and projection tests, but their current
Beads acceptance text does not state that every failure renderer must be checked.

A future CLI diagnostic or support surface could thus satisfy the provenance contract
while disclosing a username, project path, or sensitive input through an error detail.

**Required remediation**

Add `TASK-SEC-007` under the runtime-resolution or acceptance feature. Define a closed
failure schema whose rendered fields are code, safe summary, redacted source, and safe
next action; explicitly discard OS error text and raw input values. Add cases for
unreadable, changed, escaped, oversized, malformed, duplicate, unknown, forbidden,
and invalid files, asserting that neither absolute user/project paths nor secret-like
values occur in CLI stderr or diagnostic projections. Link the task to T004/T024 and
require T043/T044 evidence.

### SEC-003 — Lock-identity uniqueness is an invariant without a dedicated acceptance case

- **Severity**: Low (CVSS not assigned to an unimplemented design gap)
- **Evidence provenance**: statically-reviewed
- **Location**: `spec.md:143-146`; `data-model.md:69-90`; `quickstart.md:35-43`;
  `plan.md:163-172`; Beads `matinee-mol-hyr.3.21`/T030,
  `.3.27`/T036, and `.2.6`/T043
- **OWASP**: A06:2025 Insecure Design
- **Security task**: TASK-SEC-008 (required graph addition)
- **Historical status**: This is a new evidence gap; the prior security reports did
  not test the authoritative Beads decomposition for the lock-identity invariant.

FR-005-010 and the resolved-path invariants require equivalent roots to converge and
distinct roots to produce non-overlapping state paths **and lock identities**. T036
requires deriving lock identities, but the isolation task T030 names 100 roots and
zero mutation without naming lock identities. The quickstart's environment-contract
coverage lists roots, aliases, escapes, and replacement but not lock-ID collision
behavior. T043 promises a later FR/SC mapping, yet no current task states the expected
lock-ID algorithm, collision domain, or a test that would fail if two distinct roots
were assigned the same ID.

A collision could cause a later singleton/ownership implementation to treat two
otherwise distinct state roots as one daemon scope. This is not an exposed bug in the
current no-daemon slice, but it is a security-relevant identity invariant that the
foundation must prove before downstream specs rely on it.

**Required remediation**

Add `TASK-SEC-008` under the environment or acceptance feature. Specify the lock-ID
construction as a deterministic function of the canonical root identity, test all
equivalent aliases for convergence, test a large set of distinct roots for pairwise
non-collision, and record the result in `validation.md` against FR-005-010. T030 and
T036 should reference this task; T043 must include the lock-ID assertion.

## Control review

| Control area | Result | Current evidence and residual condition |
|---|---|---|
| Configuration trust and precedence | Pass, pending implementation proof | `spec.md:132-142,155-168` and `contracts/configuration.md:26-46` restrict protected values to user/explicit CLI, reject unknown/duplicate/secret-bearing values, and define five-layer precedence. T019-T023 and T015-T017 cover the matrix. Reserved keys remain unknown until their owning specification defines them, which is fail-closed. |
| Path containment | Pass, pending implementation proof | `spec.md:147-158`, `data-model.md:128-135`, and `contracts/configuration.md:14-17` require containment and link-type checks before opening the implicit project file. T028/T034 explicitly cover escaped and linked files without reads. |
| Path identity and aliases | Pass with SEC-003 gap | `research.md:88-101` and `data-model.md:69-90` use the longest existing anchor plus platform file identity and native case/Unicode semantics. T032/T033/T027 cover the identity algorithm and aliases; lock-ID uniqueness still needs TASK-SEC-008. |
| TOCTOU residual risk | Accepted residual, not counted | `research.md:94-97` and `data-model.md:103-116` require pre-read and post-read snapshots and explicitly exclude an active same-user replacement attacker from the local threat model. T029/T035 test replacement and mismatch. The foundation checklist's CHK018 is still unchecked, so an independent reviewer must record this as an accepted threat-model boundary rather than treating it as race-proofing. |
| Resource limits | **Finding SEC-001** | Numeric limits are present in `spec.md:159-161` and `contracts/configuration.md:63-73`; T016/T020/T021 cover them. Parser-boundary enforcement remains underspecified. |
| Redaction and secret handling | **Finding SEC-002** | `spec.md:164-168`, `contracts/configuration.md:50-60,91-92`, and T018/T024 provide provenance and secret controls. Error-field exclusion needs an explicit closed schema and negative cases. |
| Dependency compatibility | Pass, pending executable gate | `plan.md:16-19` selects Rust 2024, Rust 1.85, serde/toml/directories; `research.md:78-87` pins selected versions and calls out that directories lacks MSRV metadata. T002 and T039 require the workspace and Rust 1.85 direct/transitive build. This proves compatibility only when the lockfile-selected graph is what CI builds; dependency vulnerability/license review is outside this plan review. |
| No-mutation guarantee | Pass, pending implementation proof | `plan.md:21,38-40`, `data-model.md:81-84,141-148`, and `contracts/configuration.md:60-61` require all-or-failure resolution without file/directory creation or product-state writes. T025/T030/T037 cover the boundary and zero-mutation cases. |
| Public-surface containment | Pass | `spec.md:124-127,153-154,201-202`, `plan.md:120-140,176-184`, and T001/T013 prevent future commands, modes, endpoints, or extensions from appearing before their owning specifications are complete. |

## Checklist and historical reconciliation

- `checklists/requirements.md` is marked complete and covers source policy, limits,
  identity, no mutation, portability, and traceability. Its checked markers are
  requirements-quality claims, not implementation evidence.
- `checklists/foundation.md` now correctly names an independent reviewer at lines 8
  and 50. Its security-relevant items CHK006-CHK024 remain unchecked in this
  checkout, so the checklist must not be cited as completed evidence. In particular,
  CHK018 (same-user TOCTOU boundary), CHK019 (no mutation), and CHK022 (source plus
  mutation-safe failures) should be evaluated against this report before that gate
  closes.
- The initial `security-review.md` recorded SEC-001 through SEC-005. The rerun and
  follow-up reports state those five controls were added. This pass revalidated each
  control against the current artifacts and graph: the numeric values, source policy,
  pre-read containment, snapshots, redacted ordinary provenance, and environment-name
  comparison are present. The three findings above are residual enforcement/evidence
  gaps, not an automatic reopening of the prior findings.
- The prior critique reports are consistent with the current scope and preserve the
  no-placeholder and measured-baseline constraints. They are historical evidence only;
  the current Beads graph remains authoritative for implementation work.

## Required remediation and acceptance order

1. Add TASK-SEC-006, TASK-SEC-007, and TASK-SEC-008 as children of the appropriate
   `matinee-mol-hyr` feature bead. Keep their acceptance cases explicit and link them
   from T043 and T044; do not create a replacement `tasks.md`.
2. Implement and test T020/T021/T024/T028-T030/T032-T036 and the new security tasks
   through the single `resolve_environment` seam. No partial environment or product
   state may be returned on a failure.
3. Have the independent reviewer evaluate foundation checklist CHK006-CHK024,
   especially CHK018, CHK019, and CHK022, after the artifact/task updates.
4. Have T043 record exact commands/scenarios and observed outcomes for all FR, SC,
   and security-task controls. T044 must confirm TASK-SEC-001 through TASK-SEC-008,
   not just the original five.
5. Re-run this plan review or a security follow-up after the task graph and contracts
   are amended. Acceptance should remain blocked while SEC-001 is unresolved.

## Confirmed secure patterns

- Lower-trust project and environment layers cannot select protected settings.
- Unknown, duplicate, malformed, source-forbidden, secret-bearing, and excessive
  inputs have explicit failure codes and fail-closed semantics.
- Project containment and implicit-link rejection are specified before file open.
- Platform-specific file identity, case behavior, Unicode behavior, and pre/post file
  snapshots are part of the design.
- The resolver returns one complete result or one structured failure and does not create
  files or directories.
- User and project provenance has a redacted projection; raw absolute paths remain
  internal under the normal projection contract.
- The workspace preserves the released CLI and does not expose unfinished later-spec
  surfaces.
- Rust 1.85 compatibility is an executable gate, including transitive dependencies.

## Final risk and verdict

**Risk**: MEDIUM (0 Critical, 0 High, 1 Medium, 2 Low, 0 Informational).

**Verdict**: **CONDITIONAL PROCEED**. The architecture is security-conscious and contains
no demonstrated implementation vulnerability because implementation has not started.
Task generation and implementation may continue, but the feature cannot pass its
security/acceptance gate until the parser-boundary limit contract (SEC-001), complete
failure redaction (SEC-002), and lock-identity acceptance evidence (SEC-003) are added
to the authoritative Beads graph and proved. The explicit same-user TOCTOU exclusion
is an accepted residual risk that must remain visible in the independent checklist
review.

No durable security memory was captured; the findings are plan-specific and require
validation after implementation.

Routing row (memory index unavailable):

`| specs/005-runtime-foundation/security-review-plan-2026-09-12-conductor.md | plan | 2026-09-12 | MEDIUM | C:0 H:0 M:1 L:2 | A02,A06,A10 |`
