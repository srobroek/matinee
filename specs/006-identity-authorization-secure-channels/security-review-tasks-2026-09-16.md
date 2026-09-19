---
document_type: security-review
review_type: tasks
assessment_date: 2026-09-16
codebase_analyzed: matinee/specs/006-identity-authorization-secure-channels
total_files_analyzed: 15
total_findings: 2
overall_risk: MEDIUM
critical_count: 0
high_count: 0
medium_count: 2
low_count: 0
informational_count: 0
owasp_categories: [A04]
cwe_ids: [CWE-665, CWE-693]
asvs_requirements: [V1.1.1, V14.2.1]
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
  asvs_requirements: "Verified ASVS requirements mapped to findings."
  mitre_techniques: "Verified MITRE ATT&CK techniques applicable to findings."
  finding_id: "Unique finding identifier (SEC-NNN) for cross-referencing and task linkage."
  location: "Artifact or code path and line number supporting the finding (path/to/artifact:line)."
  owasp_category: "OWASP Top 10 2025 category for this finding (AXX:2025-Name)."
  cwe: "Common Weakness Enumeration identifier with short name (CWE-NNN: Name)."
  cvss_score: "CVSS v3.1 base score (0.0-10.0). 9.0+=Critical, 7.0-8.9=High, 4.0-6.9=Medium, 0.1-3.9=Low."
  security_task: "Security task ID for backlog tracking and remediation follow-up (TASK-SEC-NNN). Supports legacy spec_kit_task as alias."
---

# Security Task Review: Identity, Authorization, and Secure Channels

## Executive summary

The 52-task graph covers the specified v1 identity, enrollment, authenticated-channel, authorization, rotation, revocation, event, rate-limit, race, malformed-input, redaction, and evidence surfaces. The prior plan findings are carried into the task content: exact nonce/AAD vectors, one-frame/no-fragmentation limits, extension key custody and fail-closed recovery, and event-sink/access floors are represented by concrete tasks and quickstart evidence. Root workspace membership, the new crate manifest, and generated lockfile are ordered as T002/T003 followed by T004, existing CLI/runtime crates and downstream specifications remain out of scope.

Two medium sequencing findings remain before implementation. The graph's prose checkpoints do not encode all blocking edges, so parallel markers can permit implementation or risky tests to start before ADR/security preconditions and foundational contract tests. This is a reviewability and security-gate problem, not evidence of an implemented vulnerability. Conditional proceed is appropriate only after the dependency edges below are made explicit in the task graph (or an equivalent scheduler-enforced prerequisite mechanism is added).

## Tasks reviewed

Reviewed T001--T052 in `specs/006-identity-authorization-secure-channels/tasks.md`, with `plan.md`, `spec.md`, `research.md`, `data-model.md`, `quickstart.md`, all four feature contracts, `agent-assignments.yml`, the prior plan review, Constitution, roadmap, and repository guidance. No source, manifest, lockfile, Beads, or primary planning artifact was modified. No test suite, formatter, or linter was run.

## Findings

### Unsafe sequencing

#### SEC-001 -- ADR/security preconditions are not an enforced prerequisite for manifest and dependency work

- **Severity:** MEDIUM (CVSS 5.2)
- **OWASP:** A04:2025 Insecure Design
- **CWE:** CWE-665: Improper Initialization
- **ASVS:** V1.1.1
- **Evidence:** `tasks.md:18-21,29,171-174,188-191`, `plan.md:180-187,223-230`
- **Historical status:** New task-graph sequencing finding. The prior plan review did not identify this task-level edge because it reviewed design intent, the current plan's ADR requirement and the task graph's parallel example are the conflicting evidence.

T001 says ADR candidates `adr-5` and `adr-6` must be created before code begins, and Phase 2 is blocked until T001 is satisfied. However, T002 and T003 are explicitly parallel with T001 in the execution example, while T003 selects the security dependency set and creates the crate manifest. The task graph therefore permits security-sensitive dependency/manifest work before the fixed profile and keyring/Rust-1.85 departure are recorded. The prose says T001 blocks implementation but does not define whether manifest creation is exempt or how a scheduler enforces the distinction.

**Exact remediation:**

- Add an explicit dependency to T002 and T003 on T001, or split T003 into a non-security directory scaffold that may run in parallel and a dependency-bearing manifest task that depends on T001.
- Keep T004 dependent on T002 and T003, and state that lockfile generation is allowed only after the ADR gate and both manifest/workspace edits complete.
- Add a checkpoint task or acceptance condition to T001 requiring the two decisions to be recorded/approved before any dependency choice or source implementation is claimed complete. Do not fabricate Beads IDs, use the repository's eventual decision records.
- Update the parallel example so it no longer advertises T001 alongside T002--T003 unless the split above makes the parallel portion  non-security-sensitive.

### Missing enforced security-test gates

#### SEC-002 -- Test-first intent is not represented by complete task dependencies

- **Severity:** MEDIUM (CVSS 5.0)
- **OWASP:** A04:2025 Insecure Design
- **CWE:** CWE-693: Protection Mechanism Failure
- **ASVS:** V14.2.1
- **Evidence:** `tasks.md:31-40,52-64,76-88,100-111,123-132,144-154,162-165,171-184`
- **Historical status:** New task-graph finding, the prior plan review's four design findings are addressed by current contracts/tasks, but their required vector, custody, limit, and event checks are not all hard dependencies of the corresponding implementations.

The task file labels every story's test section “write first,” but many risky implementations depend only on a subset of those tests. Examples include T020 (bootstrap identity/transition) without T016/T017, T026 (enrollment creation) without T024/T025, T034 (handshake crypto) without T033, T035 (frame/nonce/parser) without T033, and T040 (authorization ordering) without T039. The phase prose and `[P]` markers do not prevent an implementation agent from starting as soon as its listed subset is complete. That can bypass negative, race, custody, and redaction gates that are the security evidence for the implementation.

**Exact remediation:**

- Add explicit test prerequisites to each risky implementation: T018→T015,T017, T019→T015,T017, T020→T015,T016,T017, T021→T016,T017, T026→T023,T024,T025, T027→T023,T024, T028→T023,T024,T025, T029→T024, T034→T031,T032,T033, T035→T031,T032,T033, T036→T013,T031,T032,T033, T040→T038,T039, T041→T039,T040, T045→T043,T044, T046→T043,T044, and T047→T044. Preserve the existing foundational and cross-story dependencies as well.
- If the task runner cannot express per-task edges, add a scheduler-enforced “tests complete” checkpoint per story and make every implementation task depend on that checkpoint. Do not rely on headings or prose alone.
- Retain the existing dedicated race/negative/secret-custody test tasks, do not collapse them into a generic test task. The required abuse cases are enumerated and need gating.

## Coverage and secure patterns confirmed

- Authentication and state-bearing channel ordering is covered by T031--T037: exact transcript/encoding, P-256/HKDF/AES-GCM profile, endpoint/epoch binding, nonce/AAD vectors, counter/replay/direction/tag/size faults, and zero dispatch before authorization.
- Authorization and object privacy are covered by T038--T042, including role ceilings, owner/grant/epoch/contract/action checks, pre-serialization filtering, and indistinguishable `object.not_found` outcomes.
- Enrollment abuse controls are covered by T023--T030: Origin/install metadata, expiry uncertainty, one-use consumption, concurrent consumption, wrong identity/replay/malformed proofs, independent five-proof and ten-host-attempt budgets, and stale-key custody recovery.
- Rotation/revocation race controls are covered by T043--T048: replacement-before-epoch, closure/invalidation, idempotency, disconnect independence, unknown transition and uncertain expiry fail-closed behavior.
- Event/key/redaction controls are covered by T008, T017, T025, T030, T049--T050 and the event contracts: bounded metadata/events/buckets, sink-unavailable fail-closed behavior, no private material, and downstream digest/access floors.
- Workspace and dependency sequencing is otherwise sound: T002/T003 are the only root workspace/manifest changes, T004 generates rather than hand-edits `Cargo.lock`, and no downstream Spec 007--016 implementation leaks into the task scope.
- The exact v1 no-fragmentation rule and 1,048,535-byte effective payload bound are explicit in the contracts and represented in T032--T033, the prior SEC-001--SEC-004 plan findings are not reopened.

## Architecture Guard

**Skipped -- unavailable.** No selected Architecture Guard adapter/configuration or host integration was present. The cached catalog entry is not an installed/selected adapter and was not treated as execution evidence. Consequently, no Ponytail boundary-drift, DRY, or repository-hygiene findings are claimed.

## Risk disposition and next steps

**MEDIUM -- conditional proceed.** Resolve SEC-001 and SEC-002 in the task graph before implementation begins. No critical or high findings were identified, and no follow-up security-review task is required solely for severity, if the project workflow requires durable remediation tracking, create TASK-SEC-001 and TASK-SEC-002 through the normal follow-up command rather than editing primary artifacts during this review.

### Proposed durable memory items (not captured)

1. Security-sensitive ADR and dependency decisions must be explicit prerequisites for manifest/lockfile work, not merely prose checkpoints.
2. Story “tests write first” claims must be scheduler-enforced dependencies for all risky security implementations, including negative, race, custody, and redaction tests.

No memory backend was invoked and no security memory was captured.

## Proposed routing row

| specs/006-identity-authorization-secure-channels/security-review-tasks-2026-09-16.md | tasks | 2026-09-16 | MEDIUM | C:0 H:0 M:2 L:0 | A04 |
