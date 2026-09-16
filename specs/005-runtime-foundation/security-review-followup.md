---
document_type: security-review
review_type: followup
assessment_date: 2026-09-11
codebase_analyzed: matinee/specs/005-runtime-foundation
total_files_analyzed: 9
total_findings: 5
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
  overall_risk: "Highest severity tier with active findings, or NONE when no active finding exists."
  critical_count: "Number of Critical findings."
  high_count: "Number of High findings."
  medium_count: "Number of Medium findings."
  low_count: "Number of Low findings."
  informational_count: "Number of Informational findings."
  owasp_categories: "OWASP Top 10 2025 categories that have at least one active finding."
  cwe_ids: "CWE identifiers referenced in this document."
  asvs_requirements: "Verified ASVS requirements mapped to findings."
  mitre_techniques: "Verified MITRE ATT&CK techniques applicable to findings."
  finding_id: "Unique finding identifier for cross-referencing and task linkage."
  location: "Artifact or code path and line number supporting the finding."
  owasp_category: "OWASP Top 10 2025 category for the finding."
  cwe: "Common Weakness Enumeration identifier with short name."
  cvss_score: "CVSS v3.1 base score."
  security_task: "Security task ID for backlog tracking and remediation follow-up."
---

# Security Review Follow-Up: Runtime Foundation

## Executive summary

The approved remediation closes all five design gaps from `security-review.md`. The
specification and plan now define the required controls. Implementation tasks must prove
each control before the feature can pass acceptance.

## Inputs reviewed

- `security-review.md`
- `spec.md`
- `plan.md`
- `research.md`
- `data-model.md`
- `contracts/configuration.md`
- `quickstart.md`
- `.specify/memory/constitution.md`
- `.specify/memory/roadmap.md`

## Resolution decisions

| Finding | Decision | Design evidence |
|---|---|---|
| SEC-001 | Implement now | The resolution state machine validates project containment before read. |
| SEC-002 | Implement now | Path identity uses platform file identity and comparison behavior; snapshots detect changes. |
| SEC-003 | Implement now | The specification and contract define byte, key, nesting, and text limits. |
| SEC-004 | Implement now | Diagnostic provenance replaces the user root with `~` and the project root with `.`. |
| SEC-005 | Implement now | Environment names use platform comparison before key mapping and duplicate detection. |

## Backlog-ready security tasks

| Task ID | Title | Severity | Type | Source Finding | Depends On | Acceptance Criteria |
|---|---|---|---|---|---|---|
| TASK-SEC-001 | Validate project configuration before read | Medium | Implement | SEC-001 | Path identity | An escaped or implicit linked file is rejected without reading its bytes. |
| TASK-SEC-002 | Enforce platform path identity snapshots | Medium | Implement | SEC-002 | Platform adapter | Platform-equivalent roots compare equal and a changed file snapshot fails resolution. |
| TASK-SEC-003 | Bound configuration resource use | Medium | Implement | SEC-003 | TOML loader | Every byte, key, nesting, and text limit passes at the boundary and fails one unit above it. |
| TASK-SEC-004 | Redact provenance paths | Low | Implement | SEC-004 | Resolved settings | No diagnostic projection contains a raw user or project absolute path. |
| TASK-SEC-005 | Normalize environment-name identity | Low | Implement | SEC-005 | Environment loader | Windows case aliases fail as duplicate keys before merge. |

## Technical debt

None.

## Confirmed secure patterns

- Configuration rejects unknown and duplicate keys.
- Lower-trust sources cannot select protected settings.
- Configuration accepts no credentials or browser-profile secrets.
- Resolution mutates no product state.
- The task plan retains every reviewed security control.
