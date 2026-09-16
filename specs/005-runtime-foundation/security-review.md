---
document_type: security-review
review_type: plan
assessment_date: 2026-09-11
codebase_analyzed: matinee/specs/005-runtime-foundation
total_files_analyzed: 8
total_findings: 5
overall_risk: MEDIUM
critical_count: 0
high_count: 0
medium_count: 3
low_count: 2
informational_count: 0
owasp_categories: [A01, A02, A06, A10]
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
  finding_id: "Unique finding ID for cross-referencing and task linkage."
  location: "Artifact or code path and line number supporting the finding."
  owasp_category: "OWASP Top 10 2025 category for this finding."
  cwe: "Common Weakness Enumeration identifier with short name."
  cvss_score: "CVSS v3.1 base score. A design gap without implemented exposure is not scored."
  security_task: "Security task ID for backlog tracking and remediation follow-up."
---

# Security Review: Runtime Foundation Plan

## Executive summary

The plan rejects unknown and lower-trust protected configuration before product-state
mutation. Five design gaps remain. None is an implemented vulnerability, so this review
does not assign CVSS scores. The path-read ordering, resource bounds, and path-race model
must be resolved before task generation.

## Artifacts reviewed

- `spec.md`
- `plan.md`
- `research.md`
- `data-model.md`
- `quickstart.md`
- `contracts/configuration.md`
- `.specify/memory/constitution.md`
- `.specify/memory/roadmap.md`

The security-review memory index and Architecture Guard assets were unavailable in this
project. The review used the repository artifacts and the prior Matinee security
decisions available through project memory.

## Findings

### SEC-001: Project configuration is parsed before containment validation

- **Severity**: Medium
- **Location**: `data-model.md`, Resolution state machine
- **OWASP**: A01:2025 Broken Access Control; A06:2025 Insecure Design
- **CWE**: CWE-22, Improper Limitation of a Pathname to a Restricted Directory
- **Security task**: TASK-SEC-001

The `loading` transition parses every present source. Project containment is checked in
the later `validating` transition. A project-controlled link can therefore make Matinee
read a file outside the project root before rejection.

**Required change**: Resolve and validate the project path before opening it. Reject an
implicit project configuration link that leaves the project root.

### SEC-002: Path identity omits race and platform equivalence rules

- **Severity**: Medium
- **Location**: `research.md`, Root identity and path safety
- **OWASP**: A01:2025 Broken Access Control; A06:2025 Insecure Design
- **CWE**: CWE-178, Improper Handling of Case Sensitivity; CWE-367, Time-of-check
  Time-of-use Race Condition
- **Security task**: TASK-SEC-002

The longest-existing-ancestor algorithm does not state how Windows case behavior,
filesystem identity, or a link change during a read affects root identity.

**Required change**: Define identity by platform. Capture metadata before reading a
project file and verify it after reading. Reject a changed identity. State that an active
same-user filesystem attacker remains outside this local product's threat model.

### SEC-003: Configuration input has no resource bounds

- **Severity**: Medium
- **Location**: `contracts/configuration.md`, Merge result
- **OWASP**: A02:2025 Security Misconfiguration; A10:2025 Mishandling of Exceptional Conditions
- **CWE**: CWE-400, Uncontrolled Resource Consumption
- **Security task**: TASK-SEC-003

A repository can provide an arbitrarily large project configuration file. The plan does
not bound file bytes, key count, nesting, or scalar length before TOML parsing.

**Required change**: Bound each configuration file to 1 MiB, accepted keys to 100, key
nesting to four segments, and text values to 4,096 Unicode scalar values before
normalization.

### SEC-004: Provenance can expose absolute local paths

- **Severity**: Low
- **Location**: `contracts/configuration.md`, Merge result
- **OWASP**: A02:2025 Security Misconfiguration
- **CWE**: CWE-200, Exposure of Sensitive Information to an Unauthorized Actor
- **Security task**: TASK-SEC-004

The contract names file paths as provenance but does not define path redaction. Future
MCP diagnostics could expose a username or private project path.

**Required change**: Render user paths relative to `~` and project paths relative to the
project root. Keep raw paths inside the local runtime.

### SEC-005: Environment-key comparison is undefined on Windows

- **Severity**: Low
- **Location**: `contracts/configuration.md`, Locations
- **OWASP**: A02:2025 Security Misconfiguration
- **CWE**: CWE-178, Improper Handling of Case Sensitivity
- **Security task**: TASK-SEC-005

Windows environment names are case-insensitive. Two differently cased `MATINEE_` names
can map to one configuration key unless the resolver normalizes before duplicate checks.

**Required change**: Normalize environment names with platform semantics before mapping
them to configuration keys. Reject two source names that map to one key.

## Confirmed secure patterns

- Lower-trust sources cannot select protected settings.
- Unknown and duplicate keys fail closed.
- Environment resolution precedes product-state mutation.
- The plan keeps credentials out of configuration files.
- No daemon, MCP, extension, or workflow surface appears as a placeholder.

## Next steps

Resolve TASK-SEC-001 through TASK-SEC-003 before task generation. Carry TASK-SEC-004 and
TASK-SEC-005 into the same remediation pass because both changes affect the configuration
contract.
