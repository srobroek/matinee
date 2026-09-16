---
document_type: security-review
review_type: plan
assessment_date: 2026-09-16
codebase_analyzed: matinee/specs/006-identity-authorization-secure-channels
total_files_analyzed: 17
total_findings: 4
overall_risk: MEDIUM
critical_count: 0
high_count: 0
medium_count: 4
low_count: 0
informational_count: 0
owasp_categories: [A02, A04, A07, A09]
cwe_ids: [CWE-327, CWE-345, CWE-400, CWE-922]
asvs_requirements: [V2.1.1, V2.2.1, V3.2.1, V4.1.1, V7.2.1]
mitre_techniques: [T1499, T1552.001]
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

# Security Plan Review: Identity, Authorization, and Secure Channels

## Executive summary

The Spec 006 plan has a strong security shape: one deep security boundary, private platform adapters, mutual authentication before state-bearing work, fixed cryptographic encodings, explicit origin/endpoint checks, capability ceilings, serialized lifecycle transitions, bounded failures, and redacted events. The Spec 001 contracts materially reinforce those controls. Four medium-severity design gaps remain before implementation: the feature plan does not carry forward the exact Spec 001 nonce construction, the frame/plaintext limits are inconsistent without an explicit fragmentation rule, extension credential-at-rest semantics are underspecified, and security-event persistence/access integrity is not bounded at this boundary. These findings concern design. Each should be resolved in the plan/contracts before task generation.

No critical or high findings were identified. This review does not constitute implementation or penetration-test sign-off.

## Scope and evidence reviewed

Seventeen artifacts were read: the Spec 006 plan, specification, research, data model, quickstart, four contracts, three checklists, Spec 001 daemon and extension protocol contracts, `.specify/memory/constitution.md`, `.specify/memory/roadmap.md`, and the prior security-plan report used for format/history comparison. The repository-native security memory index and memory directory required by the security-review extension are absent in this checkout, no historical memory finding could therefore be retrieved. No primary artifact was modified.

The active feature is governed by Constitution principles I--V and roadmap constraints C-01 through C-10. Spec 001 is treated as normative for route names, cryptographic profile, wire encodings, and frame limits, as required by `research.md:3-7` and `research.md:19-25`.

## Findings

### SEC-001 -- Nonce construction is not carried into the Spec 006 contract

- **Category:** Design gap / cryptographic interoperability
- **Location:** `specs/006-identity-authorization-secure-channels/contracts/secure-channel.md:10-12,14-16`, `specs/006-identity-authorization-secure-channels/research.md:35-39`, normative baseline `specs/001-interactive-browser-automation/contracts/daemon-protocol.md:157-163`
- **Severity:** MEDIUM (CVSS 6.5) -- **CWE-327: Use of a Broken or Risky Cryptographic Algorithm**, OWASP A02:2025 Cryptographic Failures, ASVS V2.2.1
- **Status:** New design gap, no repository security-memory record was available to reconcile it.

Spec 006 says that the AES-GCM nonce is “derived from the per-direction base nonce and counter,” but does not define the byte-level derivation. The inherited Spec 001 contract instead specifies a concrete 12-byte nonce (`direction` plus counter). The plan also says the fixed profile is inherited while introducing “base nonce” terminology. If Rust and WebCrypto implement different derivations, valid vectors can fail, worse, an unsafe implementation could reuse a nonce under a key. The contract needs one normative construction, including counter encoding, direction domain separation, and overflow behavior, and vectors must assert the resulting nonce bytes rather than only successful decryption.

**Remediation:** Copy the exact Spec 001 nonce construction into `secure-channel.md` or explicitly supersede it with a versioned protocol decision. Require nonce-byte vectors for counters 1, the maximum accepted counter, and overflow, for both directions. Keep the construction outside caller discretion. No follow-up task was created in this review.

### SEC-002 -- Frame and plaintext limits lack a fragmentation/relationship rule

- **Category:** Missing control / resource-boundary ambiguity
- **Location:** `specs/006-identity-authorization-secure-channels/contracts/secure-channel.md:14-16`, `specs/006-identity-authorization-secure-channels/data-model.md:24-32`, `specs/006-identity-authorization-secure-channels/quickstart.md:14-17`, normative baseline `specs/001-interactive-browser-automation/contracts/daemon-protocol.md:146-171`
- **Severity:** MEDIUM (CVSS 5.8) -- **CWE-400: Uncontrolled Resource Consumption**, OWASP A04:2025 Insecure Design, ASVS V12.1.1
- **Status:** New design gap, the checklists mark limits complete, but the plan-level contract remains ambiguous.

A single encoded frame is capped at 1 MiB while a decrypted message is capped at 4 MiB. The Spec 006 contract does not say whether a message may span frames, how fragments are identified and ordered, or whether the 4 MiB value applies only to one decrypted frame. The existing Spec 001 contract has an artifact-chunk protocol, stream limits, and per-principal in-flight bounds, but those rules are not imported into the new frame contract. Different implementations may reject valid 4 MiB messages, buffer four frames without a bounded aggregate, or accidentally permit an unbounded continuation queue.

**Remediation:** Choose and specify one of: (a) one message per frame, making the effective plaintext maximum no larger than the frame budget, or (b) a bounded fragmentation protocol with authenticated stream/message ID, sequence, total length, aggregate allocation cap, timeout, cancellation, and per-principal in-flight quota. Make quickstart mutations cover aggregate-over-limit, missing/duplicate fragments, gaps, and disconnect cleanup. No follow-up task was created in this review.

### SEC-003 -- Extension private-key custody and revocation semantics are underspecified

- **Category:** Missing control / credential storage
- **Location:** `specs/006-identity-authorization-secure-channels/plan.md:13-16`, `specs/006-identity-authorization-secure-channels/research.md:49-53,67-70`, `specs/001-interactive-browser-automation/contracts/extension-protocol.md:36-41,181-186`
- **Severity:** MEDIUM (CVSS 5.6) -- **CWE-922: Insecure Storage of Sensitive Information**, OWASP A07:2025 Identification and Authentication Failures, ASVS V2.1.1
- **Status:** Accepted platform-confidentiality assumption is documented, but the implementation contract is incomplete rather than closed.

The plan correctly prohibits daemon persistence of private keys and places the long-term extension key in `chrome.storage.local`. It does not state the key's extractability/WebCrypto usage policy, storage namespace isolation, migration/rollback behavior, or deletion/invalid-use behavior after rotation, revocation, uninstall, or profile restore. The extension protocol says the service worker persists identity and pinned daemon data in the same storage area and discards one-time material, but does not define how stale long-term keys are prevented from being used after a revoked epoch. A compromised or buggy extension component could otherwise retain or re-use a credential while the daemon assumes revocation is complete.

**Remediation:** Specify the extension key as a non-exportable WebCrypto private key where supported, define the exact storage record and access boundary, delete/quarantine stale keys on revocation/rotation, and require every reconnect to prove the current epoch. Define the explicit fail-closed fallback if the browser cannot provide the required key semantics, do not silently downgrade to raw PKCS#8 persistence. Add recovery tests for service-worker restart, profile restore, uninstall/reinstall, rotation, and revocation. This remains bounded by the documented replaced-runtime/local-account accepted-risk boundary, the finding is about deterministic implementation semantics, not a demand to solve that out-of-scope threat.

### SEC-004 -- Event persistence integrity, retention, and access control are deferred without a security floor

- **Category:** Missing control / logging and privacy boundary
- **Location:** `specs/006-identity-authorization-secure-channels/contracts/failures-events.md:1-5`, `specs/006-identity-authorization-secure-channels/data-model.md:15-16,20-22`, `specs/006-identity-authorization-secure-channels/plan.md:15-16,79-81`, roadmap `roadmap.md:242-252`
- **Severity:** MEDIUM (CVSS 4.8) -- **CWE-345: Insufficient Verification of Data Authenticity**, OWASP A09:2025 Security Logging and Alerting Failures, ASVS V7.2.1
- **Status:** New design gap, ownership is intentionally deferred to Spec 007/015, but no minimum security contract is stated here.

The security module emits redacted facts and the daemon/store persists them append-only with a digest predecessor. The plan does not specify digest-chain verification, behavior on a broken chain, event authorization at read/export boundaries, retention/deletion limits, or whether event metadata (principal IDs, connection IDs, endpoint, reason class, timestamps) is itself sensitive. Because the roadmap assigns audit/retention to Spec 015 and persistence to Spec 007, an implementation can satisfy the current wording while exposing unauthorized security-event history, retaining it indefinitely, or accepting silently tampered records. Digest chaining without a verification/failure policy is integrity decoration rather than an enforceable control.

**Remediation:** Add a minimum cross-spec contract: events are authorized and filtered before serialization/export, bounded by retention and size quotas, chain verification failure is surfaced as a safe diagnostic and never treated as trustworthy history, and the chain is scoped to a state-directory identity. Specify which metadata is safe for each principal and require negative tests for unauthorized history reads and tampered predecessor/digest. Leave detailed schema and storage ownership to Specs 007/015, but retain these security floors in Spec 006. No follow-up task was created in this review.

## Confirmed secure patterns

- The single deep security module and private adapter seams preserve C-09 and prevent callers from handling key material or duplicating authorization (`plan.md:54-70`, `research.md:11-17`).
- State-bearing routes require mutual authentication and AEAD before product payload, health is explicitly liveness-only (`secure-channel.md:1-10`, `daemon-protocol.md:3-8,123-130`).
- Fixed transcript fields, exact UTF-8/length/UUID/key/signature encodings, pinned daemon identity, strict version selection, and fail-closed downgrade/replay behavior are specified (`secure-channel.md:5-12`, `research.md:19-33`, `daemon-protocol.md:50-85`).
- Loopback, route, subprotocol, browser Origin, store/update/install metadata, and explicit development allowance are separate checks, the replaced-runtime boundary is  documented as accepted risk (`research.md:55-59`, `extension-protocol.md:3-21`).
- Authorization checks capability ceiling, principal kind, owner, grant, contract, and epoch before lookup serialization or mutation, with indistinguishable object-not-found results (`authorization.md:1-9`, `data-model.md:18-22`, `daemon-protocol.md:132-144`).
- Enrollment is one-use, entropy-bounded, expiry-bounded, atomically consumed, and rate-limited, rotation/revocation close old channels and invalidate stale state (`enrollment-bootstrap.md:3-9`, `data-model.md:18-20`, `research.md:61-65`).
- Private-key bytes, cookies, authorization headers, credentials, and payload text are explicitly outside failures/events, and malformed/oversized input is rejected before allocation or dispatch (`failures-events.md:1-5`, `data-model.md:1-3,24-32`).
- The quickstart includes crash, retry, race, origin, replay, downgrade, malformed-input, and redaction scenarios, making the major security claims testable without real credentials (`quickstart.md:1-9,19-35`).

## Architecture Guard

**Skipped -- unavailable.** The checkout contains no selected Architecture Guard adapter/configuration or host integration that can resolve the Ponytail contract and run an artifact review. The cached extension catalog mentioning an Architecture Guard package is not an installed/selected adapter and was not treated as execution evidence. No architecture findings are claimed from this skipped integration.

## Overall risk and disposition

**MEDIUM -- conditional proceed only after the four design gaps are resolved in the plan/contracts.** No primary artifacts, tasks, Beads records, or source files were changed. Follow-up task creation is intentionally deferred as requested. The existing checklist PASS marks requirements quality. It does not close these implementation-facing ambiguities.

## Proposed durable memory items (not captured)

1. Spec 006 must carry one exact, vector-tested AES-GCM nonce construction from the normative Spec 001 profile, “derived from base nonce and counter” is insufficient.
2. A frame/plaintext size pair requires an explicit one-frame rule or authenticated bounded fragmentation protocol, otherwise resource safety and interoperability are implementation-dependent.
3. Extension credential custody needs non-exportability, stale-key deletion/epoch enforcement, and fail-closed browser fallback semantics even when platform storage confidentiality is accepted.
4. Digest-chained security events require verification-failure, authorization/filtering, retention, and quota floors before persistence ownership is delegated to later specifications.

These items were proposed only, no memory backend was invoked and no durable security memory was captured without authorization.

## Routing row for `.specify/extensions/security-review/docs/memory/INDEX.md`

| specs/006-identity-authorization-secure-channels/security-review-plan-2026-09-16.md | plan | 2026-09-16 | MEDIUM | C:0 H:0 M:4 L:0 | A02,A04,A07,A09 |
