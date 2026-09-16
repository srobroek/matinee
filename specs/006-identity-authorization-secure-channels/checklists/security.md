# Security Requirements Checklist: Identity, Authorization, and Secure Channels

**Purpose**: Reviewer-owned requirements-quality gate for trust boundaries, authorization, secrecy, and failure semantics
**Created**: 2026-09-16
**Feature**: [spec.md](../spec.md)

**Review Ownership**: This checklist evaluates whether security requirements are complete, clear, consistent, and measurable. `[x]` means the requirements-quality criterion is satisfied, not that implementation is complete.

## Trust and Secrecy

- [x] CHK001 Does the spec identify every principal kind, identity material, private-key custody boundary, and prohibited disclosure surface? [Completeness, Spec §Key Entities, FR-001--FR-006]
- [x] CHK002 Are bootstrap, enrollment, credential-store mismatch, and secret-redaction requirements explicit for both success and failure? [Coverage, Spec §User Stories 1--2, FR-003--FR-009]
- [x] CHK003 Is the accepted local-compromise boundary stated without implying protection against a replaced extension runtime or local-account attacker? [Clarity, Spec §Accepted-Risk Boundary]
- [x] CHK004 Are origin, install metadata, loopback, route, and subprotocol checks defined as mandatory trust conditions? [Completeness, Spec §FR-018--FR-019]

## Authorization and Privacy

- [x] CHK005 Does the spec define authorization inputs (role, capability, epoch, owner, grant, action, contract) before every disclosure and mutation? [Completeness, Spec §FR-020--FR-023]
- [x] CHK006 Is the object-existence privacy rule unambiguous for unknown, cross-owner, filtered, and unauthorized identifiers? [Clarity, Spec §FR-022--FR-023]
- [x] CHK007 Are role ceilings and administrator-only boundaries consistent across native administrators, MCP clients, and extensions? [Consistency, Spec §User Story 4, FR-021]
- [x] CHK008 Are rotation and revocation requirements complete for live channels, stale credentials, grants, pending decisions, retries, and audit outcomes? [Coverage, Spec §User Story 5, FR-024--FR-026]

## Abuse and Failure Semantics

- [x] CHK009 Does the spec cover replay, downgrade, malformed input, wrong-direction frames, counter errors, size limits, and rate limits with fail-closed outcomes? [Coverage, Spec §Edge Cases, FR-009, FR-012--FR-017, FR-032]
- [x] CHK010 Are security failures bounded, redacted, classifiable, and prevented from disclosing protected object existence? [Measurability, Spec §FR-027--FR-029]
- [x] CHK011 Are concurrency boundaries defined for handshake, enrollment consumption, authorization, rotation, and revocation races? [Completeness, Spec §FR-026, Edge Cases]
- [x] CHK012 Can every security claim be evaluated using the numbered success criteria without requiring an implementation choice? [Acceptance Criteria, Spec §SC-001--SC-009]

## Notes

- All 12 criteria pass against the current specification after the requirements repair pass.
- This checklist is not an implementation or penetration-test plan.
