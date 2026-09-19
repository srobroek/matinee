# Protocol Requirements Checklist: Identity, Authorization, and Secure Channels

**Purpose**: Reviewer-owned requirements-quality gate for channel negotiation, framing, compatibility, and cross-peer contracts
**Created**: 2026-09-16
**Feature**: [spec.md](../spec.md)

**Review Ownership**: This checklist evaluates requirements quality only. `[x]` means the criterion is specified clearly and completely; it does not mean implementation is complete.

## Negotiation and Encoding

- [x] CHK001 Is the handshake context, peer identity proof, contract selection, endpoint binding, epoch binding, and key-agreement outcome defined without alternative interpretations? [Clarity, Spec §FR-010--FR-012]
- [x] CHK002 Are field encodings, lengths, byte order, key formats, signature formats, and invalid alternatives explicit? [Completeness, Spec §FR-013]
- [x] CHK003 Are deterministic vectors and cross-peer conformance expectations stated for both valid and mutation-at-boundary cases? [Traceability, Spec §FR-030, SC-003]
- [x] CHK004 Are disjoint ranges, downgrade, substitution, stale identity, stale epoch, wrong endpoint, and cross-version replay covered as distinct compatibility failures? [Coverage, Spec §User Story 3, FR-012, FR-032]

## Framing and Limits

- [x] CHK005 Does the spec define frame fields, associated-data binding, direction, counter progression, and channel-close behavior for every counter violation? [Completeness, Spec §FR-015--FR-016]
- [x] CHK006 Are frame, decrypted-message, malformed-input, and allocation limits measurable and fail-closed? [Measurability, Spec §FR-017, SC-007]
- [x] CHK007 Are liveness-only and state-bearing routes distinguished, including authentication and disclosure rules for each? [Consistency, Spec §FR-014, FR-018]

## Compatibility and Lifecycle

- [x] CHK008 Are versioned contracts, expected routes/subprotocols, origin checks, and development-versus-production extension identity rules consistent with the stated scope? [Consistency, Spec §FR-018--FR-019]
- [x] CHK009 Does the protocol specify how disconnect, rotation, revocation, and stale epochs affect connections without conflating connection lifetime with durable work? [Coverage, Spec §FR-024--FR-026, FR-031]
- [x] CHK010 Can every protocol requirement be mapped to a measurable acceptance outcome for success, rejection, confidentiality, or bounded failure? [Acceptance Criteria, Spec §SC-003, SC-007--SC-009]

## Notes

- All 10 criteria pass against the current specification after the protocol requirements repair pass.
- This checklist reviews requirements quality. It does not serve as a test plan or implementation checklist.
