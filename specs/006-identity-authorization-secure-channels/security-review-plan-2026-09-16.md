---
document_type: security-review
review_type: plan
assessment_date: 2026-09-16
highest_severity: NONE
critical_count: 0
high_count: 0
medium_count: 0
low_count: 0
informational_count: 4
owasp_categories: A02, A04, A07, A09
---
# Security Plan Review: Identity, Authorization, and Secure Channels

## Executive summary

The Spec 006 security boundary is resolved on integrated HEAD `8d9b61a7`.

Current controls cover:

- cryptographic encodings;
- frame limits;
- custody;
- revocation;
- bounded events; and
- serialized transitions.

SEC-001 through SEC-004 retain their original dispositions. No Spec 006 push blocker remains. Spec 008 owns browser realization. Spec 015 owns durable-history mechanics.

No critical or high findings were identified. This review is not implementation or penetration-test sign-off.

## Scope and evidence reviewed

The review read these artifacts:

- Spec 006 plan.
- Spec 006 specification.
- Spec 006 research.
- Spec 006 data model.
- Spec 006 quickstart.
- Spec 006 contracts and checklists;
- inherited protocol contracts;
- project constitution and roadmap; and
- the prior security-plan report.

The repository-native security memory index is absent. No historical memory finding could be retrieved. No primary artifact was modified.

The active feature follows constitution principles I--V. It follows roadmap constraints C-01 through C-10. Spec 001 is normative for these items:

- route names;
- cryptographic profile;
- wire encodings; and
- frame limits.

The research artifact records that inheritance at `research.md:3-7` and `research.md:19-25`.

## Findings

### SEC-001 -- Nonce construction is not carried into the Spec 006 contract

- **Category:** Design gap / cryptographic interoperability
- **Location:** Original concern: `contracts/secure-channel.md:10-12,14-16`, `research.md:35-39`, and `specs/001-interactive-browser-automation/contracts/daemon-protocol.md:157-163`. Current evidence: `contracts/secure-channel.md:129-149`, `crates/matinee-security/src/channel.rs:736-762,797-826,854-874`, and `crates/matinee-security/vectors/secure-channel-v1.json:37-40`.
- **Severity:** MEDIUM (CVSS 6.5) -- **CWE-327**, OWASP A02:2025, ASVS V2.2.1
- **Status:** **Resolved on integrated HEAD `8d9b61a7`; informational historical finding.**

The original concern was an undefined nonce derivation. The concern included byte layout, direction separation, and counter overflow.

The current contract fixes the 12-byte nonce as `direction_u32_be || counter_u64_be`. Direction 0 identifies client-to-daemon traffic. Direction 1 identifies daemon-to-client traffic. Callers do not supply these inputs. `channel.rs` derives the nonce internally and enforces the exact next receive counter.

It marks `u64::MAX` exhausted rather than wrapping. The committed vector pins the counter-zero client-to-daemon nonce and authenticated-frame bytes.

**Resolution evidence:** The contract, implementation, and vector implement and pin the construction. The original rationale is retained. No remaining Spec 006 acceptance item or push blocker exists.

### SEC-002 -- Frame and plaintext limits lack a fragmentation/relationship rule

- **Category:** Missing control / resource-boundary ambiguity
- **Location:**
  - **Original concern:**
    - `contracts/secure-channel.md:14-16`
    - `data-model.md:24-32`
    - `quickstart.md:14-17`
    - `specs/001-interactive-browser-automation/contracts/daemon-protocol.md:146-171`
  - **Current evidence:**
    - `contracts/secure-channel.md:152-166`
    - `crates/matinee-security/src/channel.rs:25-26,736-817`
    - `crates/matinee-security/src/lib.rs:69-89`
    - `crates/matinee-security/tests/secure_channel_frames.rs:54-78`
- **Severity:** MEDIUM (CVSS 5.8) -- **CWE-400**, OWASP A04:2025, ASVS V12.1.1
- **Status:** **Resolved on integrated HEAD `8d9b61a7`; informational historical finding.**

The original concern was a size mismatch. The encoded-frame limit appeared to be 1 MiB. The decrypted-message limit appeared to be 4 MiB.

v1 has no secure-channel fragmentation or reassembly. One decrypted payload occupies one frame. The size limits are:

- effective plaintext maximum: 1,048,535 bytes, including the kind byte;
- application-data maximum: 1,048,534 bytes; and
- artifact-chunk maximum: 1,000,000 content bytes.

The channel rejects oversized declared frames and payloads before allocation. The focused test round-trips the exact maximum. It rejects the first larger application payload.

**Resolution evidence:** These artifacts establish the no-fragmentation choice:

- the contract;
- the implementation;
- API bounds; and
- the focused test.

The original rationale is retained. The contract chooses option (a). No remaining Spec 006 acceptance item or push blocker exists.

### SEC-003 -- Extension private-key custody and revocation semantics are underspecified

- **Category:** Missing control / credential storage
- **Location:** Original concern: `plan.md:13-16`, `research.md:49-53,67-70`, and `specs/001-interactive-browser-automation/contracts/extension-protocol.md:36-41,181-186`. Current evidence: `contracts/enrollment-bootstrap.md:69-80`, `crates/matinee-security/src/enrollment.rs:687-702,755-811`, and `crates/matinee-security/src/transition.rs:1699-1838,1847-1920`.
- **Severity:** MEDIUM (CVSS 5.6) -- **CWE-922**, OWASP A07:2025, ASVS V2.1.1
- **Status:** **Resolved for Spec 006 on integrated HEAD `8d9b61a7`; browser realization owned by Spec 008.**

The original concern covered private-key custody, stale-key use, and epoch invalidation.

The current contract has these custody and recovery requirements:

- `chrome.storage.local` custody;
- non-exportable WebCrypto where supported;
- no raw PKCS#8 backup;
- fail-closed behavior for unsupported browsers;
- stale-key deletion or quarantine;
- no silent regeneration; and
- fail-closed handling for restore, uninstall, and storage-clear events.

Rust reconnect, rotation, and revocation use current custody, fingerprint, and revocation state. These operations have these effects:

- atomically advance the epoch;
- retire the old credential;
- close channels; and
- invalidate grants and decisions.

No stale registered credential can reconnect or become active through the current Rust boundary.

**Downstream acceptance, not an implementation claim:** Spec 008 must prove its MV3 `chrome.storage.local` and WebCrypto record, capability check, and recovery behavior before extension delivery. The browser package is outside Spec 006 and remains unimplemented here.

### SEC-004 -- Event persistence integrity, retention, and access control are deferred without a security floor

- **Category:** Missing control / logging and privacy boundary
- **Location:**
  - **Original concern:**
    - `contracts/failures-events.md:1-5`
    - `data-model.md:15-16,20-22`
    - `plan.md:15-16,79-81`
    - `roadmap.md:242-252`
  - **Current evidence:**
    - `contracts/failures-events.md:89-128`
    - `crates/matinee-security/src/events.rs:121-174,250-279`
    - `crates/matinee-security/src/lib.rs:559-618`
    - `crates/matinee-security/tests/authorization_privacy.rs:238-378`
- **Severity:** MEDIUM (CVSS 4.8) -- **CWE-345**, OWASP A09:2025, ASVS V7.2.1
- **Status:** **Resolved for Spec 006 on integrated HEAD `8d9b61a7`; durable-history implementation owned by Spec 015.**

The original concern covered persistence integrity, retention, and history authorization. The concern lacked a security floor.

The current boundary has no persistence, read, or export API. Every daemon projection class is authorized before serialization. Required-event sink failure serializes nothing and closes the channel. Events carry state-directory identity.

The module bounds and redacts event data. The contract requires authorization and filtering before export. It requires fail-closed broken-chain handling, retention, and quotas. It forbids trust in an unverifiable chain.

**Downstream acceptance, not an implementation claim:** Spec 015 must implement and mutation-test these controls:

- predecessor and digest verification;
- cross-state-directory partitioning;
- retention and quota enforcement; and
- unauthorized history reads and exports.

Durable-history mechanics are outside Spec 006. This finding is resolved only for its boundary.

## Overall risk and disposition

**NONE -- proceed for Spec 006.** Active findings: 0. SEC-001 through SEC-004 are resolved dispositions. SEC-003 retains a downstream acceptance obligation for Spec 008. SEC-004 retains a downstream acceptance obligation for Spec 015. No Spec 006 push blocker remains.

| document | type | date | overall | counts | categories |
|---|---|---|---|---|---|
| security-review-plan-2026-09-16.md | plan | 2026-09-16 | NONE | C:0 H:0 M:0 L:0 | A02, A04, A07, A09 |

## Confirmed secure patterns

- The single deep security module and private adapter seams preserve C-09 (`plan.md:54-70`, `research.md:11-17`).
- State-bearing routes need mutual authentication and AEAD before product payload. Health is liveness-only (`secure-channel.md:1-10`, `daemon-protocol.md:3-8,123-130`).
- The contract fixes these transcript properties:
  - transcript fields;
  - exact encodings;
  - daemon identity; and
  - version selection.
  It fails closed on downgrade and replay.
- These checks remain separate:
  - loopback;
  - route;
  - subprotocol;
  - browser Origin;
  - store;
  - update;
  - install metadata; and
  - development allowance.
- Authorization checks these values before lookup, serialization, or mutation:
  - capability ceiling;
  - principal kind;
  - owner;
  - grant;
  - contract; and
  - epoch.
  Object-not-found results remain indistinguishable.
- Enrollment has these properties:
  - one use;
  - bounded entropy;
  - bounded expiry;
  - atomic consumption; and
  - rate limiting.
  Rotation and revocation close old channels and invalidate stale state (`enrollment-bootstrap.md:3-9`, `data-model.md:18-20`, `research.md:61-65`).
- These values remain outside failures and events:
  - private-key bytes;
  - cookies;
  - authorization headers;
  - credentials; and
  - payload text.
  Malformed and oversized input is rejected before allocation or dispatch (`failures-events.md:1-5`, `data-model.md:1-3,24-32`).
- The quickstart includes these scenarios:
  - crash;
  - retry;
  - race;
  - Origin;
  - replay;
  - downgrade;
  - malformed input; and
  - redaction.

## Architecture guard

**Skipped -- unavailable.** No selected Architecture Guard adapter, configuration, or host integration exists in this checkout. The cached extension catalog is not execution evidence. This review makes no architecture claim.

| document | type | date | overall | counts | categories |
|---|---|---|---|---|---|
| security-review-plan-2026-09-16.md | plan | 2026-09-16 | NONE | C:0 H:0 M:0 L:0 | A02, A04, A07, A09 |
