---
document_type: security-review
review_type: branch
assessment_date: 2026-09-19
codebase_analyzed: matinee, omp/agent/sc003-completion @ 66a0943b
total_files_analyzed: 37
total_findings: 4
overall_risk: MEDIUM
critical_count: 0
high_count: 0
medium_count: 1
low_count: 3
informational_count: 0
owasp_categories: [A01, A02, A03, A04]
cwe_ids: [CWE-204, CWE-226, CWE-284, CWE-307, CWE-693]
asvs_requirements: [V1.1.1, V2.2.1, V14.2.1]
mitre_techniques: []
---

# Security review report, branch `omp/agent/sc003-completion` vs `main`

## Executive summary

The review followed the branch-scope security workflow using PR-style `main...HEAD` scope. The changed-file detector reported 73 paths at the reviewed head `66a0943b`; the worktree was clean. Analysis covered the complete added `matinee-security` implementation, the added runtime enrollment host with its example and tests, manifests and lockfile, the Spec 006 requirements and four contracts, the prior plan and task security reviews, accepted ADRs, and the security tests and vectors.

No dedicated security constitution exists at the root, in `.specify/memory/`, or in `.specify/extensions/security-review/docs/memory/`, and the security-memory index is absent. The applicable standards were therefore `.specify/memory/constitution.md`, in particular Least Privilege and the security-sensitive-dependency delivery gate, together with Spec 006 and its contracts.

Four branch-attributable findings survive: one Medium governance and supply-chain blocker, and three Low defense-in-depth or API-boundary findings. No Critical or High vulnerability was found, and no currently exposed remote exploit path exists. The branch is not security-clear to merge as-is, solely because SEC-001 violates the mandatory reviewed-dependency boundary. Once `p256` is removed or explicitly accepted, and `libc` documented, the remaining Low findings are non-blocking but should be tracked.

Exploitability tiers:

- **Tier 1**, directly reachable by an untrusted peer through a current executable route.
- **Tier 2**, current production call path, with authentication or local preconditions.
- **Tier 3**, latent public-API or integration hazard, or a defense-in-depth issue, with no current untrusted executable route.

All four findings are Tier 3. That is deliberate: this branch does not wire the secure-channel coordinator or the pairing host to a daemon socket or CLI route.

## Branch diff reviewed

- **Target:** `omp/agent/sc003-completion` @ `66a0943b`
- **Base:** `main`, validated against `origin/main` for remote PR scope
- **Mode:** feature-branch three-dot diff, clean worktree
- **Changed paths:** exactly 73, from `.specify/extensions/review/scripts/bash/detect-changed-files.sh --json`, reconciled against `git diff --name-status origin/main...66a0943b`
- **Security implementation:** all of `crates/matinee-security/**`, manifest, Chrome and WebCrypto fixtures, adapters, authorization, channel, enrollment, events, failures, identity, transition, the public boundary, 20 test and support files, and vectors
- **Runtime integration:** `crates/matinee-runtime/Cargo.toml`, `src/enrollment.rs`, `src/lib.rs`, `examples/enrollment_lifecycle.rs`, `tests/enrollment_boundary.rs`, `tests/enrollment_host_budget.rs`
- **Governance and spec context:** root manifest and lockfile, ADRs 0006 and 0007, all Spec 006 artifacts and contracts. The final 73-path diff holds no `.beads/interactions.jsonl` change, because that file matches `origin/main` byte for byte.

## Reconciliation with the pre-implementation security reviews

| Planned check | Implementation disposition |
|---|---|
| Plan SEC-001, exact nonce layout, direction separation, overflow, AAD vectors | **Performed.** `channel.rs:929-1108` implements direction-separated keys, `direction_u32_be \|\| counter_u64_be`, exhaustion at `u64::MAX`, and AAD over header, context, contract, epoch and direction. Native and WebCrypto vectors include zero, one, maximum, overflow, both directions, and mutations. |
| Plan SEC-002, frame and plaintext relationship, no fragmentation | **Performed.** `channel.rs:21-26,948-1026` enforces the 1 MiB frame and 1,048,535-byte plaintext limit before allocation, and one payload per frame. |
| Plan SEC-003, extension private-key custody, stale-key behaviour, recovery | **Partially performed.** The one-time PKCS#8 key is created and transferred only as channel-bound AES-GCM output; reconnect and rotation quarantine are implemented; a Chrome capability fixture checks supported-or-fail-closed semantics. The MV3 extension, real `chrome.storage.local` lifecycle, and uninstall/profile-restore recovery remain Spec 008. Memory lifetime and zeroization are incomplete, see SEC-002. |
| Plan SEC-004, event integrity, retention, access floor | **Boundary performed; durable mechanics out of scope by design.** Bounded typed events, redaction, pre-serialization authorization, aggregation and required-sink fail-closed behaviour exist. Digest chaining, persistence, retention, quotas and read/export authorization remain Spec 015. |
| Task-review SEC-001, enforce ADR and security preconditions | **Mostly performed.** ADRs 0006 and 0007 are accepted and the task DAG places manifest work behind them. The final manifest nevertheless adds an unreviewed second cryptographic library and `libc`, so the dependency gate is not satisfied, see SEC-001. Task checkboxes are stale and were not treated as implementation truth. |
| Task-review SEC-002, enforce security-test prerequisites | **Performed.** Exact vectors, 1,000 handshake cases, 100,000 malformed cases, race matrices, redaction, event-outage and public-boundary tests exist. Cold verification reports 396 passed and 207 listed `matinee-security` library tests. The two runtime test files are authored but do not execute, already tracked as `matinee-33l`. |

## Findings

### MEDIUM, SEC-001: unreviewed `p256` dependency violates the fixed single-library crypto boundary

- **Location:** `crates/matinee-security/Cargo.toml:10-15`; `crates/matinee-security/src/identity.rs:102-105`; `crates/matinee-security/src/adapters/os_pipe.rs:238-241`; `specs/006-identity-authorization-secure-channels/plan.md:18-35`
- **CVSS:** 4.0 · **Tier:** 3 · **OWASP:** A03:2025 Software Supply Chain Failures · **CWE:** CWE-693 · **ASVS:** V1.1.1, V14.2.1
- **Description:** The accepted plan permits `ring`, `keyring`, `serde` and `uuid`, explicitly rules out a second cryptographic library, and requires a decision record for security-sensitive departures. The manifest adds `p256` with arithmetic support and uses it in two production public-key validation paths. It also adds direct `libc` for close-on-exec handling without adding it to the dependency rationale. Advisory cleanliness does not satisfy the review gate, and two-library validation divergence is itself a risk.
- **Production reachability:** `PublicKey::from_uncompressed` and bootstrap-envelope parsing call `p256` in production. The exposure is governance, supply chain and parser consistency, not proven credential forgery.
- **Remediation:** Remove `p256` in favour of the accepted `ring` boundary, or accept the dependency explicitly with exact version and features, point-validation rationale, ring/`p256` differential tests, update policy and rollback plan. Add `libc` to the non-crypto platform dependency rationale. Re-run pinned cargo-deny afterwards.
- **Task:** TASK-SEC-001

### LOW, SEC-002: one-time private and wrapping-key bytes lack bounded lifetime and zeroization

- **Location:** `crates/matinee-security/src/enrollment.rs:270-276,310-353,413-438,453-483`; `crates/matinee-runtime/src/enrollment.rs:26-69,358-377`
- **CVSS:** 2.8 · **Tier:** 3 · **OWASP:** A02:2025 Cryptographic Failures · **CWE:** CWE-226 · **ASVS:** V2.2.1
- **Description:** `EnrollmentBundle` retains PKCS#8 in `Option<Vec<u8>>`, clones it before encryption, and drops the taken plaintext without clearing it. `AuthenticatedOutputCapability` stores a wrapping key in `[u8; 32]` with no clearing destructor. `EnrollmentHost` retains bundles in a process-lifetime map; expired and uncertain failures neither remove nor expire them, and only successful pairing removes the bundle. The platform credential adapter does clear its retrieved record at `credential_store.rs:137-141`, so the missing treatment is localized to enrollment custody.
- **Production reachability:** `EnrollmentHost::create_pairing` stores the live bundle and `PairingSession::deliver_one_time_key` consumes the key representation. No remote memory-read path exists at this head.
- **Remediation:** Use a non-cloneable zeroizing wrapper for PKCS#8 and the wrapping key, zeroize source buffers immediately after successful sealing, clear on every error and drop path, and remove or expire pending bundles once the typed clock first establishes expiry or revocation.
- **Task:** TASK-SEC-002

### LOW, SEC-003: channel admission narrows but does not close caller-built-principal misuse

- **Location:** `crates/matinee-security/src/channel.rs:95-131`; `crates/matinee-security/src/identity.rs:326-422`; `crates/matinee-security/src/transition.rs:1179-1200,1290-1339`
- **CVSS:** 3.1 · **Tier:** 3 · **OWASP:** A01:2025 Broken Access Control · **CWE:** CWE-284 · **ASVS:** V1.1.1
- **Description:** `register_channel(session, sink)` compares the daemon session's entire authenticated snapshot against the registry under the coordinator lock and rejects a mismatch, which closes the direct forge-a-config-then-use-daemon-operations path. It does not close the broader misuse path: `Principal::new`, `Principal::activate`, `SecurityTransitions::register_principal` and `ServerHandshakeConfig::new` are all public, so one consumer can construct an arbitrary active principal, seed it into the registry, complete the handshake and pass exact-snapshot admission. Raw daemon `ChannelSession::receive`/`send_projection` are crate-private, and public `ChannelSession::send`/`receive_filtered` reject daemon sessions.
- **Production reachability:** Only trusted Rust consumers can assemble the chain, and the current runtime does not. This is an accidental-integration hazard, not external privilege escalation.
- **Remediation:** Make principal activation and registry insertion reachable only through bootstrap, enrollment or rotation transition outcomes, or require a non-forgeable registry-issued token type in `ServerHandshakeConfig`. Keep `register_channel` as the post-handshake race check.
- **Task:** TASK-SEC-003

### LOW, SEC-004: unknown enrollment lookup bypasses the host budget and event path, and exposes a distinct existence result

- **Location:** `crates/matinee-runtime/src/enrollment.rs:358-369,394-427`; `crates/matinee-security/src/enrollment.rs:923-1020`
- **CVSS:** 3.7 · **Tier:** 3 · **OWASP:** A04:2025 Insecure Design · **CWE:** CWE-204, CWE-307 · **ASVS:** V2.2.1
- **Description:** `PairingSession::complete_pairing` queries the runtime pending map and returns `EnrollmentFailure::UnknownEnrollment` before calling `EnrollmentConsumptionService`. An unknown identifier therefore receives a distinct error and never reaches the host-attempt budget or the required rejection event, while a known pending identifier reaches binding and signature work. This contradicts the enrollment contract's requirement that malformed or unknown envelopes count against the host budget, and creates a pending-enrollment existence oracle at the eventual route boundary.
- **Production reachability:** The runtime API contains the path, but no socket or daemon route invokes it yet. The oracle discloses no protected product object and bypasses no proof verification.
- **Remediation:** Move pending-identifier resolution inside the budgeted security boundary, normalize the externally visible unknown, malformed and proof-rejected shapes, record the required redacted fact, and increment only the host budget when no enrollment binds.
- **Task:** TASK-SEC-004

## Explicit cryptographic and failure-path rulings

- **Nonce uniqueness.** Secure-channel nonces are deterministic and unique per directional key: direction is separated in HKDF and in `direction_u32_be || counter_u64_be`. Fresh ECDH and nonces make traffic keys session-specific. Enrollment wrapping uses a fresh random key and prefix with an atomic sequence. No reuse path was found.
- **Counter overflow.** The sender accepts counter `u64::MAX` once then refuses; the receiver accepts it once and marks the channel exhausted. No wrap occurs.
- **AAD binding.** The authenticated frame header, context, selected contract, epoch and direction are bound, and callers cannot select these values after session creation.
- **Transcript completeness.** Client endpoint, selector, epoch, range, nonce, ephemeral key and identity key are signed through the server proof; server selection and range, daemon identity and key, nonce, ephemeral key and connection id are added; the client proof hashes that server input and includes the exact server signature. Direction is bound in HKDF and AAD. No attacker-selectable handshake field is unbound.
- **Signature malleability.** There is no explicit low-S normalization check, and this yields no authentication bypass here: the exact server signature bytes are included in the client proof and the exact client signature bytes are in the HKDF salt, so a malleated signature either mismatches the transcript or produces divergent traffic keys before product payload acceptance. Canonical low-S enforcement is interoperability hardening, not a surviving vulnerability.
- **Constant-time comparison.** ECDSA verification and AEAD tag checking use `ring`. Fingerprints, public keys, identifiers and metadata use ordinary equality; these are non-secret identifiers by contract. No raw enrollment secret is compared in application code.
- **Failure disclosure.** Authorization maps unknown, cross-owner and filtered objects to the same `object.not_found` path before serialization. Protocol-fault classes remain distinguishable but occur before object lookup, and the first invalid frame closes the channel, so no repeatable protected-object oracle exists. Enrollment existence is the exception, reported as SEC-004.
- **Concurrent rollback.** `SecurityTransitions` holds one mutex across complete validation, required-event availability and the infallible in-memory commit; rotation and revocation close channels and invalidate grants and decisions under that guard. Runtime pairing holds the pending-map lock while the service serializes proof consumption. Crash durability remains Spec 007 and Spec 015 responsibility.

## Dependency and advisory status

New direct `matinee-security` dependencies: `ring 0.17`, `p256 0.13` with `arithmetic`, `keyring 3.6.3` with four explicit native and crypto features and no defaults, `serde 1`, `uuid 1`, `libc 0.2`. The runtime adds the path dependency and a forwarded `test-support` feature; runtime dev-dependencies add `ring` and `uuid` for fixtures. `deny.toml` is configured. The pinned invocation `mise x cargo:cargo-deny@0.20.2 -- cargo deny check advisories` completed with **advisories ok**. The bare command's missing mise shim configuration is not a finding.

## Confirmed secure patterns

- Credential-store retrieval clears its temporary secret record before returning.
- Raw framing, transcript assembly, authorization and daemon session operations remain private.
- `register_channel` performs whole-snapshot equality plus live registry epoch and lifecycle checks under one coordinator lock.
- Frame parsing bounds the declared length before allocation; AEAD, counter, epoch, lifecycle, authorization and filtering all precede dispatch.
- Required-event failure prevents protected in-memory transition commits, and bounded failures and events accept no arbitrary untrusted text.
- Rotation and revocation stage every fallible check before the required event, then apply an infallible commit under the coordinator lock.

## Action plan and merge disposition

1. **Block merge on TASK-SEC-001:** restore the accepted dependency boundary, or record an explicit accepted decision for `p256` and `libc` with differential-validation evidence.
2. Track TASK-SEC-002 through TASK-SEC-004 as Low hardening work, fixed before their respective daemon or extension routes become externally reachable.
3. Do not duplicate downstream work: real extension custody is Spec 008, event persistence and integrity are Spec 015, and runtime test discovery is tracked as `matinee-33l`.

**Security merge verdict: not safe to merge as-is, because SEC-001 is a mandatory dependency-review blocker.** No Critical or High exploit blocker exists. Once SEC-001 is resolved, the branch is acceptable to merge with the three Low Tier-3 findings tracked.
