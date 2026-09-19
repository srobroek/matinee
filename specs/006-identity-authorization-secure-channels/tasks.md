---

description: "Dependency-ordered implementation tasks for Spec 006"
---

# Tasks: Identity, Authorization, and Secure Channels

**Input**: Design documents from `/specs/006-identity-authorization-secure-channels/`

**Prerequisites**: `plan.md`, `spec.md`, `research.md`, `data-model.md`, `contracts/`, `quickstart.md`, and `.specify/memory/constitution.md`

**Scope**: This plan creates only the private `crates/matinee-security` crate and its tests/vectors. Daemon lifecycle and persistence (Spec 007), extension package (Spec 008), clock (Spec 009), product integrations (Specs 010--014), audit persistence (Spec 015), and packaging (Spec 016) are downstream and are not implementation tasks here.

## Phase 1: Setup (Workspace and Security Preconditions)

**Purpose**: Establish the crate boundary and record decisions required before security implementation.

- [ ] T001 Create the `adr-5` Beads decision bead for the fixed reviewed security profile, linking plan/spec evidence and recording the accepted protocol/security boundary, do not claim completion if `bd` is unavailable, in `specs/006-identity-authorization-secure-channels/tasks.md`
- [ ] T002 Create the `adr-6` Beads decision bead for the `keyring 3.6.3`/Rust 1.85 dependency departure, recording security review and rollback rationale, do not fabricate a bead ID when creation is blocked, in `specs/006-identity-authorization-secure-channels/tasks.md` (depends on T001)
- [ ] T003 Validate and accept `adr-5` and `adr-6` through the repository decision workflow, recording each accepted bead ID/status as a prerequisite, if ADR delivery is blocked, leave the task blocked rather than asserting acceptance, in `specs/006-identity-authorization-secure-channels/tasks.md` (depends on T001, T002)
- [X] T004 Add only `crates/matinee-security` to the virtual workspace members, while leaving `crates/matinee-cli` and `crates/matinee-runtime` unchanged in `Cargo.toml` (depends on T003)
- [X] T005 Create the Rust 2024 private crate manifest with Rust 1.85-compatible direct dependencies `ring = "0.17.x"`, `keyring = "3.6.3"` with `default-features = false` and features `apple-native`, `windows-native`, `linux-native-sync-persistent`, `crypto-rust`, `serde = "1.x"` with `derive`, and `uuid = "1.x"` with `v7,serde`, in `crates/matinee-security/Cargo.toml` (depends on T003, T004)
- [X] T006 Generate the workspace dependency lockfile with Cargo after T004--T005, never by hand-editing `Cargo.lock` (depends on T004, T005)

---

## Phase 2: Foundational (Blocking Security Boundary)

**Purpose**: Build shared typed primitives, private seams, failure/event contracts, the required-event fail-closed control, and evidence fixtures before story implementation.

**CRITICAL**: No user-story implementation may begin until this phase is complete and ADR decision beads `adr-5`/`adr-6` are created and accepted in T001--T003.

- [X] T007 [P] Define the private crate module layout and public exports for `ChannelSession`, `SessionInput`, `AuthorizedInput`, `AuthorizedOutput`, and closed `SecurityCommand` only, in `crates/matinee-security/src/lib.rs` (depends on T003, T006)
- [X] T008 [P] Define typed identity, principal, credential-reference, connection, capability, grant, enrollment, rotation, revocation, transition-input, and expiry-result entities with the exact lifecycle and secret-field invariants in `crates/matinee-security/src/identity.rs` (depends on T003, T006)
- [X] T009 [P] Define bounded stable failure codes, boundary values, safe-next-action values, and redaction invariants for authentication, authorization, compatibility, malformed, origin, replay, rate-limit, credential-store, resource-limit, stale-epoch, revocation, transition, and event-sink failures in `crates/matinee-security/src/failures.rs` (depends on T003, T006)
- [X] T010 [P] Define bounded redacted `SecurityEvent`, `SecurityEventSinkResult`, and private aggregation state (2,048-byte event, 8 metadata entries, 32-byte keys, 128-byte values, 512-byte metadata, 64 buckets, saturating count 255) in `crates/matinee-security/src/events.rs` (depends on T003, T006)
- [X] T011 [P] Define the only platform seams as private `CredentialStore` and inherited `OsPipe` adapters, including missing, mismatch, duplicate, and unavailable outcomes, in `crates/matinee-security/src/adapters/credential_store.rs` and `crates/matinee-security/src/adapters/os_pipe.rs`, do not define clock, persistence, Origin, or crypto traits (depends on T003, T006)
- [X] T012 [P] Add internal-only fake credential-store and inherited-OS-pipe adapters for deterministic tests, plus an internal-only fake `SecurityEventSink` that can report accepted, aggregated, and unavailable results, with no production export or plaintext fallback, in `crates/matinee-security/tests/support/fakes.rs` (depends on T010, T011)
- [X] T013 [P] Specify shared vector serialization and evidence-record schema for valid bytes plus one mutation at every field boundary, nonce/AAD counters 0/1/`u64::MAX`/overflow, pre-allocation rejection, maximum allocation, channel state, dispatch count, event fields, and secret scan, in `crates/matinee-security/vectors/README.txt` (depends on T003, T006)
- [X] T014 [P] Create deterministic native/WebCrypto handshake, encoding, frame, nonce, AAD, and failure vectors including DER/compressed-key/length/UTF-8/replay/direction/counter/tag/oversize mutations in `crates/matinee-security/vectors/secure-channel-v1.json` (depends on T013)
- [X] T015 [P] Implement the owned Node WebCrypto `.mjs` peer fixture that loads `vectors/secure-channel-v1.json`, exercises every valid and boundary-mutated vector with byte-exact encodings, and writes pass/fail evidence records in `crates/matinee-security/fixtures/webcrypto/secure-channel-vectors.mjs` (depends on T013, T014)
- [X] T016 [P] Implement the minimal Chrome extension capability fixture (not the downstream product package) to exercise `chrome.storage.local` persistence and non-extractable WebCrypto key behavior, asserting supported semantics or an explicit fail-closed unsupported outcome, in `crates/matinee-security/fixtures/chrome-capability/manifest.json` and `crates/matinee-security/fixtures/chrome-capability/capability.mjs` (depends on T013, T014)
- [X] T017 [P] Write foundational type, failure redaction, event-bound, adapter-seam, and public-boundary contract tests that prove raw frame/auth/authorization functions are not public and secrets cannot enter failures/events, in `crates/matinee-security/tests/foundation_contract.rs` (depends on T007--T012)
- [X] T018 [P] Write the reusable 100,000-case malformed/oversized corpus harness and evidence assertions (zero dispatch, bounded allocation, channel state, event fields, secret scan, no latency threshold) in `crates/matinee-security/tests/malformed_corpus.rs` (depends on T007--T014)
- [X] T019 Write the cross-story security-event contract tests before any story mutation implementation: required emission for every bootstrap, enrollment, authentication, authorization, rotation, revocation, replay, downgrade, malformed, counter, rate-limit, and cryptographic-failure event class, bounded aggregation (2,048-byte redacted events, 8 metadata entries, 64 buckets, saturating count 255), redaction of secrets and protected identifiers from every event and event-sink failure, and required-sink-unavailable behavior that fails closed, emits `event_sink.unavailable`, and leaves no partial protected mutation committed, in `crates/matinee-security/tests/events_contract.rs`. (depends on T009, T010, T012, T017)
- [X] T020 Implement the private `SecurityEventSink` callback, `SecurityEventSinkResult` handling, bounded aggregation state, and the reusable required-event availability gate that every protected mutation must call before committing state so unavailable required delivery rolls back and fails closed atomically, in `crates/matinee-security/src/events.rs` (depends on T010, T017, T019)

**Checkpoint**: Shared types, private seams, vector corpus, bounded failures/events, the malformed-corpus harness, the cross-story event contract tests, and the required-event fail-closed availability gate are ready before any protected mutation is authored, no downstream integration traits or implementations exist.

---

## Phase 3: User Story 1 - Bootstrap a Trusted Local Principal (Priority: P1)

**Goal**: Bootstrap exactly one daemon identity and native administrator over inherited anonymous OS pipes with crash-safe idempotency and credential-store custody.

**Independent Test**: A disposable fixture covers clean success, 100 crash injections before/after commit, duplicate and mismatched identity, missing/mismatched credential, daemon restart, and secret scanning, every successful run has one daemon identity/principal and no private bytes in pipe captures or durable application state.

### Tests for User Story 1 (write first)

- [X] T021 [P] [US1] Add bootstrap contract fixtures for inherited Unix/Windows pipe envelopes, fresh nonce, state-directory identity, daemon identity, bootstrap ID, and native public key in `crates/matinee-security/tests/bootstrap_contract.rs` (depends on T008, T011, T012, T017)
- [X] T022 [P] [US1] Add bootstrap failure and crash-recovery tests for before-commit, after-commit, duplicate, mismatched identity, missing credential, mismatched credential, malformed envelope, and daemon restart in `crates/matinee-security/tests/bootstrap_recovery.rs` (depends on T008, T009, T011, T012, T017)
- [X] T023 [US1] Add bootstrap secret-custody assertions proving private keys never occur in `crates/matinee-security/tests/bootstrap_contract.rs` captures, failures, events, or durable application payloads (depends on T009, T010, T017, T021)

### Implementation for User Story 1

- [X] T024 [US1] Implement platform credential lookup and binding to selected principal/state-directory identity, with missing, mismatch, duplicate, and unavailable outcomes, in `crates/matinee-security/src/adapters/credential_store.rs` (depends on T011, T017, T018, T021, T022, T023)
- [X] T025 [US1] Implement inherited anonymous OS-pipe bootstrap envelope parsing and bounded validation with close-on-exec/explicit-handle semantics, in `crates/matinee-security/src/adapters/os_pipe.rs` (depends on T011, T017, T018, T021, T022, T023)
- [X] T026 [US1] Implement daemon/native identity creation, lowercase-hex SHA-256 fingerprinting over exact 65-byte public keys, and atomic staged-to-active bootstrap command handling that calls the T020 required-event availability gate before the staged-to-active commit and emits the required bootstrap/identity events, in `crates/matinee-security/src/identity.rs` and `crates/matinee-security/src/transition.rs` (depends on T008, T020, T024, T025)
- [X] T027 [US1] Implement same-bootstrap retry convergence and post-commit recovery without duplicate/orphan registration, plus different-identity no-mutation failure, checking required-event sink availability before each commit so unavailable delivery leaves no mutation, in `crates/matinee-security/src/transition.rs` (depends on T020, T022, T026)
- [X] T028 [US1] Complete the independent bootstrap fixture and evidence assertions for SC-001/SC-002 and FR-002--FR-005, including the bootstrap event classes and sink-unavailable rollback outcomes, in `crates/matinee-security/tests/bootstrap_recovery.rs` (depends on T019, T023, T027)

**Checkpoint**: US1 is independently testable without loopback, daemon lifecycle, or persistence implementation, and its bootstrap commit is already gated by the required-event fail-closed control.

---

## Phase 4: User Story 2 - Enroll and Reconnect a Browser Extension (Priority: P1)

**Goal**: Create and atomically consume a ten-minute, one-use, 256-bit enrollment bound to Origin/install metadata while preserving one-time PKCS#8 custody and long-term key fail-closed storage semantics as a peer contract.

**Independent Test**: Pairing fixtures cover valid, wrong Origin, wrong extension/install metadata, expired, consumed, revoked, replayed, wrong identity, malformed, concurrent, and rate-limited attempts, only valid first-use proofs create a principal and no private key appears outside authenticated encrypted native-channel transient custody.

### Tests for User Story 2 (write first)

- [X] T029 [P] [US2] Add enrollment/bootstrap contract fixtures for 32-byte secret entropy, ten-minute expiry input, pinned daemon/endpoint, expected Origin/install metadata, one-time proof, and atomic long-term public-key registration in `crates/matinee-security/tests/enrollment_contract.rs` (depends on T008, T009, T012, T017)
- [X] T030 [P] [US2] Add enrollment negative/race tests for wrong Origin/identity/metadata, expired/uncertain, consumed/revoked/replayed, malformed proof, concurrent consumption, missing credential, and five-proof/ten-host-attempt budgets in `crates/matinee-security/tests/enrollment_failures.rs` (depends on T009, T012, T017)
- [X] T031 [P] [US2] Add custody/redaction tests proving the one-time PKCS#8 key appears only in the authenticated encrypted native-channel bundle operation, while bootstrap/loopback captures, durable records, logs, diagnostics, status, and failures contain no private bytes in `crates/matinee-security/tests/enrollment_custody.rs` (depends on T010, T012, T017)

### Implementation for User Story 2

- [X] T032 [US2] Implement closed enrollment creation and bounded bundle fields, expected Origin/install metadata, daemon binding, one-time public-key fingerprint, and typed expiry/uncertainty handling in `crates/matinee-security/src/enrollment.rs` (depends on T008, T009, T018, T029, T030, T031)
- [X] T033 [US2] Implement private Origin/endpoint/install metadata validation and fail-closed development-identity allowance rules in `crates/matinee-security/src/enrollment.rs` (depends on T018, T029, T030, T031)
- [X] T034 [US2] Implement atomic one-use proof consumption and long-term principal registration with transient PKCS#8 transfer confined to authenticated encrypted native-channel output, calling the T020 required-event availability gate before consumption/registration commits and emitting the required enrollment events, in `crates/matinee-security/src/enrollment.rs` (depends on T019, T020, T031, T032, T033)
- [X] T035 [US2] Implement independent host `(state-directory, loopback address)` ten-failure/60-second budget and per-enrollment five-failure budget under one transition boundary, including channel closure, bounded `rate_limited` action, and required rate-limit event emission with availability checked before the budget-state mutation, in `crates/matinee-security/src/enrollment.rs` (depends on T020, T030, T034)
- [X] T036 [US2] Complete extension custody/reconnect contract evidence by invoking the Chrome capability fixture for `chrome.storage.local` and non-exportable WebCrypto keys, recording supported persistence semantics or explicit fail-closed unsupported outcome, plus no raw PKCS#8 backup, stale-key deletion/quarantine, and `credential_store.mismatch`/`revoked` fail-closed outcomes in `crates/matinee-security/tests/enrollment_custody.rs` (depends on T016, T031, T034, T035)

**Checkpoint**: US2 is independently testable as a security enrollment contract with required-event-gated consumption, it does not create an extension package or daemon route.

---

## Phase 5: User Story 3 - Establish an Authenticated Encrypted Channel (Priority: P1)

**Goal**: Complete the fixed Spec 001 v1 handshake and stateful encrypted frame boundary before any product payload, using exact encodings, counters, nonce/AAD, limits, and private policy ordering.

**Independent Test**: Native/WebCrypto vector and fault-matrix runs accept all valid vectors and reject every mutation, downgrade, wrong endpoint/identity/epoch, replay, direction/counter, malformed, AEAD, and size case before payload dispatch.

### Tests for User Story 3 (write first)

- [X] T037 [P] [US3] Add native/WebCrypto handshake and encoding contract tests for context, endpoint, identity, nonce, contract intersection, unsigned big-endian lengths, UTF-8, UUID bytes, 65-byte SEC1 keys, and 64-byte P1363 signatures in `crates/matinee-security/tests/secure_channel_handshake.rs` (depends on T014, T017)
- [X] T038 [P] [US3] Add frame/nonce/AAD vector tests for exact 25-byte header, both directions, counters 0/1/`u64::MAX`/overflow, 1 MiB/1,048,535-byte limits, and no-fragmentation behavior in `crates/matinee-security/tests/secure_channel_frames.rs` (depends on T014, T017)
- [X] T039 [P] [US3] Add fault tests proving disjoint/substituted/downgraded contracts, DER/compressed keys, malformed UTF-8/lengths, altered endpoint/epoch/nonce/signature/tag, replay, wrong direction, duplicate/skipped/wrapped counters, stale epoch, and oversized payloads close before dispatch in `crates/matinee-security/tests/secure_channel_faults.rs` (depends on T014, T017, T018)

### Implementation for User Story 3

- [X] T040 [US3] Implement private handshake transcript construction, exact negotiation, P-256 ECDH, transcript signatures, HKDF-SHA-256, and directional AES-256-GCM key derivation using only `ring` in `crates/matinee-security/src/channel.rs` (depends on T015, T018, T037, T038, T039)
- [X] T041 [US3] Implement private exact v1 frame parsing/sealing, four-byte length checks before allocation, 25-byte header, directional nonce/AAD, counter state, tag validation, 1 MiB/1,048,535-byte limits, and no fragmentation in `crates/matinee-security/src/channel.rs` (depends on T015, T018, T037, T038, T039)
- [X] T042 [US3] Implement stateful `ChannelSession::receive`/`send` ordering so frame, AEAD, counter, epoch/lifecycle, authorization hook, filtering, and typed input/output are the only public path, raw framing/plaintext/authentication functions remain private, and `crates/matinee-security/src/channel.rs` owns emission of the required authentication, replay, downgrade, malformed-frame, counter, and cryptographic-failure events through the T020 sink, checking required-event availability before any protected channel-side mutation or payload dispatch so unavailable delivery closes the channel fail-closed (depends on T007, T019, T020, T040, T041)
- [X] T043 [US3] Complete the independent vector/fault evidence run by invoking both native tests and the Node WebCrypto `.mjs` peer against every valid and boundary-mutated vector, . Map valid/invalid outcomes to FR-010--FR-018, FR-027 channel event classes, FR-030, FR-032, and SC-003/SC-007 in `crates/matinee-security/tests/secure_channel_faults.rs` (depends on T015, T039, T042)

**Checkpoint**: US3 provides a stateful authenticated channel contract with zero unauthorized payload dispatch, no public raw framing API, and required channel-failure events emitted from `channel.rs`.

---

## Phase 6: User Story 4 - Authorize State and Preserve Object Privacy (Priority: P1)

**Goal**: Evaluate principal, ceiling, contract, epoch, owner, grant, and action inside the receive boundary, filtering before serialization and hiding unauthorized object existence.

**Independent Test**: Two MCP principals, one extension, and one administrator exercise every route/object class with owned, unknown, cross-owner, denied, over-ceiling, stale-epoch, revoked, filtered-event, and stream cases, authorized outputs are bounded and all unauthorized reads are indistinguishable `object.not_found`.

### Tests for User Story 4 (write first)

- [X] T044 [P] [US4] Add authorization matrix and contract tests for native-admin/MCP/extension ceilings, owner/grant/epoch/contract/action checks, administrator-only actions, and bounded authorized inputs in `crates/matinee-security/tests/authorization_contract.rs` (depends on T008, T009, T017)
- [X] T045 [P] [US4] Add privacy tests proving unknown, cross-owner, filtered, and unauthorized object/event/status/artifact/stream reads return indistinguishable `object.not_found` or redacted authorization failures before lookup serialization/mutation in `crates/matinee-security/tests/authorization_privacy.rs` (depends on T009, T010, T017)

### Implementation for User Story 4

- [X] T046 [US4] Implement private authorization ordering, principal ceilings, extension-grant subset/epoch binding, owner checks, requested-action checks, indistinguishable object-not-found mapping, and required authorization-decision event emission with the T020 availability gate checked before any authorized mutation, in `crates/matinee-security/src/authorization.rs` (depends on T008, T009, T018, T019, T020, T044, T045)
- [X] T047 [US4] Integrate authorization and pre-serialization filtering into `ChannelSession::receive`/`send` for typed events, status, artifacts, and bounded stream chunks without exposing plaintext or protected identifiers, preserving the required-event availability check before any authorized protected mutation, in `crates/matinee-security/src/channel.rs` (depends on T020, T042, T046)
- [X] T048 [US4] Complete independent authorization evidence for FR-020--FR-023, FR-027 authorization event classes, FR-028--FR-029, and SC-004/SC-009 in `crates/matinee-security/tests/authorization_privacy.rs` (depends on T019, T047)

**Checkpoint**: US4 independently proves authorization and privacy at the security boundary, with authorization events required before mutation and without daemon/MCP product routes.

---

## Phase 7: User Story 5 - Rotate or Revoke Identity Safely (Priority: P1)

**Goal**: Apply closed, idempotent rotation/revocation transitions that serialize against handshakes, enrollment, authorization, and mutation, advance epochs, close channels, and invalidate stale grants/decisions.

**Independent Test**: Rotation/revocation fixtures cover current/old keys, live channels, pending extension decisions, concurrent handshake/enrollment/authorization, stale epochs, repeated idempotency keys, and redacted events, no stale credential completes a mutation after commit.

### Tests for User Story 5 (write first)

- [X] T049 [P] [US5] Add rotation/revocation contract tests for replacement registration before epoch transition, old-channel closure, stale-key rejection, grant/decision invalidation, terminal revocation, typed transition outcomes, and idempotency in `crates/matinee-security/tests/rotation_revocation.rs` (depends on T008, T009, T017)
- [X] T050 [P] [US5] Add race/replay tests for handshake, enrollment consumption, authorization, object mutation, disconnect, repeated delivery, `unknown` transition, and `uncertain` expiry in `crates/matinee-security/tests/rotation_revocation_races.rs` (depends on T009, T012, T017)

### Implementation for User Story 5

- [X] T051 [US5] Implement closed `SecurityCommand` application for bootstrap, enrollment creation/consumption, rotation, and revocation with typed Spec 007 outcomes and fail-closed `unknown`, calling the T020 required-event availability gate before every command commit and emitting the required transition events, in `crates/matinee-security/src/transition.rs` (depends on T008, T009, T018, T019, T020, T026, T034, T049, T050)
- [X] T052 [US5] Replace registration, epoch advancement, old credential/channel closure, grant invalidation, and stale-epoch receive rejection with required rotation events checked available before the epoch commit, in `crates/matinee-security/src/transition.rs` and `crates/matinee-security/src/channel.rs` (depends on T020, T047, T049, T051)
- [X] T053 [US5] Implement terminal idempotent revocation, pending extension-decision invalidation, serialized transition boundary, disconnect independence, and fail-closed `uncertain` expiry handling, with required revocation events checked available before the revocation commit, in `crates/matinee-security/src/transition.rs` (depends on T020, T050, T052)
- [X] T054 [US5] Complete independent rotation/revocation evidence for FR-024--FR-026, FR-027 rotation/revocation event classes, FR-031--FR-032, and SC-006/SC-008 in `crates/matinee-security/tests/rotation_revocation_races.rs` (depends on T019, T053)

**Checkpoint**: US5 independently proves stale credentials cannot authenticate, authorize, mutate, or complete pending decisions after transition commit, and that unavailable required events block transition commits.

---

## Phase 8: Polish and Cross-Cutting Security Evidence

- [X] T055 Aggregate the final cross-story security-event evidence for FR-027 and SC-009 across US1--US5. Per-class emission for bootstrap, enrollment, authentication, authorization, rotation, revocation, replay, downgrade, malformed, counter, rate-limit, and cryptographic failures, bounded aggregation counters, sink-unavailable rollback outcomes, and secret/identifier redaction scans -- without adding sink behavior or availability checks that belong to T020 and the story implementations, in `crates/matinee-security/tests/events_contract.rs` (depends on T019, T020, T028, T036, T043, T048, T054)
- [X] T056 [P] Add the complete quickstart evidence mapping to FR-002--FR-032 and SC-001--SC-009, including secret scans, Node WebCrypto and Chrome capability fixture invocation/results, and downstream typed-contract boundaries, in `crates/matinee-security/tests/quickstart_evidence.rs` (depends on T015, T016, T018, T028, T036, T043, T048, T054, T055)
- [X] T057 [P] Review only feature-tied comments/docstrings and public boundary documentation for stale raw-framing, adapter, dependency, or downstream-ownership claims in `crates/matinee-security/src/lib.rs` and `specs/006-identity-authorization-secure-channels/quickstart.md` (depends on T056)
- [X] T058 Run the documented focused `matinee-security` quickstart validation and record its bounded evidence without modifying downstream crates, manifests outside T004, or Beads in `specs/006-identity-authorization-secure-channels/quickstart.md` (depends on T057)

---

## Dependencies & Execution Order

Every ordering statement below is encoded in the per-task `(depends on …)` edges above. Headings, checkpoints, and parallel examples are explanatory only and never a substitute for those edges.

### Phase Dependencies

- Setup T001--T006 is strictly serialized by explicit edges: create and accept both ADR decision beads (T001--T003), then gate root `Cargo.toml` (T004 on T003), crate manifest (T005 on T003 and T004), and generated `Cargo.lock` (T006 on T004--T005), no manifest/source task may start before T003.
- Foundational T007--T020 follows setup and blocks every story. It ends with the cross-story event contract tests (T019) and the required-event fail-closed availability gate (T020), so no protected mutation is ever authored before its event control and tests exist. Vectors, owned WebCrypto/Chrome fixtures, the malformed corpus harness T018, and contract tests T017 are explicit prerequisites of every story's first risky implementation.
- US1--US5 depend on foundational completion through explicit edges. Each story's first implementation tasks depend on that story's complete test set, on T018, . Protected mutations also wait on T019/T020: T024--T025 on T021--T023 and T018, T032--T033 on T029--T031 and T018, T040--T041 on T037--T039 and T018, T046 on T044--T045, T018, T019, and T020, T051 on T049--T050, T018, T019, and T020. Shared `transition.rs`/`channel.rs` work remains serialized by explicit dependencies.
- Every protected mutation task depends on T020 directly (T026, T027, T034, T035, T042, T046, T047, T051, T052, T053) and on T019 directly or transitively, so required-event availability is checked before enrollment consumption, identity/bootstrap commits, epoch rotation, revocation, authorization-driven mutation, and channel dispatch.
- Polish T055--T058 contains only final evidence work: T055 aggregates cross-story event evidence produced by the story implementations, T056 consumes both peer fixture results, . No sink behavior or availability check is introduced after a story mutation.

### User Story Dependencies

- **US1 (P1)**: Depends on T007--T020, T024--T025 wait for the full US1 test set T021--T023 and for T018, T026--T027 additionally wait for T020. No loopback or downstream persistence.
- **US2 (P1)**: Depends on T007--T020 and the identity/credential primitives, T032--T033 wait for the full US2 test set T029--T031 and for T018, T034--T035 additionally wait for T019/T020, T036 additionally requires the owned Chrome capability fixture T016.
- **US3 (P1)**: Depends on T007--T020 and shared vectors, T040--T041 wait for the full US3 test set T037--T039 and for T018, T042 additionally waits for T019/T020 because `channel.rs` owns authentication, replay, downgrade, malformed, counter, and cryptographic-failure event emission, T043 invokes the owned Node WebCrypto fixture T015 alongside native vectors.
- **US4 (P1)**: Depends on T007--T020 and `ChannelSession` from US3 at T047, T046 waits for the full US4 test set T044--T045, T018, T019, and T020, authorization tests may be prepared independently, but implementation waits for US3.
- **US5 (P1)**: Depends on T007--T020 and transition/session contracts from US1--US4 for T051--T053, T051 waits for the full US5 test set T049--T050, T018, T019, T020, T026, and T034, race tests may be prepared independently but implementation waits for those seams.

### Parallel Execution Examples
```text
After T003 is accepted:
  Run T004, then T005, then T006, do not parallelize ADR, workspace, manifest, or lockfile work.

After setup:
  Build T007--T014 and owned peer fixtures T015--T016 in separate files, then complete foundational tests T017--T018,
  then write T019 event contract tests, then implement the T020 sink gate.

After Phase 2:
  US1: T021--T022 tests in parallel, then T023 in the same file as T021, then T024--T028.
  US2: T029--T031 tests in parallel, then T032--T036 (including T016 invocation).
  US3: T037--T039 tests in parallel, then T040--T043 (including T015 invocation).
  US4: T044--T045 tests in parallel, then T046--T048.
  US5: T049--T050 tests in parallel, then T051--T054 after required transition/session seams.

Cross-story parallelism:
  After T020, US1 tests, US2 tests, US3 tests, and US4 matrices may be staffed concurrently because they use separate files. Do not parallelize shared implementation edits or two tasks that own the same file, honor each listed dependency.
```

## Implementation Strategy

### MVP First (User Story 1)

1. Complete T001--T020, including accepted ADR decision beads, serialized workspace/crate setup, vectors, owned peer fixtures, malformed harness, private boundaries, cross-story event contract tests, and the required-event fail-closed availability gate.
2. Complete US1 T021--T028 and stop for its independent clean/crash/restart/secret-custody evidence, including bootstrap event emission and sink-unavailable rollback.
3. Do not add daemon, persistence, extension product package, clock, MCP, browser product, or audit implementations to this MVP.

### Incremental Delivery

1. Add US2 enrollment and reconnect contract, then validate independently.
2. Add US3 authenticated encrypted channel, its `channel.rs` event emission, and shared vector evidence, then validate independently.
3. Add US4 authorization/privacy ordering, then validate independently.
4. Add US5 rotation/revocation races and idempotency, then validate independently.
5. Finish cross-story event evidence aggregation, malformed-corpus, quickstart, and redaction evidence.

### Completion Criteria

Every story has test-first contract/negative coverage encoded as task dependencies, an independently stated acceptance criterion, exact owned paths, and no downstream implementation leakage. Required security events are emitted from the story implementations that own each class, and every protected mutation checks required-sink availability before committing. The final evidence must cover FR-001--FR-032, SC-001--SC-009, the 100,000-case malformed campaign, and all quickstart security invariants.
---

## Phase 9: Convergence (Remaining Implementation and Evidence)

**Purpose**: Close the verified gaps between the existing task ledger and the present scoped crate without changing existing task text, ordering, or completion markers.

- [X] T059 [CONVERGENCE] Finish credential-store and OS-pipe adapters. Cover crash-safe bootstrap, binding outcomes, bounded envelopes, staged commits, retries, recovery, and event gating. Paths `crates/matinee-security/src/adapters/credential_store.rs`, `crates/matinee-security/src/adapters/os_pipe.rs`, `crates/matinee-security/src/transition.rs`, `crates/matinee-security/tests/bootstrap_*.rs`. Traces T024--T028, FR-002--FR-006, SC-001--SC-002.
- [X] T060 [CONVERGENCE] Secure enrollment proof consumption and reconnect. Cover one-use proofs, registration, Origin/install/endpoint checks, host/enrollment budgets, PKCS#8 custody, stale keys, and event gating. Path `crates/matinee-security/src/enrollment.rs` plus contract tests. Traces T032--T036, FR-007--FR-009, FR-019, SC-005.
- [X] T061 [CONVERGENCE] Secure the private v1 channel. Cover transcript signatures, ECDH/HKDF/AES-GCM, exact frames, nonce/AAD, counters, and native/WebCrypto vectors through `ChannelSession::receive`/`send`. Paths `crates/matinee-security/src/lib.rs`, `crates/matinee-security/src/channel.rs`, `crates/matinee-security/tests/secure_channel_*.rs`. Traces T040--T043, FR-010--FR-018, FR-030, FR-032, SC-003, SC-007.
- [X] T062 [CONVERGENCE] Enforce authorization ordering and pre-serialization privacy. Filter typed I/O, objects, events, status, artifacts, streams. Check ceilings, grants, epochs, owners, `object.not_found`, and decision events. Paths `crates/matinee-security/src/authorization.rs`, `crates/matinee-security/src/lib.rs`. Traces T046--T048, FR-020--FR-023, FR-027--FR-029, SC-004, SC-009.
- [X] T063 [CONVERGENCE] Apply serialized rotation and revocation transitions. Register replacements before epoch advancement. Invalidate channels, grants, decisions. Reject stale epochs. Support terminal idempotency, disconnect independence, uncertain-expiry fail-closed handling, typed outcomes, and event gating in `crates/matinee-security/src/transition.rs`. Traces T051--T054, FR-024--FR-027, FR-031--FR-032, SC-006, SC-008.
- [X] T064 [CONVERGENCE] Record cross-story evidence and quickstart validation. Capture native/WebCrypto agreement, Chrome invocation, 100,000-case malformed campaign, event aggregation, redaction scans, FR/SC mapping, boundary docs, and focused results in `crates/matinee-security/tests/quickstart_evidence.rs` and `specs/006-identity-authorization-secure-channels/quickstart.md`. Traces T055--T058, FR-001--FR-032, SC-001--SC-009.
