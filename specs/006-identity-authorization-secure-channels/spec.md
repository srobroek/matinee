# Feature Specification: Identity, Authorization, and Secure Channels

**Feature Branch**: `006-identity-authorization-secure-channels`
**Created**: 2026-09-16
**Status**: Ready for implementation (held for approval)
**Input**: Local principal identity, authorization, enrollment, revocation, credential-store integration, ECDSA identity/key agreement, authenticated channel framing, origin checks, rotation, and replay protection for Matinee processes.

## Scope and Boundaries

This specification defines the trust and authorization module shared by the local CLI/MCP adapter, daemon, and paired browser extension. Approved principals establish authenticated encrypted channels. Each state-bearing action is limited to the principal's capability, owner, epoch, and grant.

**In scope**: native administrator bootstrap, MCP-client and browser-extension principal identities, platform credential-store integration, public-key registration and fingerprints, extension enrollment, principal roles and capability ceilings, P-256 ECDSA identity proofs, P-256 ephemeral key agreement, transcript binding, version negotiation, loopback and browser-origin checks, encrypted frame limits and counters, authorization and object-existence privacy, rotation, revocation, replay and downgrade handling, malformed-input and rate-limit handling, failure behavior, and redacted security events.

**Out of scope**: browser discovery or operations, human approval policy and trusted decision UI, daemon lifecycle and recovery ownership (007), clock implementation or clock seam (009), remote execution, hosted identity, website authentication, and defense against a local account or installed extension runtime already replaced by an attacker.

## User Scenarios & Testing

### User Story 1 - Bootstrap a trusted local principal (Priority: P1)

A user runs setup on a clean machine. The first native administrator and daemon establish identities without sending private keys over an unauthenticated network route or placing them in durable application state. The user can then use the resulting principal to administer the local runtime.

**Why this priority**: Every later connection and pairing depends on one unambiguous local trust root.

**Independent Test**: A clean-state setup fixture exercises success, crash-before-commit, crash-after-commit, duplicate bootstrap, mismatched bootstrap, missing credential, and daemon restart cases; it confirms stable identity and no private-key disclosure.

**Acceptance Scenarios**:
1. **Given** no registered native principal, **when** setup bootstraps one through inherited operating-system pipes, **then** the daemon establishes or reuses its identity, setup pins that identity, the daemon commits exactly one native administrator, and setup marks the credential active.
2. **Given** setup stopped during staged bootstrap, **when** it resumes with the same bootstrap identity, **then** it converges on the same daemon identity and exactly one native administrator without creating a duplicate or orphaned registration.
3. **Given** setup stopped after the principal commit, **when** it resumes, **then** it recovers the existing principal rather than replacing it.
4. **Given** an initialized state, **when** a different bootstrap identity is presented, **then** it fails without changing registrations.

### User Story 2 - Enroll and reconnect a browser extension (Priority: P1)

A native administrator creates a short-lived, single-use enrollment for the expected extension. The extension proves its origin and enrollment identity, creates its long-term identity, and reconnects later using its stored private key and pinned daemon identity.

**Why this priority**: Pairing is the only supported route for browser control and must not expose browser credentials or accept an impostor origin.

**Independent Test**: A pairing fixture covers valid, wrong-origin, wrong-extension, expired, consumed, rate-limited, and replayed enrollments, then reconnects the resulting extension through the extension channel.

**Acceptance Scenarios**:
1. **Given** an authenticated administrator, **when** it requests enrollment, **then** the result contains a ten-minute, one-use bundle with at least 256 bits of entropy and the expected origin and daemon identity.
2. **Given** a valid bundle, **when** the expected extension connects with its browser-supplied origin, **then** the one-time identity is consumed and a distinct long-term extension principal is created atomically.
3. **Given** a consumed, expired, revoked, wrong-origin, or wrong-identity bundle, **when** it is presented, **then** pairing fails before any product payload is accepted.
4. **Given** an active paired extension, **when** it reconnects, **then** it resumes only the sessions and capabilities authorized for that extension identity.

### User Story 3 - Establish an authenticated encrypted channel (Priority: P1)

An approved native or extension principal connects to the daemon. Both peers negotiate a compatible application contract, authenticate a complete transcript, derive directional keys, and exchange only bounded encrypted frames after authentication.

**Why this priority**: The loopback endpoint is not itself a trust boundary; channel authentication and confidentiality prevent impostors, observers, relays, and altered negotiation from accessing state.

**Independent Test**: Deterministic protocol vectors and a fault matrix exercise valid handshakes plus malicious listeners, observers, relays, signature mutations, key mutations, contract downgrade, wrong endpoint, wrong epoch, replay, wrong-direction, counter, size, and malformed-frame cases.

**Acceptance Scenarios**:
1. **Given** a registered principal and overlapping contract range, **when** both peers complete the fixed secure-channel handshake, **then** the first product payload is accepted only after mutual transcript verification and directional key derivation.
2. **Given** disjoint or tampered contract ranges, **when** negotiation occurs, **then** it returns a structured compatibility failure before channel creation or mutation.
3. **Given** an observer or relay, **when** it reads or alters transport bytes, **then** it cannot recover or modify a product payload and the channel closes on alteration.
4. **Given** a repeated, skipped, wrapped, or wrong-direction frame counter, **when** the frame is received, **then** the channel closes without dispatching it.

### User Story 4 - Authorize state and preserve object privacy (Priority: P1)

The daemon evaluates each route, command, event, stream, and object lookup against the principal role, capability ceiling, authentication epoch, ownership, and extension grant. Authorized callers see only the state they are entitled to see.

**Why this priority**: Authentication alone must not let one local principal read or mutate another principal's sessions, requests, artifacts, or approvals.

**Independent Test**: Two MCP principals, one extension principal, and one administrator probe every route and object class with allowed, denied, unknown, cross-owner, over-ceiling, stale-epoch, and revoked credentials.

**Acceptance Scenarios**:
1. **Given** an MCP client, **when** it requests a resource it owns, **then** the daemon returns the authorized bounded result.
2. **Given** an MCP client, **when** it requests another principal's object or an administrator-only action, **then** the daemon returns the same not-found envelope used for an unknown object where object existence would otherwise be disclosed.
3. **Given** an extension, **when** it requests a session not bound to its browser identity or grant, **then** the request is denied without leaking state.
4. **Given** an unauthorized or malformed request, **when** it reaches the authorization boundary, **then** no mutation is performed and a redacted security event is recorded.

### User Story 5 - Rotate or revoke identity safely (Priority: P1)

An administrator rotates a principal key or revokes a principal. Existing channels close, the authentication epoch advances, pending trusted decisions owned by the revoked extension are invalidated, and old credentials cannot reconnect or mutate state.

**Why this priority**: Credential compromise and replacement must have a deterministic, fail-closed response.

**Independent Test**: A rotation/revocation fixture checks current and old keys, live channels, epochs, pending decisions, reconnects, duplicate requests, and audit events for native and extension principals.

**Acceptance Scenarios**:
1. **Given** an active principal, **when** its identity is rotated, **then** a new key is registered, the epoch increments, old live channels close, and only the new credential can authenticate.
2. **Given** a revoked principal, **when** it sends a frame or reconnects, **then** authentication or authorization fails before state disclosure or mutation.
3. **Given** a revoked extension with pending trusted decisions, **when** revocation commits, **then** its unconsumed decisions become invalid and cannot complete operations.
4. **Given** repeated rotation or revocation delivery, **when** the same operation is retried, **then** the recorded outcome is returned without a second state transition.

### Edge Cases

- Credential store is unavailable, returns a mismatched key, or contains duplicate references.
- A private key, enrollment secret, or sensitive handshake field appears in an error, log, status, or frame.
- A non-loopback endpoint, unexpected WebSocket subprotocol, wrong browser Origin, wrong store identity, or development identity without explicit allowance is presented.
- An enrollment is retried concurrently, expires during proof, exceeds proof or address rate limits, or is replayed after consumption.
- A peer submits unsupported key encoding, DER instead of the required fixed signature encoding, invalid length prefix, oversized frame/message, invalid UTF-8, malformed JSON envelope, or unknown payload kind.
- A peer presents an old epoch, contract, daemon identity, endpoint, nonce, connection identifier, or transcript.
- A frame counter is duplicated, skipped, wrapped, or sent in the opposite direction; a disconnect occurs between proof and registration.
- Authorization is evaluated for an unknown object, cross-owner object, filtered event, stream chunk, or capability above the principal ceiling.
- Rotation and revocation race with connection establishment, enrollment consumption, authorization, or a pending decision.
- A local attacker can observe or squat on the loopback endpoint; accepted risk remains compromise of the local account or already-replaced extension runtime.

## Requirements

### Functional Requirements

- **FR-001**: The system MUST distinguish daemon identity, principal identities, enrollment authority, connection, credential reference, capability, grant, authentication epoch, and rotation or revocation transition, with observable identity and lifecycle invariants for each; storage representation remains deferred to planning.
- **FR-002**: The system MUST create one daemon identity and one independent ECDSA P-256 identity for each principal; public-key fingerprints MUST be lowercase hexadecimal SHA-256 over the exact 65-byte uncompressed public key.
- **FR-003**: Private keys MUST remain only in the owning platform credential store or extension-local storage, except that the daemon-generated one-time enrollment private key MAY be transferred inside the authenticated encrypted native channel for inclusion in the enrollment bundle, held in transient setup custody, and presented through trusted local QR-code, extension-link, or copyable base64url representations of that bundle. Private keys MUST NOT be written to the durable application store, logs, diagnostics, status output, enrollment records, or plaintext transport.
- **FR-004**: Native setup MUST bootstrap the first principal only through inherited operating-system pipes, with crash-safe idempotency before and after principal commit; loopback MUST NOT be used for first-principal bootstrap.
- **FR-005**: The system MUST resolve native credentials by the selected principal and state-directory identity, reject missing or mismatched credentials before initialization, and never silently select another principal.
- **FR-006**: The system MUST assign principal kinds of native administrator, MCP client, and browser extension, each with an explicit capability ceiling and immutable ownership identity.
- **FR-007**: An administrator MUST be able to create a single-use extension enrollment containing expected origin, identity, daemon identity, endpoint, expiry, and at least 256 bits of secret entropy; enrollment expiry MUST be ten minutes by default.
- **FR-008**: Enrollment consumption MUST require the expected browser-supplied Origin, expected extension identity/install metadata, valid one-time proof, unexpired state, and rate-limit allowance; consumption and long-term principal creation MUST be atomic.
- **FR-009**: The system MUST limit an enrollment to one successful use, close after a failed proof, allow at most five failed proofs per enrollment, and rate-limit failed pairing attempts to ten per loopback address per minute.
- **FR-010**: The secure channel MUST use context `matinee.secure-channel.v1`, P-256 ephemeral key agreement, ECDSA-SHA-256 transcript signatures, HKDF-SHA-256, and AES-256-GCM; cryptographic primitives MUST be supplied by reviewed libraries.
- **FR-011**: The handshake MUST bind endpoint, daemon identity, both nonces, principal identity, authentication epoch, selected application contract, connection identity, and direction; a peer MUST verify the pinned daemon identity and complete transcript before sending a product payload.
- **FR-012**: Contract negotiation MUST select exactly one contract from the intersection of peer ranges; disjoint, substituted, downgraded, or cross-version selections MUST fail before key derivation or mutation.
- **FR-013**: Handshake encodings MUST use unsigned big-endian integers, explicit four-byte length prefixes, exact UTF-8 strings, raw UUID bytes, 65-byte uncompressed public keys, and fixed 64-byte IEEE P1363 signatures; alternate encodings MUST be rejected.
- **FR-014**: Every state-bearing peer MUST use an authenticated encrypted channel before reading state, invoking an operation, receiving an event, or opening a stream; liveness-only health information MAY remain unauthenticated and MUST expose no identity or state.
- **FR-015**: Encrypted frames MUST contain version, connection identity, strictly increasing 64-bit counter, ciphertext, and authentication tag; associated data MUST bind frame header, context, contract, epoch, and direction.
- **FR-016**: The system MUST close a channel on repeated, skipped, wrapped, wrong-direction, stale-epoch, malformed, or cryptographically invalid frames and MUST dispatch no contained payload.
- **FR-017**: A frame MUST be no larger than 1 MiB and a decrypted message no larger than 4 MiB; limits MUST be enforced before unbounded allocation and report a bounded resource failure.
- **FR-018**: WebSocket state-bearing routes MUST accept only configured loopback endpoints, expected route, and expected versioned subprotocol; non-loopback binding and unexpected origins MUST fail closed.
- **FR-019**: Production extension pairing MUST require the expected `chrome-extension://` origin, store identity, normal install type, update URL, and supported version range; development identities require explicit interactive allowance and visible warning.
- **FR-020**: Authorization MUST evaluate principal kind, capability ceiling, authentication epoch, object owner, extension grant, requested action, and negotiated contract before disclosure or mutation.
- **FR-021**: The system MUST enforce administrator-only actions for global state, setup, principal management, rotation, and revocation; MCP clients MUST NOT administer or trusted extension decisions; extensions MUST be limited to their own browser identity and granted sessions.
- **FR-022**: Unauthorized object lookups and filtered streams MUST return an indistinguishable `object.not_found` result where existence would disclose protected state; unauthorized actions MUST return a structured authorization failure without protected fields.
- **FR-023**: Event, status, artifact, and stream responses MUST filter by authorization before serialization; object identifiers, counts, titles, origins, and error detail MUST not bypass authorization through side channels.
- **FR-024**: Principal rotation MUST register the replacement credential, increment the authentication epoch, close live channels for the prior epoch, invalidate stale credentials, and preserve an auditable redacted outcome.
- **FR-025**: Revocation MUST be idempotent, close all live channels for the principal, invalidate unconsumed approvals owned by a revoked extension, and prevent later authentication, authorization, event completion, or decision from that principal.
- **FR-026**: Rotation and revocation MUST be serialized against handshake, enrollment consumption, authorization, and object mutation so no stale credential can pass a check after the transition commits.
- **FR-027**: The system MUST emit redacted security events for accepted enrollment, rejected proof, rejected origin, authentication failure, authorization denial, rotation, revocation, replay, downgrade, malformed input, and rate-limit outcomes.
- **FR-028**: Security events and failures MUST identify a stable boundary, principal or connection when safe, reason class, and next action without exposing private keys, reusable enrollment secrets, cookies, authorization headers, credentials, or sensitive payloads.
- **FR-029**: The system MUST provide bounded structured failures for authentication, authorization, compatibility, malformed input, origin, replay, rate-limit, credential-store, and resource-limit cases; no failure may disclose whether an unauthorized object exists.
- **FR-030**: Protocol constants, field ordering, limits, signature encoding, counter rules, and cryptographic context MUST be versioned and represented by deterministic test vectors shared by native and extension peers; the vector set MUST include a valid vector and at least one mutation at every field boundary, and both peer types MUST exercise each valid and boundary-mutated vector.
- **FR-031**: The system MUST preserve connection lifetime separately from daemon-owned requests, sessions, approvals, and grants; disconnect alone MUST NOT grant, revoke, or complete durable work.
- **FR-032**: The system MUST reject replay of a handshake, enrollment, frame, contract, epoch, or authorization decision outside its valid nonce, counter, connection, and lifecycle context.

### Key Entities

- **Daemon Identity**: Local identity with public key, fingerprint, endpoint binding, contract range, and credential-store reference.
- **Principal**: Registered native administrator, MCP client, or browser extension identity with public key, kind, capability ceiling, lifecycle, and authentication epoch.
- **Credential Reference**: Non-secret locator for exactly one private key and pinned daemon identity in the owning store.
- **Extension Enrollment**: Expiring one-time authority with expected origin, one-time public key, daemon binding, expiry, failure count, and consumed or revoked state.
- **Connection**: Ephemeral channel with principal, contract, epoch, nonces, direction keys, counter state, and lifecycle.
- **Capability and Grant**: Explicit allowed action set and extension-scoped ownership grant; neither can exceed the principal ceiling.
- **Rotation Transition**: Auditable replacement transition linking old and new fingerprints, epoch, effective boundary, and redacted outcome.
- **Revocation Transition**: Idempotent denial transition with reason, epoch, affected channels, invalidated grants, and timestamp.
- **Security Event**: Redacted append-only fact describing authentication, authorization, protocol, enrollment, rotation, or revocation outcome.

## Success Criteria

### Measurable Outcomes

- **SC-001**: In 100 clean bootstrap runs, all successful runs create exactly one daemon identity and one native administrator, and zero private-key bytes occur in durable application state or bootstrap transport captures.
- **SC-002**: In 100 crash injections during staged bootstrap, every retry converges to one principal with no duplicate or orphaned registration.
- **SC-003**: In 1,000 valid and invalid handshake vectors across native and extension peers, every valid vector authenticates and every mutation, downgrade, wrong endpoint, wrong identity, stale epoch, malformed encoding, and replay vector fails before product payload acceptance.
- **SC-004**: In a matrix covering every route, object type, role, capability ceiling, ownership, and grant, 100% of unauthorized probes disclose neither protected data nor object existence.
- **SC-005**: In 100 enrollment attempts per failure class, only valid, unexpired, expected-origin, first-use proofs succeed; consumed, expired, wrong-origin, wrong-identity, replayed, and rate-limited attempts produce no principal.
- **SC-006**: In 100 rotation and revocation trials with live channels and pending extension decisions, zero stale-epoch frames complete a mutation or decision after the transition commits.
- **SC-007**: In 100,000 bounded malformed and oversized input cases, no case allocates beyond declared limits, leaks secret material, or mutates protected state.
- **SC-008**: In 100 channel disconnects, confirmed daemon-owned work remains independent of connection lifetime and no disconnect creates a duplicate authorization or revocation transition.
- **SC-009**: Every security failure in the acceptance matrix maps to exactly one stable redacted failure class, boundary, and safe next action.
 

## Clarifications

### Session 2026-09-16

- Q: Which workflow depth should govern this cross-cutting security feature? → A: Full SDD; the tinyspec classifier recommended full SDD because the feature spans multiple modules and carries high security risk.
- Q: Which local trust boundary should first-principal bootstrap use? → A: Inherited operating-system pipes; this is the Spec 001 contract and avoids trusting an unauthenticated loopback route.
- Q: Which secure-channel and identity profile should be normative? → A: The fixed Spec 001 profile: ECDSA P-256 identities, P-256 ephemeral key agreement, HKDF-SHA-256, AES-256-GCM, transcript binding, and strictly increasing authenticated counters.
- Q: Which extension enrollment defaults should be normative? → A: Single-use enrollment with at least 256 bits of entropy, ten-minute expiry, expected Origin/install metadata, five failed proofs per enrollment, and ten failed pairing attempts per loopback address per minute.
- Q: Which authorization privacy behavior should apply to unauthorized object lookups? → A: Return the same object.not_found envelope as unknown identifiers and filter status/events before serialization.

## Assumptions

- The user controls the local account, state directory, credential store, browser installation, and MCP client configuration.
- Spec 001 contracts are authoritative for route names, cryptographic encodings, limits, roles, and acceptance identifiers; plan-level wire implementation details remain deferred to planning.
- The platform credential store and extension-local storage provide confidentiality for private keys; this feature does not claim protection from a compromised local account or replaced extension runtime.
- The daemon lifecycle and durable store serialize and persistence boundaries; this specification defines their security contract but not their implementation or recovery machinery.
- The clock and deadline seam belongs to spec 009; this feature consumes enrollment expiry and epoch validity as supplied by the owning lifecycle/time contract.
- No hosted identity provider, remote machine, browser profile credential read, website authorization bypass, or human approval policy is required.

## Accepted-Risk Boundary

Matinee accepts that a local attacker with the user's account authority can read process memory, replace the installed extension runtime, or interfere with local credential-store access. The feature does not claim to attest executable extension code beyond the browser-provided identity/install metadata, and it does not defend against a trusted browser or extension already replaced by that attacker. It does claim that an untrusted loopback listener, observer, relay, malformed peer, revoked credential, stale epoch, replay, or unauthorized principal cannot obtain protected product payloads or cause a protected mutation through the specified channels.

## Explicit Non-Goals

- Browser operations, tab ownership, page observation, file selection, or session semantics.
- Human approval policy, decision-surface UX, or deciding which effects require attention.
- Daemon election, process lifecycle, durable storage schema, migrations, or restart recovery.
- Clock implementation, deadline calculation, or time synchronization.
- Remote execution, hosted identity, multi-user tenancy, or arbitrary extension support.
- Website login, website authorization, anti-automation bypass, or legal/compliance policy.
- A stable public library API or implementation-specific module/task sequencing.
