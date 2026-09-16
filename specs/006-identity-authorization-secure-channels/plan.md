# Implementation Plan: Identity, Authorization, and Secure Channels

**Branch**: `006-identity-authorization-secure-channels` | **Date**: 2026-09-16 | **Spec**: [spec.md](spec.md)

## Summary

Add one deep `matinee-security` crate to the current two-crate workspace. The crate owns
identity, the inherited v1 secure-channel profile, enrollment, authorization, rotation,
revocation, bounded failures, and redacted security-event facts. It exposes a stateful
session receive path rather than independent authentication, authorization, or framing
functions. Credential-store and inherited OS-pipe adapters remain the only platform seams.

The crate does not implement daemon lifecycle, durable persistence, browser operations,
human approval, or clock calculation. Specifications 007, 009, and 015 own those
concerns and integrate through typed values described below.

## Technical Context

**Language/Version**: Rust 2024 edition with minimum Rust 1.85. The extension peer uses
the WebCrypto APIs required by the inherited Spec 001 contract.

**Security dependencies**: The current workspace contains no security crate and the
current lockfile contains none of the inherited security stack. Add these direct
dependencies only to `crates/matinee-security/Cargo.toml`:

| Dependency | Version | Features | Evidence and boundary |
|---|---|---|---|
| `ring` | `0.17.x` | no feature override | Spec 001 selects reviewed `ring` primitives for P-256, HKDF-SHA-256, and AES-256-GCM; cryptographic operations stay private. |
| `keyring` | `3.6.3` | `default-features = false`; `apple-native`, `windows-native`, `linux-native-sync-persistent`, `crypto-rust` | `keyring 3.6.3` declares Rust 1.75 compatibility, so it supports the fixed Rust 1.85 workspace and the required macOS, Windows, and Linux backends. `keyring 4.0.0` requires Rust 1.88 and is rejected. No plaintext fallback is permitted. |
| `serde` | `1.x` | `derive` | The current runtime already uses this feature for typed envelopes. |
| `uuid` | `1.x` | `v7`, `serde` | Spec 001 selects UUIDv7 identifiers and the data model serializes typed identifiers. |

Do not add `tokio`, `axum`, `rusqlite`, `rmcp`, or a second cryptographic library to
this crate. The Spec 001 dependency list is a product baseline. It does not transfer ownership of its
superseded five-crate layout. Any departure from `ring` or the fixed profile requires a
versioned protocol decision and an ADR before implementation.

**Storage**: The security crate receives opaque credential references and emits typed
transition outcomes. It never owns a database connection, persistence trait, clock
trait, or retention policy. The extension stores its long-term WebCrypto private key,
non-secret record, and pinned daemon identity in `chrome.storage.local`; it does not
create a backup. The one-time PKCS#8 enrollment key is transient and is discarded after
the authenticated pairing channel establishes the long-term key.

**Testing and evidence**: Rust and extension peers consume the same deterministic
vectors. Vector evidence covers exact bytes, nonce construction, frame boundaries, and
one mutation at every field boundary. The malformed-input campaign has 100,000 bounded
cases across length prefixes, UTF-8, keys, signatures, headers, counters, AEAD, payload
kinds, and aggregate limits. Each run records pre-allocation rejection, maximum observed
allocation, channel-close result, dispatch count (which must remain zero), and a scan
for secrets or protected event fields. No unsupported latency threshold is part of this
plan.

**Target Platform**: macOS, Linux, and Windows local accounts; Chrome/Chromium the manifest V3 extension; configured loopback-only daemon routes owned by downstream specs.

**Project Type**: Two existing Rust crates plus one new private security crate. The
current workspace is not the Spec 001 five-crate proposal.

**Constraints**: Preserve the exact Spec 001 v1 context, handshake encodings, frame
layout, zero-based directional counters, nonce/AAD construction, routes, limits, and
one-time enrollment-key transfer. Reject malformed, stale, replayed, downgraded,
unauthorized, and uncertain security outcomes before payload dispatch. v1 has no secure
channel fragmentation or reassembly.

## Constitution Check

- **I Human Authority -- PASS**: The crate authenticates and authorizes. It does not
  approve browser effects or decide UI.
- **II Visible Browser Ownership -- PASS**: Extension origin, installation metadata,
  grants, and channel checks are enforced. Browser operations remain downstream.
- **III Durable Local State -- PASS**: Security returns typed transition outcomes and
  leaves single-writer persistence and recovery to Spec 007.
- **IV Least Privilege -- PASS**: Private keys remain in their owning stores, all
  state-bearing input passes through one session gate, and object existence is hidden.
- **V Observable Contracts -- PASS**: Failures, safe actions, vectors, event bounds,
  and typed sink outcomes are explicit and redacted.
- **Delivery gates -- PASS**: This plan creates one complete crate boundary and no
  placeholder downstream package or public raw framing API.

## Current Workspace and Ownership

```text
Cargo.toml                         # existing virtual workspace; add the new member
Cargo.lock                         # generated by Cargo after manifest changes; never hand-edit
crates/
├── matinee-cli/                   # existing; unchanged by Spec 006
├── matinee-runtime/               # existing; unchanged by Spec 006
└── matinee-security/              # the only new Spec 006 crate
    ├── Cargo.toml                 # new crate manifest owned by Spec 006
    ├── src/
    │   ├── identity.rs
    │   ├── channel.rs
    │   ├── authorization.rs
    │   ├── enrollment.rs
    │   ├── transition.rs
    │   ├── failures.rs
    │   ├── events.rs
    │   └── adapters/
    │       ├── credential_store.rs
    │       └── os_pipe.rs
    └── vectors/
```

Spec 006 owns only the new crate and the planning artifacts in this directory. The
existing CLI and runtime crates are not modified for security integration in this
specification.

| Later owner | Consumes from `matinee-security` | Spec 006 status |
|---|---|---|
| Spec 007 daemon lifecycle/store | authenticated typed input, closed transition commands, event sink facts | downstream integration; no daemon or persistence implementation here |
| Spec 008 extension/pairing | WebCrypto peer, Origin/install checks, local key custody | downstream integration; no extension package here |
| Spec 009 clock/deadline seam | typed expiry and deadline results | downstream typed input; no clock trait or calculation here |
| Specs 010--014 product workflow | authorized typed commands and bounded results | downstream integration; browser operations and human approval remain out of scope |
| Spec 015 audit persistence | typed events, chain-verification and access floors | downstream persistence/retention/access policy |
| Spec 016 packaging/acceptance | compatibility and release integration | downstream only; no Spec 006 ownership or source target |

This file map supersedes the Spec 001 five-crate proposal only for repository layout.
Spec 001 protocol and product contracts remain normative.

## Deep Public Boundary

`matinee-security` exposes a stateful `ChannelSession`/`SessionInput` boundary:

1. Session establishment performs the inherited handshake internally and binds the
   principal, negotiated contract, connection, epoch, direction, and expected endpoint.
2. `ChannelSession::receive(frame, typed_context)` validates the exact v1 frame, checks
   counter and AEAD, checks current epoch/lifecycle, evaluates the authorization inputs,
   and returns only an `AuthorizedInput` typed for the caller's permitted capability.
   The caller cannot observe plaintext before these checks complete.
3. `ChannelSession::send(AuthorizedOutput)` seals an already authorized typed result or
   event with the same private frame rules. Callers cannot select headers, counters,
   nonce bytes, AAD, or algorithms.
4. `SecurityCommand` is a closed enum for bootstrap, enrollment creation/consumption,
   rotation, and revocation. `apply(command, typed_transition_input)` returns a typed
   transition outcome. Callers cannot mutate lifecycle fields or sequence checks.

Raw frame encoding/decoding, handshake transcript assembly, cryptographic operations,
Origin parsing, and authorization-gate implementation are private. There are no public
`authenticate`, `authorize`, `encode_frame`, or `decode_frame` functions. The only
private adapter seams are `CredentialStore` for key handles/signing and `OsPipe` for
inherited bootstrap handles. The crate consumes typed transition and expiry results
from future owners instead of defining hypothetical persistence or clock traits.

## Typed Downstream Inputs (Non-Blocking)

Spec 007 will supply a typed transition input containing a state-directory identity,
transition ID, operation kind, idempotency key, prior epoch, and one of `committed`,
`already_committed`, `rejected`, or `unknown`. The security module treats `unknown` as
fail-closed and never reports a protected success. Spec 007 owns serialization,
durability, and reconciliation.

Spec 009 will supply typed expiry/deadline results with `valid`, `expired`, or
`uncertain` status and the bounded expiry/deadline value. The security module accepts
these values at enrollment and epoch boundaries and treats `uncertain` as invalid for
security-sensitive work. Spec 009 owns time calculation and test-clock behavior.

These are input/output contracts for later integration, published traits. They do
not block Spec 006 implementation or reverse roadmap dependencies.

## Security Event Sink Boundary

The crate emits a typed `SecurityEvent` to a `SecurityEventSink` callback boundary. The
event contains only closed enums, raw UUIDs for safe principal/connection IDs, a typed
time value supplied by the owning contract, and bounded redacted metadata. The event
serialization is at most 2,048 bytes, has at most eight metadata entries, limits each
metadata key to 32 UTF-8 bytes and value to 128 bytes, and limits total metadata to 512
bytes. URLs, payload text, keys, cookies, credentials, authorization headers, enrollment
secrets, and object-sensitive identifiers are rejected before emission.

The sink returns `accepted`, `aggregated`, or `unavailable`. It aggregates by boundary,
stable code, safe principal/connection IDs, and endpoint class with at most 64 active
buckets; each count saturates at 255. A required event with an unavailable sink makes
the related security transition fail closed without protected mutation. Health remains
bounded and may report only liveness. Spec 015 owns durable schema, digest-chain
storage and verification, retention, quotas, and read/export authorization. It must
filter events before serialization/export, scope a chain to the state-directory
identity, and surface a broken predecessor/digest as an untrusted-history diagnostic.

## Implementation Sequence

1. Freeze the inherited constants, typed entities, failure codes, safe-action map,
   event bounds, and v1 vectors from the contracts.
2. Add `crates/matinee-security` to the root `Cargo.toml` workspace members and create
   its manifest with the concrete Rust 1.85 dependency set. Run Cargo to generate the
   root `Cargo.lock`; never hand-edit lockfile contents. Keep the existing two crates
   unchanged.
3. Implement private credential-store and inherited OS-pipe adapters, including
   missing, mismatch, duplicate, and unavailable outcomes.
4. Implement the private inherited handshake, exact v1 frame, nonce/AAD, AES-GCM,
   directional zero-based counters, and no-fragmentation limit checks.
5. Implement the stateful session receive/send path so validation, decryption, epoch,
   lifecycle, authorization, filtering, and typed output occur in one ordering.
6. Implement closed bootstrap, enrollment, rotation, and revocation commands with
   independent host and per-enrollment budgets and typed downstream outcomes.
7. Implement bounded failures, safe actions, event aggregation, and sink-unavailable
   fail-closed behavior. Extend custody rules as the peer contract, not an
   extension crate.
8. Produce deterministic native/WebCrypto vectors and the reproducible malformed-input
   evidence described above. Downstream specifications consume this crate later.

## Finding Resolution Matrix

| Finding | Resolution in this plan |
|---|---|
| Architecture: current workspace | Add `crates/matinee-security` to the root `Cargo.toml` members, create its crate manifest, and regenerate the root `Cargo.lock` with Cargo; CLI/runtime remain unchanged. |
| Architecture: inherited frame | Spec 001 v1 frame, zero-based counter, nonce, and AAD are copied without a new header or protocol version. |
| Architecture: deep boundary | Stateful session receive/send and closed transition commands hide raw framing and policy ordering. |
| Architecture: adapter ownership | Only credential-store and inherited OS-pipe seams remain; clock, persistence, Origin, and crypto traits are removed. |
| Architecture: dependencies | `ring 0.17.x`, `keyring 3.6.3` with `default-features = false` and the four explicit platform/crypto features, `serde 1.x` derive, and `uuid 1.x` `v7,serde`; 4.0.0 is rejected because it requires Rust 1.88. |
| SEC-001 | Exact 12-byte nonce and AAD construction are normative and vector-tested. |
| SEC-002 | v1 carries one payload per frame; no fragmentation or reassembly; the frame-derived plaintext maximum is explicit. |
| SEC-003 | `chrome.storage.local` custody, non-exportability where supported, stale-key deletion, no backup, and fail-closed administrator re-pairing are explicit. |
| SEC-004 | Typed bounded events, aggregation, sink status, access filtering, quota/retention ownership, and broken-chain handling are explicit. |
| Critique P1/E1 | Rejected. Spec 001 daemon-protocol.md:111-120 and extension-protocol.md:25-40 require one-time PKCS#8 enrollment-key transfer through the authenticated native channel. FR-003 remains unchanged. |
| Critique P2/P3/E2/E3/E4/E5 | Safe actions, independent budgets, typed 007/009 inputs, reproducible malformed-input evidence, event floors, and extension-key recovery are covered in the contracts and quickstart. |

## Post-Design Constitution Check

I--V remain PASS. The plan adds no constitution exception, no public raw framing API,
and no implementation target owned by a later specification.

1. Preserve the Spec 001 v1 cryptographic context and exact frame bytes. Any change
   requires a new protocol context/version, migration, and ADR.
2. Add one deep `matinee-security` crate to the Spec 005 two-crate workspace while
   keeping callers and future integrations outside it.
3. Depart from the Spec 001 credential-store dependency baseline by pinning
   `keyring 3.6.3` with explicit native and Rust-crypto features because `keyring 4.0.0`
   requires Rust 1.88 while the workspace remains at Rust 1.85. Record this departure
   in an ADR before implementation.
4. Keep one-time PKCS#8 enrollment-key transfer inside the authenticated native
   channel while forbidding durable or unauthenticated private-key disclosure.
5. Preserve independent host-address and per-enrollment failure budgets despite the
   accepted bounded host-wide denial tradeoff for local loopback peers.

## Revisit List

- Spec 007 must publish the typed transition outcome and recovery carrier before its
  daemon/store integration, without changing Spec 006 security ordering.
- Spec 009 must publish typed expiry/deadline results and uncertainty behavior.
- Spec 015 must publish event persistence, digest verification, retention, quota, and
  read/export authorization while preserving this security floor.
- The downstream extension specification must validate Chrome persistence of a
  non-exportable key, stale-key deletion, profile restore, uninstall, and admin
  re-pairing. No extension-key backup is supported in v1.
- A future protocol revision may add algorithms only with a new context/version and
  explicit migration.

No implementation tasks, source files, Beads records, or test suites are created by this
planning repair.
