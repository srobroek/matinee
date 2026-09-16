# Phase 0 Research: Identity, Authorization, and Secure Channels

## Existing contract baseline

**Decision:** Treat Spec 001 `daemon-protocol.md`, `extension-protocol.md`, and
`mcp-schemas.md` as normative for route names, identity profile, encodings, frame
limits, enrollment transfer, roles, and event redaction. Spec 005's implemented
two-crate workspace supersedes only Spec 001's proposed five-crate repository layout.

**Evidence:** The current workspace contains `matinee-cli` and `matinee-runtime` only.
Spec 005 states that later specifications add their assigned domain, protocol, store,
daemon, and extension implementations. Spec 006 therefore adds only
`crates/matinee-security` and does not assign files to later crates.
The root virtual workspace manifest must add `crates/matinee-security` as a member. The new crate manifest belongs to Spec 006 and declares the direct dependency set. Cargo must generate the resulting root `Cargo.lock`; implementation must never hand-edit lockfile contents.

## Dependency baseline and MSRV evidence

**Decision:** Pin `keyring = 3.6.3` with features `apple-native`, `windows-native`, `linux-native-sync-persistent`, and `crypto-rust`, and disable default features explicitly. The selected release declares Rust 1.75 compatibility, so it remains compatible with the workspace Rust 1.85 minimum while covering the macOS, Windows, and Linux credential-store backends required by Spec 006.

**Rejected alternative:** `keyring 4.0.0` requires Rust 1.88 and cannot support the fixed Rust 1.85 workspace. This is a deliberate departure from the Spec 001 dependency baseline and requires an ADR candidate before implementation records the final decision. No plaintext fallback is permitted.


## Deep-module boundary

**Decision:** Add one `matinee-security` crate with a stateful channel/session boundary.
Session establishment performs the inherited handshake internally. Its receive operation
validates the v1 frame, decrypts it, checks counter, epoch, lifecycle, and authorization,
and returns only an `AuthorizedInput` typed for the permitted capability. Its send
operation accepts only an authorized typed output and seals it internally. Raw frame
encoding/decoding, transcript construction, Origin parsing, and authorization policy
ordering remain private.

Lifecycle changes use one closed `SecurityCommand` set for bootstrap, enrollment
creation/consumption, rotation, and revocation. Callers cannot invoke separate
`authenticate`, `authorize`, `encode_frame`, or `decode_frame` functions, mutate epochs,
or bypass the receive ordering.

**Real seams:** Keep only private `CredentialStore` and inherited `OsPipe` adapters.
The security crate does not define clock, persistence, Origin, or cryptographic-library
traits. It consumes typed expiry/deadline and transition results from their future
owners, and it emits typed event facts to the event sink boundary.

## Critique P1/E1 disposition: rejected public-key-only enrollment

The critique's proposed removal of the FR-003 private-key transfer exception is
**rejected**. Spec 001 `daemon-protocol.md:111-120` requires the daemon-generated
one-time ECDSA keypair, returns its PKCS#8 private key through the encrypted native
channel, and requires the extension to use that key once before generating its
long-term key. Spec 001 `extension-protocol.md:25-40` repeats the same pairing carrier
and says that only the long-term public key crosses the authenticated pairing channel.

FR-003 remains unchanged. The transfer is permitted only inside the authenticated
encrypted native channel, never through bootstrap pipes, loopback before authentication,
plaintext transport, durable application state, logs, diagnostics, or status output.
The one-time key is transient setup custody and is discarded after pairing. Native
transport captures contain ciphertext, not the decrypted bundle. This preserves the
reviewed contract without weakening private-key custody.

## Cryptographic and wire profile

**Decision:** Use the fixed context `matinee.secure-channel.v1` and the inherited
P-256 ECDSA-SHA-256 identity proofs, P-256 ephemeral ECDH, HKDF-SHA-256, and
AES-256-GCM profile. Use `ring 0.17.x` for native reviewed primitives and WebCrypto
for the extension peer. Encode integers unsigned big-endian, strings as exact UTF-8
with four-byte length prefixes, UUIDs as 16 raw bytes, public keys as 65-byte SEC1
uncompressed points, and signatures as exactly 64-byte IEEE P1363 `(r || s)`. Fingerprints
are lowercase hexadecimal SHA-256 over the exact 65 public-key bytes.

The canonical handshake fields and signatures are those in Spec 001. The selected
contract, endpoint, identities, epoch, connection ID, nonces, direction, and context
are transcript-bound. No alternate encoding, DER signature, compressed key, or v1
algorithm negotiation is accepted.

## Inherited v1 frame and nonce construction

The encrypted WebSocket frame is exactly 25 header bytes followed by AES-GCM ciphertext
and its 16-byte tag:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | frame version `0x01` |
| 1 | 16 | raw connection UUID |
| 17 | 8 | unsigned big-endian counter |
| 25 | remaining | ciphertext followed by the 16-byte tag |

The counter is directional, starts at zero, and must equal the receiver's next expected
value. Duplicate, skipped, wrong-direction, stale-epoch, malformed, or wrapped counters
close the channel before dispatch. The sender refuses to encrypt after counter
`u64::MAX`; the receiver accepts that value once and then closes on any subsequent frame.

The 12-byte AES-GCM nonce is `direction_u32_be || counter_u64_be`. Direction is
`0x00000000` for client-to-daemon and `0x00000001` for daemon-to-client. AAD is the
first 25 frame bytes followed by `LP("matinee.secure-channel.v1")`,
`LP(selected_application_contract)`, the eight-byte authentication epoch, and
`LP(direction)`. Vectors assert nonce bytes and AAD bytes for both directions at
counter zero, counter one, `u64::MAX`, and overflow.

## Limits and v1 fragmentation rule

The inherited WebSocket frame limit is 1 MiB and the decrypted-message upper bound is
4 MiB. v1 has no secure-channel fragmentation or reassembly. One decrypted payload is
one frame, so the frame limit is tighter: with a 25-byte header and 16-byte tag, the
maximum v1 plaintext is `1,048,535` bytes. The 4 MiB value remains the inherited
decrypted-message ceiling for the protocol family, but no v1 session can carry a larger
single payload. Application artifact streams use the inherited bounded artifact-chunk
format, with each chunk in its own frame; the security module never buffers fragments.
Reject encoded frames and declared lengths before allocation. A rejected oversize,
malformed, or invalid-AEAD frame closes the channel and dispatches no payload.

## Bootstrap and enrollment

First-principal setup uses inherited anonymous OS pipes only. Unix uses close-on-exec
inherited file descriptors and Windows uses explicitly inherited anonymous handles. The
bounded bootstrap envelope binds a fresh nonce, daemon identity, selected state-directory
identity, bootstrap ID, and native public key. The private native key remains in the
credential store. Commit is an atomic transition supplied by the daemon owner; retry
with the same bootstrap identity converges, while a different identity fails.

An authenticated administrator requests a one-use extension enrollment. The daemon
generates a 32-byte-secret, ten-minute bundle with expected Origin/install metadata,
daemon fingerprint, endpoint, enrollment ID, and one-time public/private keypair. The
private PKCS#8 key crosses only the authenticated native channel required by Spec 001.
The extension uses that key once on `/v1/pair`, generates a fresh long-term ECDSA key,
and sends only its public key for atomic registration.

The extension stores the long-term key as a non-exportable WebCrypto key where the
browser supports that flag, together with a versioned record and pinned daemon identity
in `chrome.storage.local`. It never stores a raw PKCS#8 backup and does not support
backup or profile export. If the browser cannot provide the required key semantics,
pairing fails closed rather than downgrading to raw private-key storage.

Rotation or revocation causes the extension to delete or quarantine stale local key
records and reconnect only after proving the current epoch. A missing, unusable, or
stale key returns `credential_store.mismatch` or `revoked`; it never silently regenerates
access. Administrator-mediated re-pairing creates a new principal or explicitly rotates
the old principal, advances the epoch, closes old channels, and records one idempotent
transition. Uninstall, profile restore, and storage clearing follow the same fail-closed
path.

## Origin and endpoint checks

Origin and endpoint checks are private implementation logic, not adapters. Canonicalize
the endpoint as scheme, lowercase host, and explicit port. Accept only configured
`127.0.0.1` or `::1` literals, the expected route, and the expected WebSocket
subprotocol. Reject DNS aliases, wildcard binds, non-default paths, and unexpected
subprotocols. Production pairing requires the pinned `chrome-extension://<id>` Origin,
store ID, normal install type, update URL, and supported version. Development IDs
require an explicit interactive allowance and a visible warning. A replaced extension
runtime remains the documented local accepted-risk boundary.

## Enrollment budgets and races

Preserve two independent inherited budgets:

1. The host budget keys on `(state-directory, loopback address)` and allows at most ten
   failed pairing attempts in a 60-second window. The window starts with the first
   counted failure and resets after 60 seconds of the owning time result. The eleventh
   attempt is rejected as `rate_limited` before proof work, does not increment the
   enrollment counter, and returns only a bounded retry action. A successful pairing
   does not reset the host window.
2. Each enrollment counts failed proofs independently and closes after the fifth.
   The current channel closes after each failed proof. The enrollment counter resets
   only when an administrator creates a new enrollment; it never resets because the
   host window resets. Expiry, consumption, revoke, or the fifth failure closes the
   enrollment permanently.

Malformed or unknown envelopes that cannot bind to an enrollment count only against the
host budget. A proof failure bound to a pending enrollment counts against both budgets.
All checks and increments occur under one transition boundary. Host-wide denial of
other local clients is an inherited local threat tradeoff because all supported peers
share loopback addresses; the bounded denial is documented rather than silently
changing the Spec 001 budget key.

## Authorization and privacy

The session receive path evaluates principal kind, capability ceiling, negotiated
contract, current epoch/lifecycle, owner, extension grant, and requested action before
serialization or mutation. Unknown, cross-owner, and unauthorized lookups return the
same `object.not_found` envelope. Filtering occurs before serialization for status,
events, artifacts, and stream chunks. A grant cannot exceed its principal ceiling.

## Typed transition and expiry inputs

Spec 007 supplies state-directory identity, transition ID, operation, idempotency key,
prior epoch, and `committed`, `already_committed`, `rejected`, or `unknown` outcome.
Security treats `unknown` as a safe failure and does not persist or
recovery. Spec 009 supplies `valid`, `expired`, or `uncertain` expiry/deadline results;
security treats `uncertain` as invalid for enrollment and epoch decisions. The module consumes these typed values. They do not block
Spec 006 work.

## Security events and sink contract

Emit a typed event with closed boundary/code/outcome/action enums, optional safe UUIDs,
typed time, and redacted metadata. The encoded event is at most 2,048 bytes. Metadata
has at most eight entries, each key is at most 32 UTF-8 bytes, each value is at most
128 bytes, and total metadata is at most 512 bytes. Never include private keys,
enrollment secrets, credentials, cookies, authorization headers, payload text, full
URLs, or protected object identifiers.

The sink accepts `SecurityEvent` and returns `accepted`, `aggregated`, or `unavailable`.
Aggregation uses boundary, stable code, safe IDs, and endpoint class as the key, with
at most 64 active buckets and a saturating count of 255. A required event with an
unavailable sink fails the related security transition closed without protected
mutation. Spec 015 owns durable representation, digest chaining, retention, quotas,
and read/export authorization. Its minimum floor is filtering before serialization,
state-directory chain scoping, and an untrusted-history diagnostic on predecessor or
digest verification failure.

## Reproducible evidence

Vectors must include valid bytes and one mutation at every field boundary for both Rust
and WebCrypto. The malformed campaign must cover every length prefix, invalid UTF-8,
key/signature length, header field, direction, counter, AEAD tag, payload kind, and
v1 frame/aggregate limit. Evidence records the input class, pre-allocation rejection,
maximum allocation, dispatch count, channel state, event fields, and secret scan result.
The campaign has 100,000 bounded cases and has no performance pass/fail threshold.

## Decisions and non-blocking revisits

- The Spec 001 wire profile, v1 frame, counter, nonce, and AAD are fixed. A future
  algorithm or framing change needs a new context/version and migration decision.
- `ring 0.17.x`, `keyring 3.6.3` with explicit native and Rust-crypto features, `serde 1.x` with derive, and `uuid 1.x` with `v7,serde`
  are the concrete native dependencies. No second crypto library is introduced.
- Spec 007 owns transition persistence/recovery, Spec 009 owns time, and Spec 015 owns
  event persistence/retention/access. Their typed inputs are integration prerequisites,
  not blockers for Spec 006 task generation.
- The extension has no private-key backup. Missing or stale local keys require
  administrator-mediated fail-closed re-pairing.

No unresolved `NEEDS CLARIFICATION` remains. No source files, implementation tasks,
or Beads records are created by this research repair.
