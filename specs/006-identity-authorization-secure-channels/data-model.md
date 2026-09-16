# Data Model

All durable identifiers are UUIDv7 unless noted. Secret fields are write-only or
transient and MUST never be serialized into durable state, logs, diagnostics, errors,
or unauthenticated transport.

## Entities

- **DaemonIdentity**: `id`, 65-byte uncompressed public key, lowercase-hex SHA-256
  fingerprint, loopback endpoint binding, supported contract range, credential
  reference, and lifecycle (`staged|active|replaced`). One active identity exists per
  state directory.
- **Principal**: `id`, kind (`native_admin|mcp_client|browser_extension`), public
  key/fingerprint, immutable owner identity, capability ceiling, lifecycle
  (`pending|active|rotating|revoked`), authentication epoch, credential reference,
  and extension metadata when applicable.
- **CredentialReference**: opaque provider plus stable key locator bound to one
  daemon/state identity. It never contains private-key bytes. Native private keys stay
  in the platform store. The extension stores its non-exportable long-term WebCrypto
  key and pinned daemon identity in `chrome.storage.local` without backup.
- **ExtensionEnrollment**: one-time ID, expected Origin and extension metadata,
  daemon fingerprint/endpoint, one-time public-key fingerprint, typed expiry result,
  failed-proof count, and lifecycle (`pending|consumed|closed|expired|revoked`). The
  32-byte secret and one-time PKCS#8 private key are transient. The PKCS#8 key may
  cross only the authenticated native channel required by Spec 001.
- **Connection**: connection ID, principal ID, negotiated contract, epoch, client and
  daemon nonces, directional key handles/base nonces, next send/receive counters, and
  lifecycle (`handshaking|authenticated|closing|closed`). Each directional counter
  starts at zero.
- **ChannelSession**: the stateful receive/send boundary over one authenticated
  `Connection`. It owns frame parsing, AEAD, counter, epoch/lifecycle, authorization,
  and typed input/output ordering. Raw plaintext is not returned before all checks.
- **AuthorizedInput**: one typed command/event/stream chunk that passed frame,
  connection, epoch, lifecycle, capability, owner, grant, and action checks. It has no
  private key, raw frame, or unauthorized object fields.
- **AuthorizedOutput**: one typed response/event/stream chunk already filtered for the
  principal. The session seals it and chooses all v1 framing fields privately.
- **SecurityCommand**: closed lifecycle command enum for bootstrap, enrollment
  creation/consumption, rotation, and revocation. Callers cannot mutate lifecycle or
  epoch fields directly.
- **Capability**: closed action enum and resource scope. A requested set is a subset
  of the principal ceiling.
- **ExtensionGrant**: extension principal, session/object owner, bounded capability
  subset, grant lifecycle, and epoch binding.
- **RotationTransition**: idempotency key, principal, old/new fingerprints, old/new
  epochs, effective boundary, and redacted outcome.
- **RevocationTransition**: idempotency key, principal, reason class, epoch,
  invalidated channel/grant counts, and redacted outcome.
- **SecurityEvent**: event ID, boundary, stable code, safe principal/connection IDs,
  reason class, outcome, next action, typed time, redacted metadata, and state-directory
  identity. Encoded size is at most 2,048 bytes. Metadata has at most eight entries;
  each key is at most 32 UTF-8 bytes, each value at most 128 bytes, and total metadata
  at most 512 bytes.
- **SecurityEventSinkResult**: closed result `accepted|aggregated|unavailable`.
  Aggregation has at most 64 active buckets keyed by boundary, code, safe IDs, and
  endpoint class. Each bucket count saturates at 255.
- **TransitionInput**: typed value supplied by Spec 007 with state-directory identity,
  transition ID, operation kind, idempotency key, prior epoch, and outcome
  (`committed|already_committed|rejected|unknown`). Security treats `unknown` as
  fail-closed and does not persist.
- **ExpiryResult**: typed value supplied by Spec 009 with status
  (`valid|expired|uncertain`) and bounded expiry/deadline data. Security treats
  `uncertain` as invalid for security-sensitive work and does not implement a clock.

## Invariants and state transitions

`pending -> active` is atomic for bootstrap and enrollment. `active -> rotating -> active`
registers replacement material and increments the epoch; old credentials and channels
are invalid at that boundary. `active -> revoked` is terminal and idempotent. Enrollment
`pending -> consumed` occurs exactly once. Expiry, revoke, or the fifth bound proof
failure closes it.

Session establishment completes the inherited handshake before any product payload.
`ChannelSession::receive` validates the exact v1 frame, decrypts it, checks the expected
directional counter, checks epoch/lifecycle, evaluates authorization, and then returns
only `AuthorizedInput`. Counter, AEAD, endpoint, Origin, stale-epoch, malformed, or
authorization failures close or reject before dispatch as specified by the boundary.

Authorization evaluates kind, ceiling, contract, epoch, owner, grant, and action before
object lookup serialization or mutation. Unknown, cross-owner, and denied object
lookups map to indistinguishable `object.not_found`.

The host failure budget and enrollment budget are independent. The host key is
`(state-directory, loopback address)` with at most ten failed pairing attempts in a
60-second window. The eleventh attempt returns `rate_limited` before proof work. A
pending enrollment counts proof failures independently and closes at the fifth; its
counter resets only when a new enrollment is created. The host window does not reset
when an enrollment resets. Host-wide denial of another loopback client is the inherited
bounded local threat tradeoff.

The extension deletes or quarantines local key records after rotation or revocation and
must prove the current epoch before reconnecting. Missing, unusable, or stale local
keys fail closed as `credential_store.mismatch` or `revoked`; automatic regeneration
and private-key backup are forbidden. Administrator-mediated re-pairing creates a new
principal or an explicit rotation transition.

## Validation limits and v1 wire rules

- Enrollment secret: 32 random bytes minimum.
- Failed proofs: maximum five per enrollment; the current channel closes after each
  failed proof, and the fifth closes the enrollment.
- Failed pairing attempts: maximum ten per loopback address per 60-second window.
- Frame layout: version byte `0x01`, 16-byte raw connection UUID, eight-byte unsigned
  big-endian counter, then ciphertext and a 16-byte tag. No direction, contract, or
  epoch fields are added to the header.
- Counter: unsigned 64-bit, starts at zero, exact next value; `u64::MAX` is accepted
  once and cannot be incremented or wrapped.
- Nonce: 12 bytes `direction_u32_be || counter_u64_be`; direction zero is
  client-to-daemon and direction one is daemon-to-client.
- AAD: first 25 frame bytes, then `LP("matinee.secure-channel.v1")`,
  `LP(selected_application_contract)`, eight-byte authentication epoch, and
  `LP(direction)`.
- Encoded frame: 1 MiB maximum. Decrypted-message family limit: 4 MiB. v1 has no
  secure-channel fragmentation, so one payload is one frame and the effective v1
  plaintext maximum is `1,048,535` bytes (`1 MiB - 25 - 16`).
- Length prefixes: unsigned four-byte big-endian; reject before allocation.
- Public key: exactly 65 bytes uncompressed P-256; signature exactly 64-byte P1363.
- Security-event metadata: eight entries, 32-byte keys, 128-byte values, 512-byte
  total, and 2,048-byte encoded event maximum.

## Typed downstream ownership

Spec 007 owns transition persistence, serialization, reconciliation, and durable state.
Spec 009 owns expiry/deadline calculation and uncertainty. Spec 015 owns event storage,
digest-chain verification, retention, quotas, and read/export authorization. These specifications consume the typed entities above. They preserve the security
ordering or create a reverse dependency.
