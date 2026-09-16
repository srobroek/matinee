# Failures and security events contract

## Stable failures and safe actions

The module bounds every failure. A failure contains one stable `boundary`, one `code`, and
one `safe_next_action`, plus an optional safe principal or connection ID. A failure never
includes:

- Private keys
- PKCS#8 enrollment material
- Enrollment secrets
- Credentials
- Cookies
- Authorization headers
- Payload text
- Full URLs
- Protected object identifiers

An unknown object, a cross-owner object, and an unauthorized object all use the same
`object.not_found` result.

| Code | Safe next action |
|---|---|
| `authentication.failed` | Verify the selected credential reference and reconnect without resending a failed proof. |
| `authorization.denied` | Request the required grant from the owning administrator. Do not infer object existence. |
| `compatibility.unsupported` | Use a peer that supports the fixed `matinee.secure-channel.v1` contract. |
| `malformed.input` | Discard the bytes and reconnect or upgrade the peer. Do not retry the same bytes. |
| `origin.rejected` | Install or enable the exact paired extension and repeat administrator-mediated pairing. |
| `replay.detected` | Discard the frame or proof and establish a fresh channel. Do not resend it. |
| `rate_limited` | Wait for the bounded retry window of the host. Do not resend proofs during that window. |
| `credential_store.unavailable` | After restoring the platform credential service and confirming availability, retry the operation. |
| `credential_store.mismatch` | Stop and inspect the selected state-directory and principal binding. Use administrator-mediated re-pairing. |
| `resource_limit` | Reduce the one-frame payload or artifact chunk to the declared bound. v1 has no secure-channel fragmentation. |
| `stale_epoch` | Reconnect with the current credential and epoch. After key loss, use administrator pairing. |
| `endpoint.rejected` | Use the configured loopback IP, route, and versioned subprotocol. |
| `revoked` | Stop the old channel and complete administrator-mediated re-pairing. |
| `transition.unknown` | Before retrying an idempotency key, inspect the transition status of the owning daemon. |
| `event_sink.unavailable` | Preserve the protected transition by failing closed and repair the downstream event sink. |

A safe action is a closed value and contains no protected field. It does not distinguish
an unknown object from an unauthorized object. A rate-limit response exposes only a
bounded retry action. That response exposes no activity of another principal and no exact
protected state.

## Security event facts

The security module emits one typed redacted fact for each of these outcomes:

- An accepted enrollment
- A rejected proof
- A rejected Origin
- An authentication failure
- An authorization denial
- A rotation
- A revocation
- A replay
- A downgrade
- A malformed input
- A resource limit
- A rate limit

Each event contains:

- A closed boundary
- A stable code
- The outcome
- The safe next action
- Optional safe UUIDs
- A typed time
- The state-directory identity
- Redacted metadata

The encoded event is at most 2,048 bytes. Metadata has at most eight entries. Each key is
at most 32 UTF-8 bytes, and each value is at most 128 bytes. Total metadata is at most
512 bytes. An event never contains:

- Private keys
- One-time PKCS#8 enrollment keys
- Enrollment secrets
- Credentials
- Cookies
- Authorization headers
- Payload text
- Full URLs
- Protected object identifiers

## Typed event sink

The sink accepts one `SecurityEvent`. It returns exactly one of `accepted`, `aggregated`,
or `unavailable`. It aggregates repeated failures by four keys:

- The boundary
- The stable code
- The safe principal and connection IDs
- The class of endpoint

The sink keeps at most 64 active aggregation buckets and saturates each bucket count at
255. The security module emits no unbounded queue. That module defines no persistence, no
retention, and no clock trait.

If the sink is unavailable for an event that must justify a security transition, the
module returns `event_sink.unavailable` and performs no protected mutation. Health-only
liveness may remain bounded and must expose no identity or state. The sink may aggregate
repeated facts about failures. It must never aggregate away a required transition outcome.

Spec 015 owns five downstream concerns:

- The durable event schema
- Digest chaining
- Retention
- Quotas
- Read and export authorization

Its minimum security floor has three parts:

- Authorization and filtering precede every serialization and export.
- The state-directory identity scopes the digest chain.
- A failure of predecessor or digest verification returns a safe untrusted-history
  diagnostic.

A broken chain is never trustworthy history, and it never authorizes a transition.

## Redaction and dispatch invariant

Before payload dispatch, the receive path rejects input that is:

- Malformed
- Oversized
- Stale
- Replayed
- Wrong-direction
- Cryptographically invalid

Before the typed output reaches the sender, authorization filters four output kinds:

- Events
- Status
- Artifacts
- Stream chunks

Every failure and every event reports only its boundary, its stable reason class, and one
safe action.
