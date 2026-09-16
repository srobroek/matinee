# Spec 006 quickstart validation

This guide validates the security contracts. It needs no browser-operation implementation
and no daemon-lifecycle implementation. Use a disposable state directory and a test Chrome
profile. Never use a real profile, a real credential, or a real enrollment key.

## Prerequisites

- Rust 1.85, with `crates/matinee-security` registered in the root `Cargo.toml`.
- A focused `matinee-security` fixture crate with these dependencies:
  - `ring 0.17.x`
  - `keyring 3.6.3`, with these feature settings:
    - `default-features = false`
    - `apple-native`
    - `windows-native`
    - `linux-native-sync-persistent`
    - `crypto-rust`
  - `serde 1.x` with `derive`
  - `uuid 1.x` with `v7,serde`
- A root `Cargo.lock` that Cargo generated after the manifest edits. Never hand-edit that
  lockfile.
- Node and pnpm.
- A browser that provides the WebCrypto primitives used by the vector peer and extension storage through `chrome.storage.local`.
- A fixture credential-store adapter.
- A fixture adapter for inherited operating-system pipes.
- Typed Spec 007 transition-result fixtures.
- Typed Spec 009 fixtures for expiry results and deadline results.

Create no clock trait and no persistence trait in the fixture.

## Run protocol vectors

1. Generate or load the versioned vectors under `crates/matinee-security/vectors/`.
2. Run the focused vector checks for the native peer.
3. Run the focused vector checks for the extension peer.
4. Confirm that a valid handshake establishes a stateful session.
5. Confirm that `receive` emits only an authorized typed input. It emits that input after
   these checks:
   - The frame check
   - The AEAD check
   - The epoch check
   - The lifecycle check
   - The authorization check
6. Confirm that callers cannot invoke raw encoding or decoding of a frame.
7. Confirm that callers cannot invoke an independent authentication or authorization
   function.

A valid vector uses the fixed profile: P-256 with P1363, HKDF-SHA-256, and AES-256-GCM.
The frame is exactly these fields:

- The version byte `0x01`
- A 16-byte connection UUID
- An eight-byte big-endian counter
- The ciphertext
- A 16-byte tag

Counters start at zero. Nonce vectors assert `direction_u32_be || counter_u64_be` for both
directions, at these counter values:

- Zero
- One
- `u64::MAX`
- Overflow

AAD vectors assert the first 25 frame bytes, followed by these four values in order:

- The context
- The contract
- The epoch
- The direction

Invalid vectors include these cases:

- A DER signature
- A compressed key
- An alternate length
- An altered endpoint
- An altered epoch
- An altered contract
- An altered nonce
- An altered signature
- A replay
- A wrong direction
- A duplicate counter
- A skipped counter
- A stale epoch
- An invalid tag
- Malformed UTF-8
- An oversized frame

Before payload dispatch, every invalid vector closes the session or returns its bounded
failure. v1 has no secure-channel fragmentation. One frame carries one payload. The
effective plaintext maximum is therefore 1,048,535 bytes, even though the inherited
protocol family sets a decrypted-message ceiling of 4 MiB.

## Bootstrap and enrollment scenarios

Run a disposable fixture for each of these bootstrap cases:

- A clean bootstrap
- A crash before commit
- A crash after commit
- A same-identity retry
- A mismatched identity
- A missing or mismatched credential
- A malformed envelope
- A different-identity retry

Confirm exactly one daemon identity and exactly one native administrator. Confirm that no
private bytes appear in a bootstrap capture or in durable state.

Run extension enrollment for each of these cases:

- A valid proof
- A wrong Origin
- Wrong install metadata
- An expired enrollment
- A consumed enrollment
- A revoked enrollment
- A replayed proof
- A wrong identity
- A malformed proof
- A concurrent consumption

Show the Spec 001 exception in the fixture. The one-time PKCS#8 key appears only in the
bundle operation over the authenticated encrypted native channel. Transport captures
contain ciphertext. Confirm that the extension does all of the following:

- It uses that key once.
- It creates a fresh long-term key.
- It sends only its public key.
- It discards the one-time key.

No private key appears in any of these places:

- Durable state
- Logs
- Diagnostics
- Status
- Unauthenticated transport

Verify these properties of the long-term extension key:

- Where the browser supports the semantics, the key is non-exportable.
- The extension stores the key in `chrome.storage.local` without a raw backup.
- Rotation or revocation deletes or quarantines the key.

Then run three recovery probes: clear storage, restore a profile without the key, and
simulate uninstalling the extension. Each case returns `credential_store.mismatch` or
`revoked`. Each case requires administrator-mediated pairing of a new principal, or an
explicit rotation. No case silently regenerates access.

## Independent failure-budget scenarios

Use two pending enrollments and two loopback peers.

For the host budget, count ten failed attempts to pair under one `(state-directory,
loopback address)` key. The tenth is the last counted attempt. Before proof work, the
eleventh returns `rate_limited`.

Advance the typed Spec 009 time result by 60 seconds and confirm that the host window
resets. Confirm that a successful pairing does not reset the window. Confirm that a new
enrollment does not reset it either. Record only the bounded retry action.

For one enrollment, submit five failed proofs across separate channels. After its own
failed proof, each channel closes. The fifth closes the enrollment permanently. Confirm
that a reset of the host window does not reset this count. Create a new enrollment and
confirm that only the new enrollment has a fresh proof budget. A malformed or unknown
envelope cannot bind to an enrollment, so it counts only against the host budget.

Exhaust one host key. Confirm that the module denies a second local peer until the reset.
Record that result as the inherited bounded host-wide denial tradeoff. Do not record it as
a per-principal budget.

## Stateful authorization scenarios

Create an administrator, two MCP principals, and one extension with bounded grants. Feed
each encrypted frame through the session receive path. Exercise these inputs:

- An owned input
- An unknown input
- A cross-owner input
- An over-ceiling input
- A stale-epoch input
- A revoked input
- A filtered event input
- A filtered stream input

Confirm that the module types and bounds an authorized result. Confirm that an
unauthorized read uses the indistinguishable `object.not_found` result. Confirm that
plaintext never leaves the module until authorization succeeds.

Run rotation and revocation against four conditions:

- A live channel
- Pending extension decisions
- A concurrent handshake
- Repeated idempotency keys

Confirm each of these outcomes:

- The replacement registration precedes the epoch transition.
- Old channels close.
- A stale frame dispatches no payload.
- Grants invalidate.
- A repeated transition returns the recorded typed outcome without a duplicate mutation.

Feed an `unknown` Spec 007 transition result and an `uncertain` Spec 009 expiry result.
Both must fail closed.

## Origin, endpoint, and malformed-input scenarios

Probe each of these bindings and identities:

- A non-loopback binding
- A DNS loopback alias
- A wrong route or subprotocol
- A wrong browser Origin
- Wrong production store, update, or install metadata
- A development identity without an explicit allowance

Probe each of these malformed inputs:

- Malformed UTF-8
- An invalid four-byte length
- An unknown payload kind
- A wrong-direction frame
- A duplicate, skipped, or wrapped counter
- An invalid tag
- An oversized frame
- A payload over 1,048,535 bytes

Expect these results:

- One stable tuple of boundary, code, and safe next action
- A redacted event
- Channel closure where the contract requires it
- Zero product dispatch

Health-only liveness may respond. Expose no identity and no state in that response.

## Event sink and evidence scenarios

Emit every required event class, including these outcomes:

- Enrollment
- Proof
- Origin
- Authentication
- Authorization
- Rotation
- Revocation
- Replay
- Downgrade
- Malformed input
- Resource limit
- Rate limit

Assert these bounds:

- An encoded event is at most 2,048 bytes.
- Metadata has at most eight entries.
- Each key is at most 32 bytes.
- Each value is at most 128 bytes.
- Total metadata is at most 512 bytes.

Flood repeated failures and confirm at most 64 active aggregation buckets, with a
saturating count of 255. Return `unavailable` from the sink. Confirm that the required
transitions fail closed and make no protected mutation.

The downstream Spec 015 fixture must do all of the following:

- Before export, it filters events.
- It scopes digest chains to the state-directory identity.
- It surfaces a broken predecessor or digest verification as an untrusted-history
  diagnostic.

Retention, quota, and access policy remain downstream. Two further checks apply:

- For an accepted event and for an aggregated event, verify continuity of the predecessor
  and of the digest across sink flushes.
- Tamper with one predecessor or one digest. Confirm that the downstream result is an
  untrusted-history diagnostic that cannot authorize a transition.

Run 100,000 malformed and oversized cases across each parser boundary. Record these fields
per case:

- The case ID
- The input class
- The pre-allocation rejection
- The maximum allocation
- The channel state
- The dispatch count
- The emitted event fields
- The secret-scan result

For a rejected case, every dispatch count must be zero. Do not use a latency threshold as
acceptance evidence.

## Evidence checklist

Record these values:

- The vector IDs
- The scenario inputs
- The failure boundary, code, and action
- The typed transition result or expiry result
- Whether any mutation or event occurred

Assert that none of the following appears in output:

- A private key
- A one-time enrollment key
- An enrollment secret
- A cookie
- An authorization header
- A credential
- Payload text
- A full URL
- Protected object metadata

Map results to FR-002 through FR-032, and to SC-001 through SC-009. Spec 007 supplies the
lifecycle and recovery evidence, and Spec 009 supplies the clock and expiry evidence. The
typed contracts of those two specifications do not block these Spec 006 vectors.
