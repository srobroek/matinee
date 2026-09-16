# Bootstrap and enrollment contract

## Native bootstrap

Setup and the daemon exchange bounded envelopes. They use inherited anonymous
operating-system pipes only. Unix uses inherited file descriptors with close-on-exec.
Windows uses explicitly inherited anonymous handles. The envelope binds:

- A fresh nonce
- The state-directory identity
- The daemon identity
- The bootstrap ID
- The native public key

Native private-key bytes stay in the selected credential store. Those bytes never enter
the bootstrap envelope.

The daemon creates or reuses one daemon identity. It commits one native administrator
through an atomic transition. A retry that carries the same bootstrap identity and the
same public key returns the recorded outcome. Four inputs fail without changing any
registration:

- A different identity
- A missing or mismatched credential
- A duplicate envelope
- A malformed envelope

First-principal bootstrap never uses loopback.

## Extension enrollment and the inherited private-key exception

An authenticated administrator requests a one-use bundle. That bundle contains:

- A 32-byte secret
- The expected `chrome-extension://` Origin
- The extension store metadata
- The extension update metadata
- The extension install metadata
- The daemon fingerprint
- The daemon endpoint
- The enrollment ID
- The one-time public key
- A ten-minute expiry

Spec 001 requires one exception. The daemon generates a one-time ECDSA private key in
PKCS#8 form. For this bundle, the daemon returns that key through the authenticated
encrypted native channel. This exception is explicit in FR-003, so the bundle is not
public-key-only enrollment.

The setup path presents that one-time bundle through a trusted ceremony. The ceremony
uses a QR code, an extension link, or a copyable base64url value. The one-time private
key is transient setup custody. Never put that key in:

- Bootstrap pipes
- Unauthenticated loopback
- Plaintext transport
- Durable state
- Logs
- Diagnostics
- Status
- Enrollment records

Transport captures contain only AEAD ciphertext.

On `/v1/pair`, the extension uses the one-time key exactly once. After that call, the
extension generates a fresh long-term ECDSA keypair. It sends only the public key of that
keypair. The daemon consumes the enrollment and registers that public key atomically.

The extension stores the long-term private key in `chrome.storage.local`. Where the
browser supports the semantics, that key is a non-exportable WebCrypto key. Alongside it
the extension stores a versioned record and the pinned daemon identity. It stores no raw
PKCS#8 backup, and it offers no backup path and no profile-export path. If the browser
cannot preserve the required key semantics, pairing fails closed.

Rotation or revocation deletes or quarantines a stale key record. A missing, unusable, or
stale key returns `credential_store.mismatch` or `revoked`. The extension never silently
generates a replacement. Administrator-mediated re-pairing creates a new principal, or it
performs an explicit rotation. Either path advances the epoch, closes old channels, and
records one idempotent outcome. Uninstall, profile restore, and storage clearing all use
this same fail-closed path.

## Independent failure budgets

The host budget and the enrollment budget are independent, and both preserve the scopes
that Spec 001 sets:

- The host key is `(state-directory, loopback address)`. It permits at most ten failed
  attempts to pair, in a 60-second window. The window begins with the first counted
  failure. After 60 seconds of the owning typed time result, the window resets. A
  successful pairing does not reset it. Before proof work, the eleventh attempt returns
  `rate_limited`. That attempt increments no enrollment proof count and exposes only a
  bounded retry action.
- Each pending enrollment permits at most five failed proofs. The channel closes after
  every failed proof. The fifth failure permanently closes that enrollment. The proof
  count resets only when an administrator creates a new enrollment. A reset of the host
  window does not reset the proof count.

A malformed or unknown envelope cannot bind to a pending enrollment, so it counts only
against the host budget. A proof failure that binds to a pending enrollment counts
against both budgets. Each of these events closes the enrollment:

- Expiry
- Consumption
- Revocation
- Proof-limit exhaustion

All increments and state changes serialize in one transition boundary.

Exhausting the host key denies other local peers that share the loopback address. That
denial is the inherited bounded local threat tradeoff. Spec 006 does not silently
re-scope it.

## Typed transition and expiry inputs

The contract consumes the typed transition input and outcome that Spec 007 defines. An
`unknown` outcome fails closed and cannot report a protected success. The contract also
consumes the typed `valid|expired|uncertain` expiry result that Spec 009 defines. It
rejects `uncertain` for an enrollment decision or an authentication decision. Spec 006
defines no persistence trait and no clock trait.
