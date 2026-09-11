# Browser Extension Protocol

## Trusted extension identity

Each Matinee release embeds the expected Chrome Web Store extension ID, store update URL,
and version range from signed release metadata. Production enrollment accepts only the
expected `chrome-extension://<id>` Origin. The pairing surface also obtains
`chrome.management.getSelf()` and requires the matching ID, `installType: normal`, store
update URL, and version. Setup displays these values for user confirmation.

An unpacked extension uses a separate development ID. Setup accepts it only with
`--allow-development-extension <id>` from an interactive terminal. Matinee records the
development channel and displays a persistent warning in status and attention surfaces.
The allowance applies to one state directory.

Production setup opens the configured Chrome Web Store listing. The pairing surface shows
the extension ID, version, install type, update URL, and daemon fingerprint before the user
confirms enrollment. The daemon can verify Origin but cannot independently attest
`management.getSelf()` values or executing extension code. A hostile same-ID runtime that
the user installed is outside Matinee's local threat boundary. The acceptance suite records
that case as accepted risk rather than claiming rejection.

## Pairing

1. Setup asks the authenticated daemon for a single-use extension enrollment with a
   ten-minute expiry, expected extension origin, daemon identity, and endpoint.
2. The daemon generates a one-time ECDSA P-256 keypair. It stores only the public key
   and returns the PKCS#8 private key through the existing encrypted native channel.
3. Setup presents the enrollment bundle as a QR code, extension link, and copyable
   base64url value. The bundle contains at least 256 bits of secret entropy.
4. The extension opens `/v1/pair` with its browser-supplied Origin and WebSocket
   subprotocol `matinee.pair.v1`. It sends no private key during the upgrade.
5. The extension and daemon establish the secure channel from `daemon-protocol.md`.
   The extension authenticates with the one-time ECDSA key and pins the daemon public
   key from the bundle. The transcript also binds endpoint and expected origin.
6. Inside that channel, the extension generates a fresh ECDSA P-256 keypair and sends
   only its public key. The daemon consumes the enrollment and activates that key in one
   transaction.
7. The extension stores its private key and pinned daemon identity in
   `chrome.storage.local`, then discards the one-time private key. The daemon stores only
   the long-term public key, fingerprint, authentication epoch, and revocation state.

The daemon permits five failed proofs per enrollment and ten failed pairing attempts per
loopback address each minute. It closes the channel after one failed proof. A consumed,
expired, rate-limited, or wrong-origin enrollment cannot pair. Re-pairing creates a new
principal and revokes the replaced principal only after user confirmation.

## Session connection

The extension connects to `/v1/extension` with its Chrome-supplied Origin and WebSocket
subprotocol `matinee.extension.v1`. It establishes the secure channel from
`daemon-protocol.md` with key fingerprint, authentication epoch, supported contract
range, expected daemon identity, ephemeral P-256 keys, and transcript signatures. The
extension verifies the daemon signature before sending a product payload.

The first encrypted message declares package version, browser identity, browser version,
profile reference, self-reported installation metadata, and capabilities. The daemon
returns authorized resumable sessions and the capability intersection. Every later frame
binds the negotiated contract and current authentication epoch as associated data.

Rotation or revocation increments the principal's authentication epoch and closes its
live channel. Messages from an old epoch fail. Revocation invalidates unconsumed approvals
and fails pending attention owned by that principal with
`authorization.trusted_surface_revoked`; no later event from that channel can complete an
operation or decide attention.

## Message envelope

```json
{
  "contract": "matinee.extension.v1",
  "message_id": "0199...",
  "correlation_id": null,
  "kind": "operation.dispatch",
  "sent_at": "2026-09-11T11:00:00.000000Z",
  "payload": {}
}
```

This envelope is the decrypted payload of an encrypted frame from
`daemon-protocol.md`. A response sets `correlation_id` to the command's `message_id`.
Delivery acknowledgment does not imply browser-effect completion.

## Extension commands

| Kind | Required behavior |
|---|---|
| `browser.describe` | Return redacted browser, profile, window, and tab candidates owned by this extension identity |
| `permission.request` | Show the Chrome runtime host-permission prompt from a user gesture |
| `session.bind` | Establish exclusive tab ownership and inject the content script |
| `session.rebind` | Prove the same browser tab and document generation after reconnect |
| `session.create_tab` | Create one visible tab for the selected browser, opaque profile, and opaque window references, then return its opaque tab reference |
| `page.observe` | Return a bounded semantic tree and document generation |
| `operation.dispatch` | Validate generation and execute one authorized operation |
| `operation.reconcile` | Inspect declared postconditions without repeating an effect |
| `attention.present` | Render redacted details in the trusted side panel |
| `file.select` | Let the user select files and return immutable metadata plus volatile handles |
| `artifact.capture` | Mask sensitive fields and capture declared evidence |

## Extension events

| Kind | Meaning |
|---|---|
| `browser.changed` | Browser, window, tab, or permission candidates changed |
| `session.bound` | Content surface established ownership and indicators |
| `session.lost` | Tab, frame, content script, or permission became unavailable |
| `document.changed` | Navigation or replacement advanced document generation |
| `operation.started` | Target validation passed and dispatch began |
| `operation.completed` | Declared result and postconditions are available |
| `operation.uncertain` | Dispatch crossed an effect boundary without a reliable result |
| `attention.decided` | The trusted side panel produced approve, deny, edit, or cancel |
| `artifact.ready` | Masked bytes and metadata are available for daemon ingestion |

The daemon authorizes every event against extension identity, authentication epoch,
session binding, pending command, operation digest, and expected document generation
before applying a transition.

## Content surface

The content script runs in an isolated world. It provides semantic observation,
generation-scoped element references, operation preflight, a Matinee tab badge, a
synthetic pointer, and target highlighting. It can display that attention is pending,
but it cannot render decision controls. Page scripts cannot access its message port.

The extension requests HTTP or HTTPS origin access at session open. A grant applies to
the requested origin only. Navigation to an ungranted origin pauses and requires a new
user permission grant. File URLs and incognito profiles are unsupported unless a later
contract explicitly adds them.

## Trusted attention decision

The extension side panel owns trusted decision controls. An `attention.decided` payload
contains:

- attention ID and original operation digest;
- approve, deny, edit, or cancel decision;
- timestamp, nonce, and current authentication epoch.

An edit contains a complete replacement operation descriptor. Non-secret parameters
appear directly. Volatile extension-local handles replace credentials and secret values;
the descriptor includes their digests and sensitivity classes. The daemon persists and
reclassifies the descriptor. It returns a handle for dispatch only on the same authenticated
connection. A missing handle creates a new `value_reentry_required` attention request.

## File selection and upload

An MCP client cannot supply a local path. `file_upload` creates an attention request that
identifies the destination origin, selected form control, requested file count, accepted
media types, and maximum size. The user chooses files through the extension side panel's
browser file picker.

The extension rejects special files and accepts browser-provided `File` objects. For each
file, it computes:

- name and media type;
- size and last-modified value;
- SHA-256 digest.

Approval binds those fields to the destination origin, control, operation digest, and one
upload. File objects remain extension-local under volatile handles. Matinee does not log,
persist, or return paths or bytes. Each file is at most 32 MiB. One operation is at most
128 MiB.

The approval becomes invalid when a file changes, its handle disappears, the connection
closes, or the service worker restarts before dispatch. The user must then select again.

## Service-worker recovery

The service worker stores extension identity, endpoint, pinned daemon identity,
negotiated contract, and resumable session identifiers in `chrome.storage.local`. It
treats operation values and file handles as disposable. On startup or WebSocket closure
it reconnects with bounded exponential backoff. Keepalive messages maintain the connection
on Chrome 116 or later but do not replace recovery.
