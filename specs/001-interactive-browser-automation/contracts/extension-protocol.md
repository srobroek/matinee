# Browser Extension Protocol

## Pairing

1. Setup asks the daemon for a single-use pairing code with a ten-minute expiry.
2. The user opens the installed extension and enters or confirms that code.
3. The extension opens `/v1/pair` with `Origin: chrome-extension://<extension-id>` and
   WebSocket subprotocol `matinee.pair.v1`.
4. The daemon consumes the code, records the exact origin, creates an extension
   principal, and returns its credential through that authenticated loopback WebSocket.
5. The extension stores the credential in `chrome.storage.local`. The daemon stores
   only its hash, identifier, rotation metadata, and revocation state.

A consumed or expired code cannot be retried. Re-pairing creates a new principal and
revokes the replaced credential only after user confirmation.

## Session Connection

The extension connects to `/v1/extension` with its bearer credential, exact Origin,
and WebSocket subprotocol `matinee.extension.v1`. The first message declares package
version, contract range, browser identity, browser version, profile reference, and
capabilities. The daemon returns the negotiated contract and resumable sessions.

## Message Envelope

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

A response sets `correlation_id` to the command's `message_id`. Delivery acknowledgments
do not imply browser-effect completion.

## Extension Commands

| Kind | Required behavior |
|---|---|
| `browser.describe` | Return redacted browser, profile, window, and tab candidates |
| `permission.request` | Show the Chrome runtime host-permission prompt from a user gesture |
| `session.bind` | Establish exclusive tab ownership and inject the content script |
| `session.rebind` | Prove the same browser tab and document generation after reconnect |
| `session.release` | Remove indicators and release ownership |
| `page.observe` | Return a bounded semantic tree and document generation |
| `operation.dispatch` | Validate generation and execute one operation |
| `operation.reconcile` | Inspect declared postconditions without repeating the effect |
| `attention.present` | Render redacted details and decision controls |
| `artifact.capture` | Mask sensitive fields and capture declared evidence |

## Extension Events

| Kind | Meaning |
|---|---|
| `browser.changed` | Browser, window, tab, or permission candidates changed |
| `session.bound` | Content surface established ownership and indicators |
| `session.lost` | Tab, frame, content script, or permission became unavailable |
| `document.changed` | Navigation or replacement advanced document generation |
| `operation.started` | Target validation passed and dispatch began |
| `operation.completed` | Declared result and postconditions are available |
| `operation.uncertain` | Dispatch crossed an effect boundary without a reliable result |
| `attention.decided` | The paired user surface produced approve, deny, edit, or cancel |
| `artifact.ready` | Masked bytes and metadata are available for daemon ingestion |

## Content Surface

The content script runs in an isolated world. It provides semantic observation,
generation-scoped element references, operation preflight, a Matinee tab badge, a
synthetic pointer, and target highlighting. It can display that attention is pending,
but it cannot render decision controls. Page scripts cannot access its message port.

The extension requests HTTP or HTTPS origin access at session open. A grant applies to
the requested origin only. Navigation to an ungranted origin pauses and requires a new
user permission grant. File URLs and incognito profiles are unsupported unless a later
contract explicitly adds them.

## Trusted attention decision

The extension side panel owns the trusted decision controls. `attention.decided`
includes the attention ID, operation digest, decision, edited-value digest, timestamp, and nonce. The
daemon accepts it only from the paired origin over the authenticated live connection
for the designated trusted principal. MCP messages cannot produce this event.

## Service-Worker Recovery

The service worker stores pairing identity, endpoint, negotiated contract, and resumable
session identifiers in `chrome.storage.local`. It treats memory as disposable. On
startup or WebSocket closure it reconnects with bounded exponential backoff. Keepalive
messages maintain the connection on Chrome 116 or newer but do not replace recovery.
