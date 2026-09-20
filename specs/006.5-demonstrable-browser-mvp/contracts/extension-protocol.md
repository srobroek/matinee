# Contract: Extension Protocol

**Feature**: [spec.md](../spec.md)

One loopback WebSocket carries every browser command. The daemon listens on
`127.0.0.1` with an ephemeral port; the extension service worker connects as the
client (`FR-007`).

## Handshake

1. The daemon accepts the upgrade only when the request path matches the channel
   path, the `Origin` equals the pinned `chrome-extension://<id>`, and the
   subprotocol equals the channel protocol version. Anything else is rejected
   before upgrade (`FR-008`).
2. After upgrade, the extension proves possession of its enrolled key through the
   Spec 006 `ServerHandshake` challenge. The secret never appears in the URL.
3. The daemon authorizes commands only after the handshake completes and the
   pairing is active and unrevoked (`FR-009`).

A reconnect opens a new channel generation. The previous generation stops
authorizing commands immediately, and durable sessions survive the reconnect
(`FR-010`, `adr-8`).

## Frames

Every frame carries `protocol_version`, `channel_generation`, and a
`correlation_id`. Command frames additionally carry `operation_id`,
`request_id`, and the target descriptor.

### Daemon to extension

| Frame | Payload | Notes |
|---|---|---|
| `bind_session` | preallocated session, selection or creation target | Returns incarnation and initial generation |
| `observe` | session, incarnation, generation | Returns bounded element references |
| `navigate` | session, incarnation, generation, fixture URL | Non-fixture origin never reaches here |
| `click` | session, incarnation, generation, element reference | Shows indicator before activation |
| `type` | session, incarnation, generation, element reference, text | Shows indicator before activation |
| `screenshot` | session, incarnation, generation | Activates the tab, captures, restores the prior tab |
| `release_session` | session, `close_tab` | Leaves the tab open unless asked |

### Extension to daemon

| Frame | Payload | Notes |
|---|---|---|
| `result` | correlation, operation, session, incarnation, generation, outcome | The daemon verifies all five before committing (`FR-042`) |
| `uncertain` | correlation, operation, reason | The daemon records an Unknown Reservation |
| `generation_changed` | session, incarnation, new generation | Invalidates stale references |
| `incarnation_lost` | session, incarnation | The user closed or replaced the tab |

## Verification rules

- The extension verifies session, operation, tab incarnation, and document
  generation for an existing tab, and the daemon-authenticated target descriptor
  for new-tab creation (`FR-026`).
- A mismatch returns a stale-state failure and performs no browser action.
- The extension never retargets another tab when its target disappears
  (`FR-029`).
- The daemon discards a result whose channel generation is no longer current.

## Identity and custody

The extension private key is created non-exportable through WebCrypto and stays in
extension-local storage; only its public key and fingerprint reach the daemon
(`FR-016`). The manifest pins the extension id with its `key` field, so the
paired origin survives reloads.

## Permissions

The manifest requests `scripting`, `activeTab`, and host access for the fixture
origin only. It does not request `debugger`, `<all_urls>`, `cookies`, or
`webRequest`.
