# Acceptance Quickstart

This guide is the release acceptance journey for spec 001. Commands describe the
finished contract. A release candidate fails this guide until every step produces the
stated result.

## Prerequisites

- A supported macOS, Linux desktop, or Windows machine.
- Stable Chrome or Chromium 116 or newer.
- A test browser profile with an authenticated account on the fixture site.
- The matching Matinee CLI and extension release candidate.
- An MCP client that supports the negotiated MCP protocol version.
- A checkout of the deterministic fixture site for the release candidate.

Do not use a personal production account for release acceptance.

## 1. Install

Install the release artifact through the platform package instructions, then run:

```sh
matinee version --output json
matinee doctor --output json
```

Expected results:

- `version` emits `matinee.cli.v1` with package, state-schema, daemon, extension,
  and MCP tool contract versions.
- Doctor can find the browser and state directory.
- Doctor reports the unpaired extension as the only blocking check.

## 2. Pair the Extension

Run:

```sh
matinee setup --browser chrome --mcp-client acceptance --output json
```

Install or open the expected store extension when prompted. Transfer the single-use
enrollment bundle through its trusted pairing surface and grant access only to the fixture
site's origin.

Expected results:

- Setup bootstraps the first native principal through inherited OS pipes and completes
  within 10 minutes of the first command.
- The extension reports the same pinned daemon identity as setup.
- Setup prints valid MCP client configuration without exposing a reusable private key.
  The one-time enrollment seed appears only in the dedicated pairing transfer surface.
- `matinee status --output json` reports one ready daemon, one paired extension, no
  active session, and no pending attention.

## 3. Connect an MCP Client

Add the emitted client configuration and start the MCP client. Invoke `matinee_status`.

Expected results:

- The adapter starts as `matinee mcp` over stdio.
- The tool result reports `matinee.tools.v1` and the same daemon identity.
- Closing and reopening the MCP client does not restart the daemon.

## 4. Open a Visible Session

Use `browser_list` to obtain candidates. If more than one eligible tab exists, omit the
selection once and confirm that `session_open` returns `selection.ambiguous`. Repeat with
exact browser, window, and tab identifiers.

Expected results:

- The selected tab displays the Matinee control indicator.
- The session result contains a stable `session_id` and document generation.
- A second mutating session for the same tab receives an ownership conflict.

## 5. Observe and Act

Run these operations against the fixture site:

1. `page_observe` with bounded depth and node count.
2. `element_click` on a navigation control.
3. Reuse the pre-navigation element reference and confirm a stale-state failure.
4. Observe the new document.
5. Use `element_type`, `keyboard_press`, `page_scroll`, `element_select`,
   `file_upload`, `page_wait`, and `page_screenshot` on their fixture controls. Select the
   upload fixture only through the trusted extension file picker. Retry the screenshot
   with the same idempotency key.

Expected results:

- The synthetic pointer and target highlight appear before each activation.
- Operations execute in submission order for the tab.
- Observation reports truncation metadata when a bound is reached.
- The screenshot masks fixture fields marked sensitive, and its equivalent retry returns
  the same artifact without a second capture.
- The upload result exposes selected-file metadata but no local path, handle, or bytes.
- The stale reference causes no browser action.

## 6. Exercise Human Attention

Navigate to the fixture purchase flow and request final submission.

Expected results:

- Matinee pauses before submission and creates one pending attention request.
- The MCP client can read redacted attention details but cannot approve them.
- Editing the operation in the extension invalidates the original scope and creates a
  new attention request.
- Approving the exact new operation in the extension consumes one approval and submits
  once.

Repeat for credential entry, deletion, legal acceptance, permission grant, denial,
cancellation, and expiry. No path may infer approval from silence or reconnect.

## 7. Inject Interruptions

Start a request containing two fixture operations. After the first operation commits,
terminate the daemon through the crash-injection harness. Restart through:

```sh
matinee status --output json
```

Disconnect the MCP client during a second request's pending attention state. Reconnect
both the extension and client.

Expected results:

- The daemon reports recovery before readiness.
- The original request, operation, session, and attention identifiers remain stable.
- The completed first operation does not repeat.
- Pending attention remains pending until the user decides or it expires.
- An uncertain fixture effect becomes `reconciliation_required` and does not retry.

## 8. Cancel and Diagnose

Start independent requests on two tabs. Cancel one through `request_cancel`. Force a
fixture browser failure in the other. Run:

```sh
matinee status --requests all --output json
matinee doctor --output json
matinee diagnostics export --request <failed-request-id> --destination ./diagnostics.zip
```

Read the same bundle through `diagnostic_export` from the MCP client.

Expected results:

- Cancellation on one tab does not change the other session.
- Each terminal request has one outcome.
- The failure names its class, stable code, failed boundary, retryability, and safe next
  action.
- A byte scan finds none of the fixture's seeded tokens, cookies, credentials,
  authorization headers, secret fields, or marked sensitive content.

## 9. Close and Stop

Close the session without requesting tab closure, then run:

```sh
matinee stop --output json
```

Expected results:

- The adopted browser tab remains open.
- Matinee removes the tab indicator, pointer, and target overlay.
- The daemon drains active work, persists its final transitions, and stops.
- A later `matinee status` guardedly starts one daemon and retains request history.

## 10. Upgrade and Uninstall

Install the release candidate over the prior supported state fixture. Verify outcomes,
pending attention, pairings, and artifact tombstones. Inject one migration failure and
confirm restoration of the pre-migration backup.

Finally run both uninstall choices on separate fixtures:

```sh
matinee uninstall --data retain
matinee uninstall --data delete
```

Expected results:

- `retain` revokes registrations and preserves declared data locations.
- `delete` revokes registrations and removes history, artifacts, and credentials.
- Neither choice leaves a running daemon.
