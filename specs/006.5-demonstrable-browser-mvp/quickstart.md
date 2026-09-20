# Quickstart: Demonstrable Multi-Tab Browser MVP

**Feature**: [spec.md](../006.5-demonstrable-browser-mvp/spec.md) | Satisfies `FR-056`, `FR-057`, `FR-058`

This procedure drives two visible Chrome tabs from one MCP client through the
paired extension, then proves honest in-run failure reporting and restart
detection. Every boundary is a real process: no step substitutes an in-process
fake.

## Prerequisites

- Rust 1.85 or later, with the workspace building.
- Chrome or Chromium, with a profile you are willing to pair.
- A platform credential store the current user can unlock.
- A free loopback port for the fixture. The daemon picks ephemeral ports itself.
- One shell variable used by every command below, because the CLI reads the state
  directory from the environment rather than a flag:

```bash
export MATINEE_STATE_DIR="$PWD/target/mvp-demo/state"
```

## 1. Start the fixture

```bash
cargo run -p matinee -- fixture --port 8787
```

The fixture serves two independent routes, `/alpha` and `/beta`, each with a text
field and a counter. Leave it running.

## 2. Initialize the state directory

```bash
cargo run -p matinee -- setup
```

Expect: a state id, the created credential references, the ownership lock, and a
daemon the setup command started for you. `FR-009` allows only setup and the MCP
adapter to start one, so there is no public start command. Running setup twice
must report ownership conflict rather than reinitializing.

## 3. Confirm the daemon is ready

```bash
cargo run -p matinee -- status
```

Expect: `ready`, the bound loopback endpoints, the daemon instance identity, and
zero sessions on a fresh run.

## 4. Pair the extension

```bash
cargo run -p matinee -- setup pair-extension
```

Expect: a one-time pairing key, the daemon's extension WebSocket URL, and the
pinned `chrome-extension://<id>` origin. The key is valid for ten minutes and may
be spent once. An unauthenticated caller asking for it is denied.

Then load the extension:

1. Open `chrome://extensions`.
2. Enable Developer mode.
3. Choose Load unpacked and select the `extension/` directory.
4. Confirm the id Chrome shows matches the origin printed above.
5. Open the extension's options page, paste the one-time key and the WebSocket
   URL, and submit.

Expect: the options page reports that pairing started. That message confirms only
that the extension accepted the configuration and opened the socket; it does not
wait for the daemon's signed acceptance. Verify the pairing itself in step 6, where
`session_open` succeeds only over an authenticated channel. A pairing that never
completed makes that call fail with `operation.extension_disconnected`.

## 5. Connect the MCP client

```bash
cargo run -p matinee -- mcp
```

This speaks JSON-RPC on stdio. Point your MCP client at that command, then call
`tools/list`. Expect the 10 MVP tools.

## 6. Drive two tabs

Through the MCP client, in order:

1. `browser_list` and keep the returned `revision`.
2. `session_open` with `new_tab` and `http://127.0.0.1:8787/alpha`; keep
   `session_id` as A.
3. `session_open` with `new_tab` and `http://127.0.0.1:8787/beta`; keep
   `session_id` as B.
4. Focus an unrelated third tab in the same window and leave it focused.
5. `element_type` `alpha` into A's text field and `beta` into B's.
6. `element_click` A's counter button, then B's.
7. `page_observe` both sessions.

Expect: A holds `alpha` with its own counter at 1, B holds `beta` with its own
counter at 1, and no operation followed your focus. Each tab shows the ownership
indicator during its own actions only.

## 7. Capture screenshots

Call `page_screenshot` for A, then for B.

Expect: each returns an `ArtifactSummary` with a digest and a `resource_uri`. Each
capture briefly activates its own tab and restores the tab that was active
before. Reading a `resource_uri` through `resources/read` as the owning principal
returns the bytes; any other principal receives `authorization.denied`.

## 8. Prove cross-tab isolation at volume

Run 100 alternating operations across A and B with the third tab focused.

Expect: `SC-003` holds. Distinct values, counters, generations, and histories per
tab, with zero cross-tab mutation.

## 9. Prove honest reporting after a lost boundary

1. Set the fixture to stall its counter route:
   `curl -X POST http://127.0.0.1:8787/control/stall?route=alpha`.
2. Call `element_click` on A's counter.
3. Disconnect the extension before the click result arrives.
4. Read the fixture counter:
   `curl http://127.0.0.1:8787/alpha/counter`.
5. Kill the daemon: `pkill -f '__daemon-child'`.
6. Start the MCP adapter again with the same `MATINEE_STATE_DIR`, which brings a
   fresh daemon up.
7. Call `request_get` for the disconnected request using the prior daemon
   instance identity.

Expect: the disconnected Operation ends `failed` naming the lost boundary, the
fixture counter is unchanged by any retry, and the restarted client's next call
fails with `daemon.restarted` naming its last action sequence. The restarted
daemon holds zero sessions, and the fixture counter has advanced at most once.
Matinee never re-sends the click.

## 10. Write the evidence report

Capture the report before stopping anything. The daemon holds every record in
memory, so stop discards exactly the evidence `FR-058` requires.

```bash
cargo run -p matinee -- report --output target/mvp-demo/evidence.json
```

Expect a sanitized machine-readable report containing component versions,
redacted identity fingerprints, the daemon instance identity, session and tab
identities, Request and Operation identities with canonical states and action
sequences, screenshot artifact digests, resource-read results, and evidence that
a lost boundary terminated an Operation as `failed`. It must contain no secret,
raw page text, or private browser data.

A report captured from a run that skipped steps 6 through 9 is valid but empty.
An empty report is not `FR-058` proof; only a report from a completed run is.

## 11. Prove stop safety

Request stop as the authenticated native principal.

Expect: stop always succeeds. The daemon enters `draining`, rejects new
operations, abandons its in-memory state, disconnects the extension, leaves every
fixture tab open, and exits. No stop request is blocked by an outstanding
Operation.

## Cleanup

Step 11 already stopped the daemon and released the ownership lock. Stop the
fixture, then remove the unpacked extension from `chrome://extensions`. There is
no state database to delete, because the MVP keeps none.

