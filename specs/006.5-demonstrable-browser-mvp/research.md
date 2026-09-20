# Phase 0 Research: Demonstrable Multi-Tab Browser MVP

**Feature**: `specs/006.5-demonstrable-browser-mvp/spec.md` | **Date**: 2026-09-20

Every pin selected below was compiled under `cargo +1.85.0 check` in this
worktree. `rmcp` was compiled and failed there. The other rejected options were
ruled out on published metadata and maturity statements rather than by a local
compile. The constitution fixes the minimum supported Rust version at 1.85, so a
declared or inferred MSRV was not accepted as evidence for a selected pin.

## D1: MCP stdio adapter implements JSON-RPC directly

**Decision**: Implement the adapter against the MCP wire protocol using
`serde_json` and `tokio`. Do not depend on an MCP SDK.

**Rationale**: The official SDK cannot compile on Rust 1.85.

- `rmcp 3.4.0` declares `rust-version = 1.88.0`.
- `rmcp 0.17.0` with `macros` requires `darling ^0.23`, which declares
  `rust-version = 1.88.0`. The requirement is a caret range on 0.23, so no
  older `darling` satisfies it.
- `rmcp 0.17.0` without `macros` still fails on 1.85:
  `error[E0658]: let expressions in this position are unstable` at
  `rmcp-0.17.0/src/model/elicitation_schema.rs:882` and `:893`.

The MVP exposes a fixed, small tool set, so the protocol surface needed is
`initialize`, `tools/list`, and `tools/call` over newline-delimited JSON-RPC 2.0.
`stdout` carries only protocol messages; logs go to `stderr`.

**Alternatives rejected**: Raising the MSRV to 1.88 requires a constitution
amendment and user approval, which the MVP does not need. Unofficial SDKs were
rejected because their conformance is unverified.

## D2: Extension channel uses tokio-tungstenite

**Decision**: `tokio-tungstenite = "=0.30.0"` (declares `rust-version = 1.85`),
served with `accept_hdr_async`.

**Rationale**: The handshake callback rejects a wrong path, a wrong `Origin`, or
a wrong subprotocol before the upgrade completes. The listener binds
`127.0.0.1:0`, never a wildcard address. Header checks alone do not authenticate
a local process, so the channel runs the Spec 006 `ServerHandshake` challenge
and authorizes commands only after it completes.

**Alternatives rejected**: `axum 0.8.9` adds a router and framework state for one
upgrade endpoint. A raw TCP upgrade would reimplement the WebSocket protocol.

## D3: No storage engine; state lives in memory

**Decision**: Hold all MVP state in memory for one daemon run. Add no storage
dependency.

**Rationale**: `FR-018` confines the MVP to the deterministic local fixture, so
repeating an action changes a counter the user can see. A durable pre-dispatch
journal exists to stop duplicate consequential effects on real sites, which this
MVP cannot reach, and Spec 007 already owns that store. `adr-10` records the
decision, its Constitution III exception, and its expiry condition.

A client detects daemon loss from its dropped connection and a changed instance
identity, so durability was never what told the client an outcome was unknown.
Durability would only let the daemon distinguish never-sent from maybe-sent, which
is an optimization rather than a safety property. The MVP therefore always gives
the conservative answer: an operation whose outcome it did not observe terminates
as `failed` naming the lost boundary.

**Alternatives rejected**: `rusqlite =0.34.0` with `bundled` was implemented and
then removed; it compiled under Rust 1.85 in this worktree, resolving
`libsqlite3-sys 0.32.0`, but it bought crash safety the MVP does not claim.
`redb 2.6.3` declares MSRV 1.85 yet documents itself as beta.
`sled 1.0.0-alpha.124` calls itself unstable and recommends SQLite where
reliability is primary.

**Known gap**: with no server-side record surviving a restart, a client that
retries after one can duplicate an effect. The fixture-only restriction bounds
that risk. The cheapest fix for Spec 007 is a per-operation crash flag written
before dispatch and removed on terminal result, which refuses a reused
idempotency key after restart without a database.

## D4: Browser automation uses content scripts, not the debugger

**Decision**: Drive tabs with `chrome.tabs.update` for navigation and
`chrome.scripting.executeScript` plus a content script for DOM work. Do not use
`chrome.debugger`.

**Rationale**: `chrome.debugger` requires the `debugger` permission and shows a
user-visible infobar on every attached tab, which conflicts with the
constitution's visible-ownership model and adds a privileged surface the MVP does
not need. `chrome.scripting` needs the `scripting` permission plus host access
for the fixture origin only.

## D5: Screenshots use captureVisibleTab

**Decision**: `chrome.tabs.captureVisibleTab` with `format: "png"`.

**Rationale**: It captures the active tab of a window and requires `activeTab` or
host access. The daemon persists the returned bytes and their digest before
artifact metadata becomes `available`, per `FR-030`. The MVP redacts before
persisting and bounds the stored artifact.

**Consequence**: Capture requires the target tab to be active in its window, so
the extension activates the owned tab for the capture and the session records
that focus change.

## D6: Tab incarnation and document generation

**Decision**: Treat the Chrome tab id as reusable and never as identity. Bind a
daemon-issued tab incarnation at session bind time, and use the Chrome
`documentId` as the document generation.

**Rationale**: `Tab.id` is unique only within a browser session and is reused
after a tab closes, so `FR-023`'s non-repeating incarnation cannot come from it.
`webNavigation` events expose `documentId`, documented as the document's UUID,
plus `documentLifecycle`. A changed `documentId` is exactly the stale-generation
signal `FR-025` needs.

## D7: Extension identity is pinned by manifest key

**Decision**: Embed the extension's public key in `manifest.json` as `key`, so
the unpacked development extension keeps a stable id and origin.

**Rationale**: Pairing authorizes one `chrome-extension://<id>` origin. Without
`key`, an unpacked extension's id changes with its path and every reload would
invalidate the pinned origin. `chrome.runtime.id` reports the resulting id for
the handshake.

## D8: Fixture site uses axum

**Decision**: `axum = "=0.8.9"` bound to `127.0.0.1`, serving two independent
routes with editable fields and counters.

**Rationale**: The pin compiled under 1.85 in this worktree. The daemon already
depends on `tokio`, so `axum` adds no new runtime. Two routes with distinct
server-side counters make cross-tab leakage observable.

**Alternatives rejected**: `tiny_http` has no current MSRV metadata and no async
integration. `hyper` alone would need hand-written routing.

## Reuse map from Specs 005 and 006

These exist and MUST be reused rather than reimplemented:

- `matinee_runtime::environment` resolves the state root and its `LockIdentity`
  value.
- `matinee_runtime::enrollment` wraps the process-lifetime `EnrollmentHost`:
  `create_pairing`, `session`, `deliver_one_time_key`, `proof_challenge`,
  `complete_pairing`, `reconnect`, `update_custody`, `revoke`.
- `matinee_security::channel` supplies `ClientHandshake` and `ServerHandshake`
  plus `AdmittedEndpoint` loopback admission.
- `matinee_security::adapters::os_pipe` parses the inherited bootstrap handle.
- `matinee_security::adapters::credential_store` wraps `keyring 3.6.3`.
- `matinee_security::identity` supplies `IdentityId` and `CredentialReference`.
- `matinee_runtime::error` and `matinee_security::failures` supply the stable
  failure taxonomies to extend.

These do not exist and are new work:

- Daemon process, lifecycle states, and serialized dispatch admission.
- Exclusive state-root ownership; `LockIdentity` is a value, not a lock.
- Every durable record: schema, transactions, recovery.
- Socket, WebSocket, and stdio transports; only protocol state machines exist.
- The bootstrap client that launches the daemon with an inherited handle.
- The extension, the fixture, and all browser control.
- The `FR-058` evidence report.
