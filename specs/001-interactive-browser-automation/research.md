# Technical Research: Interactive Local Browser Automation

## Runtime and Process Topology

**Decision**: Keep one published `matinee` Rust binary with `mcp`, `daemon`, `setup`,
`doctor`, `status`, and `stop` modes. MCP clients launch `matinee mcp`. That adapter
connects to the persistent daemon or starts it through a guarded start protocol.

**Rationale**: One artifact simplifies installation while preserving the process
boundary between client-owned stdio and daemon-owned state. Adapter exit cannot own
or terminate confirmed work.

**Alternatives considered**:

- A stateful stdio server ties request lifetime to one MCP client process.
- A separate binary per mode expands packaging without adding a security boundary.
- Streamable HTTP as the first public MCP transport exposes a network service that the
  local-client journey does not require.

## MCP SDK

**Decision**: Use `rmcp` 3.x with its `server` and `transport-io` crate flags for the
stdio adapter. Override the supported protocol-version set and translate every tool
call to the daemon contract.

**Rationale**: `rmcp` is the official Rust MCP SDK. It provides stdio transport,
server lifecycle, cancellation tokens, initialization, and explicit supported protocol
versions. Matinee should implement product semantics behind that standard boundary.

**Alternatives considered**:

- A hand-written JSON-RPC implementation duplicates protocol negotiation and lifecycle
  behavior.
- A TypeScript MCP adapter introduces a second runtime into the installed CLI path.

**Sources**:

- [RMCP stdio transport](https://docs.rs/rmcp/latest/rmcp/transport/io/index.html)
- [RMCP server lifecycle](https://docs.rs/rmcp/latest/rmcp/service/fn.serve_server_with_ct.html)
- [MCP transports](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports)

## Local Control Transport

**Decision**: Expose one authenticated loopback HTTP and WebSocket server from the
daemon using Axum 0.8.x. Native CLI and MCP clients use bounded HTTP requests plus an
event WebSocket. The extension uses a WebSocket subprotocol and a paired credential.
The default endpoint is `127.0.0.1:3210`; configuration may select another loopback
address or port.

**Rationale**: The browser extension cannot use Unix sockets or Windows named pipes.
One loopback protocol avoids a second transport and preserves cross-platform behavior.
Axum supports middleware authentication, WebSocket subprotocol selection, message-size
limits, and graceful shutdown. A warm loopback request is compatible with the 100 ms
median product target, which the benchmark must verify.

**Alternatives considered**:

- Unix sockets plus Windows named pipes reduce native-client exposure but require a
  second protocol for the extension.
- Chrome Native Messaging gives the browser ownership of the host process and has
  platform registration plus message-size constraints.
- Two daemon ports separate native and extension traffic but add configuration and
  recovery states without a distinct trust benefit.

**Sources**:

- [Axum WebSocket upgrade](https://docs.rs/axum/0.8.4/axum/extract/ws/struct.WebSocketUpgrade.html)
- [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)

## Authentication and Pairing

**Decision**: Create independent 256-bit random bearer credentials for each MCP client
registration and extension pairing. Store native client credentials in the platform
credential store through `keyring` 4.x. The extension stores its credential in
`chrome.storage.local`. Persist credential identifiers, hashes, rotation metadata,
and revocation state in SQLite. A pairing code expires after 10 minutes and works once.

The daemon accepts only loopback peers. Native requests require a bearer credential.
Extension upgrades require the bearer credential, an exact paired extension origin,
and the `matinee.v1` WebSocket subprotocol. Logs retain only credential fingerprints.

**Rationale**: Separate credentials permit revocation and attribution. Reusable
plaintext tokens stay out of project configuration and SQLite. The daemon needs only
credential hashes. Origin validation binds an extension credential to the paired
extension package.

**Alternatives considered**:

- One machine-wide token prevents per-client revocation and attribution.
- Plaintext token files require platform-specific permission and ACL handling.
- Mutual TLS adds certificate lifecycle work to a loopback-only product.

## Browser Extension

**Decision**: Build a Manifest V3 Chrome extension in strict TypeScript with no UI
framework. Require Chrome 116 or later. Use a service worker for the authenticated
daemon WebSocket. Use a programmatically injected isolated-world content script for
semantic observation, visible cursor and target overlays, and DOM-backed operations.
Use an extension side panel for trusted attention decisions; page scripts cannot
render or submit that decision surface.

Declare `storage`, `scripting`, `tabs`, and `sidePanel` permissions. Declare HTTP and
HTTPS patterns under `optional_host_permissions`; request an origin when the user opens
a session for that site. Do not request `cookies`, `webRequest`, `debugger`, or permanent
all-site host access. Persist only pairing metadata and resumable connection state in
`chrome.storage.local`.

**Rationale**: Chrome 116 extends the extension service-worker lifetime when WebSocket
messages are sent or received. The service worker must still recover from suspension.
Optional host permissions give users runtime control. Isolated-world content scripts
avoid sharing JavaScript state with the page.

**Alternatives considered**:

- A static `<all_urls>` content script grants access before the user selects a site.
- `activeTab` alone depends on a user gesture for each tab and cannot support durable
  reconnect semantics.
- The debugger protocol grants broader browser authority than the first operation set
  requires.

**Sources**:

- [Extension service-worker lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [Extension permissions](https://developer.chrome.com/docs/extensions/develop/concepts/declare-permissions)
- [Content-script isolated worlds](https://developer.chrome.com/docs/extensions/develop/concepts/content-scripts)

## Persistence and Single-Writer State

**Decision**: Use SQLite through `rusqlite` 0.40.x on one dedicated database actor.
Enable WAL mode, foreign keys, full synchronous commits for effect-boundary records,
and a five-second busy timeout. Run numbered migrations inside exclusive transactions.
Store artifacts as content-addressed files beside the database; commit artifact metadata
only after the file is durable.

The database actor serializes mutations. Request handlers submit typed commands and do
not own database connections. Startup runs migration, `quick_check`, interrupted-
operation classification, and artifact reconciliation before readiness.

**Rationale**: SQLite supplies atomic local transactions and crash recovery without a
separate service. A single actor makes write order explicit and matches the daemon's
single-writer invariant. Content-addressed files keep large screenshots out of WAL.

**Alternatives considered**:

- JSON files require a transaction and recovery protocol across related entities.
- An embedded key-value store does not provide the relational constraints needed for
  operation ordering, approvals, artifacts, and idempotency records.
- Multiple pooled writers obscure transition order and increase lock contention.

**Sources**:

- [Rusqlite connection and busy timeout](https://docs.rs/rusqlite/latest/rusqlite/struct.Connection.html)
- [SQLite WAL](https://www.sqlite.org/wal.html)

## Identifiers, Time, and Deadlines

**Decision**: Use UUID version 7 identifiers through `uuid` 1.x for durable entities.
Persist UTC wall-clock timestamps for audit and monotonic durations for live deadlines.
On restart, recompute remaining deadlines from persisted wall-clock expiry and fail
closed when clock movement makes approval validity uncertain.

**Rationale**: UUIDv7 identifiers sort by creation time without a centralized sequence.
Monotonic timers resist wall-clock changes during one process lifetime. Persisted UTC
expiry remains interpretable after restart.

**Alternatives considered**:

- Database integer identifiers leak local row ordering into public contracts.
- Wall-clock-only live timers can extend or shorten approvals when the clock changes.

## Internal Architecture

**Decision**: Use a Rust workspace with deep modules rather than one crate per domain.
Create `matinee-domain` for pure types and transition rules, `matinee-store` for the
single-writer actor, `matinee-protocol` for shared JSON contracts, `matinee-daemon` for
orchestration and loopback transport, and `matinee-cli` for the installed binary.
Keep the MCP adapter as a `matinee-cli` mode backed by a narrow daemon client.

The extension is a separate pnpm package because Chrome executes JavaScript. Generate
TypeScript types from versioned JSON Schemas emitted by `matinee-protocol`; CI rejects
schema drift.

**Rationale**: Pure transition logic can be tested without browser or storage. The
store and daemon boundaries centralize persistence and orchestration. Five Rust crates
separate actual dependency boundaries without producing a crate for every entity.

**Alternatives considered**:

- One Rust crate allows daemon, CLI, protocol, and persistence concerns to depend on
  each other without reviewable seams.
- A crate for every domain entity adds build and navigation overhead without isolation.
- Hand-maintained Rust and TypeScript message types will drift.

## Concurrency, Retries, and Backpressure

**Decision**: Serialize mutations per tab with an owned session queue. Allow four active
tabs and 32 queued operations by default. Reject additional work with a resource-limit
failure. Apply cancellation tokens at queue wait, preflight, attention wait, browser
wait, and post-operation reconciliation boundaries.

Retry transport delivery and read-only observations at most twice with bounded jitter.
Do not automatically retry activations, text submission, uploads, permission grants,
or any operation classified as an external effect. Idempotency lookup precedes queueing.

**Rationale**: Per-tab serialization matches browser ordering while preserving useful
cross-tab concurrency. Bounded queues make overload visible. Effect-aware retries avoid
turning network ambiguity into duplicate actions.

## Artifacts, Redaction, and Audit

**Decision**: Apply redaction before serialization or filesystem writes. Use structured
field sensitivity plus conservative pattern redaction. Screenshots require an explicit
request or diagnostic policy and pass through browser-side masking for known sensitive
fields before capture. If masking cannot be confirmed, mark the artifact unsafe and do
not persist or return it.

Retain request metadata for 30 days and artifacts for 7 days by default. Cleanup writes
tombstones transactionally. Audit events are append-only rows chained by a digest per
daemon instance; they are tamper-evident, not a claim of external non-repudiation.

**Alternatives considered**:

- Redaction after writing leaves secrets in deleted blocks, logs, or crash artifacts.
- Recording every page snapshot creates unnecessary sensitive data.
- Encrypting every artifact with an application-managed key adds key recovery before
  the first release; platform filesystem encryption remains an environmental control.

## Failure and Observability Model

**Decision**: Use the failure classes and fields in FR-052 and FR-053. Emit structured
`tracing` events with request, operation, session, and connection identifiers. Expose
an authenticated local diagnostics snapshot in status output; do not add a remote
telemetry exporter in the first release.

Metrics use bounded labels. URLs, selectors, page text, and credential fingerprints do
not become metric labels. Diagnostic export applies the same redaction policy as live
logs.

## Packaging and Upgrade

**Decision**: Keep crates.io publication for the Rust package and add checksummed or
signed platform archives through GitHub Releases. Publish `server.json` to the official
MCP Registry with the crates.io package as its package source. Publish the extension
through the Chrome Web Store and provide an unpacked development build for contributors.
Use schema-versioned SQLite migrations and retain one pre-migration backup until the
new daemon reaches readiness.

**Rationale**: The MCP Registry gives compatible clients a vendor-neutral discovery
record. Cargo preserves the existing package channel. Platform archives serve users
without a Rust toolchain. Transactional migrations make compatibility explicit.

## Testing Shape

**Decision**: Use pure state-machine tests, SQLite integration tests, Rust-to-TypeScript
schema conformance tests, extension unit tests, daemon protocol tests, and browser
journeys against a deterministic local fixture site. Run crash injection at every
persisted boundary and mutation testing against approval, idempotency, and recovery
invariants.

Browser acceptance uses a dedicated temporary Chrome profile with the unpacked
extension. It does not use a contributor's normal profile or external production site.
A manual release check repeats the visible primary journey in an existing authenticated
test profile.
