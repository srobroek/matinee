# Implementation Plan: Interactive Local Browser Automation

**Branch**: `001-interactive-browser-automation` | **Date**: 2026-09-11 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-interactive-browser-automation/spec.md`

## Summary

Build one installable Matinee product consisting of a Rust CLI, stdio MCP adapter,
persistent local daemon, and Manifest V3 browser extension. The daemon owns durable
state in SQLite, exposes an authenticated loopback protocol, serializes mutations per
tab, and recovers confirmed requests. The extension controls user-selected Chrome or
Chromium tabs through optional host permissions and renders user-visible operation and
attention surfaces.

## Technical Context

**Language/Version**: Rust 2024 edition with minimum Rust 1.85; TypeScript 5.x for the
browser extension

**Primary Dependencies**: `tokio` 1.x, `rmcp` 3.x, `axum` 0.8.x, `rusqlite` 0.40.x,
`keyring` 4.x, `serde` 1.x, `uuid` 1.x, `clap` 4.x, `tracing` 0.1.x; Chrome Extension
Manifest V3; pnpm with TypeScript, esbuild, Vitest, and Playwright

**Storage**: SQLite in WAL mode for durable state; content-addressed local files for
artifacts; platform credential store for reusable bearer credentials

**Testing**: Rust unit and integration tests, cargo-nextest where installed, Vitest,
JSON Schema conformance, Playwright with a temporary Chrome profile, deterministic
fixture sites, crash injection, and mutation checks for safety invariants

**Target Platform**: macOS, Linux desktop, and Windows desktop; stable Chrome or
Chromium 116 or newer

**Project Type**: Multi-crate Rust CLI and local service with one TypeScript browser
extension

**Performance Goals**: Warm MCP-to-extension no-op observation dispatch at or below
100 ms median and 250 ms p95 over 1,000 sequential requests on the recorded reference
machine; four active tabs without per-tab order violations

**Constraints**: Loopback-only control and visible browser operation. The runtime has
one durable writer and does not copy browser profiles. Approval precedes sensitive
effects. Recovery does not replay recorded effects. Rust 1.85 remains compatible.

**Scale/Scope**: One user account, one authoritative daemon per state directory, up to
four active tabs, up to four connected MCP clients, and 32 queued operations by default

## Constitution Check

### Pre-Design Gate

- **I. Human Authority -- PASS**: The design creates a durable attention boundary and
  accepts decisions only from the paired extension surface.
- **II. Visible Browser Ownership -- PASS**: One extension-owned content surface marks
  the tab, cursor, target, and operation boundary.
- **III. Durable Local State -- PASS**: One daemon and one database actor own state.
  Idempotency and reconciliation precede retries.
- **IV. Least Privilege -- PASS**: Control is loopback-only, credentials are per
  principal, host access is optional per origin, and browser credential stores remain
  browser-owned.
- **V. Observable Contracts -- PASS**: Versioned schemas cover external messages,
  failures, transitions, artifacts, MCP tools, and CLI JSON.
- **Delivery Gates -- PASS**: The plan includes boundary integration tests, crash
  injection, real-browser verification, migration checks, and no placeholder stage.

### Post-Design Gate

- [data-model.md](data-model.md) defines explicit states and invariants.
- [contracts/](contracts/) separates MCP, daemon, extension, CLI, failure, and artifact
  ownership.
- [quickstart.md](quickstart.md) proves installation through recovery as one vertical
  journey.
- No constitution exception is required.

## Project Structure

### Documentation

```text
specs/001-interactive-browser-automation/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   └── requirements.md
└── contracts/
    ├── README.md
    ├── acceptance-matrix.md
    ├── cli.md
    ├── daemon-protocol.md
    ├── extension-protocol.md
    └── mcp-tools.md
```

### Source Code

```text
Cargo.toml
server.json
crates/
├── matinee-domain/
│   ├── src/
│   │   ├── attention.rs
│   │   ├── failure.rs
│   │   ├── operation.rs
│   │   ├── request.rs
│   │   ├── session.rs
│   │   └── lib.rs
│   └── tests/
├── matinee-protocol/
│   ├── src/
│   ├── schemas/
│   └── tests/
├── matinee-store/
│   ├── migrations/
│   ├── src/
│   └── tests/
├── matinee-daemon/
│   ├── src/
│   │   ├── artifacts/
│   │   ├── auth/
│   │   ├── browser/
│   │   ├── diagnostics/
│   │   ├── runtime/
│   │   └── transport/
│   └── tests/
└── matinee-cli/
    ├── src/
    │   ├── commands/
    │   ├── mcp/
    │   └── main.rs
    └── tests/
extension/
├── manifest.json
├── package.json
├── src/
│   ├── content/
│   ├── protocol/
│   ├── service-worker/
│   ├── sidepanel/
│   └── surfaces/
└── tests/
fixtures/
├── browser-site/
├── certificates/
└── secrets/
tests/
├── contract/
├── integration/
└── journeys/
```

**Structure Decision**: Five Rust crates express the real dependency boundaries. Domain
and protocol contain pure contracts. Store owns durable writes. Daemon owns orchestration
and loopback transport. CLI owns installed process modes and stdio MCP translation. The
extension remains a separate TypeScript package because Chrome executes JavaScript.

## Dependency Rules

1. `matinee-domain` depends only on serialization, identifiers, and time abstractions.
2. `matinee-protocol` depends on `matinee-domain` and owns versioned wire schemas.
3. `matinee-store` depends on domain types and exposes typed commands. It does not expose
   database connections or row types.
4. `matinee-daemon` depends on domain, protocol, and store. Browser and transport modules
   invoke domain transitions rather than mutating records directly.
5. `matinee-cli` depends on protocol client interfaces and MCP translation. It does not
   depend on store internals.
6. The extension imports generated TypeScript contract types. Rust schemas are the
   canonical source, and CI rejects generated drift.

## Implementation Sequence

### Stage 1 - Domain and Contract Core

- Replace the single binary layout with the workspace structure.
- Define identifiers, clocks, failure envelopes, effect classes, and all state machines.
- Generate JSON Schemas and TypeScript types from protocol types.
- Add transition-table, invalid-transition, serialization, and schema-drift tests.
- Exit condition: every state and wire contract in `data-model.md` and `contracts/`
  has a concrete type plus a passing conformance test.

### Stage 2 - Durable Runtime

- Implement the single-writer SQLite actor, numbered migrations, integrity checks,
  idempotency records, audit chaining, retention metadata, and artifact transactions.
- Implement daemon election, guarded startup, readiness, graceful shutdown, and recovery.
- Add boundary crash injection for every acknowledged transition and artifact commit.
- Exit condition: restart tests preserve one terminal outcome and never replay a recorded
  completed effect.

### Stage 3 - Authenticated Local Protocol

- Implement loopback HTTP and WebSocket routes with message, frame, queue, and connection
  limits.
- Implement per-principal credentials, pairing codes, origin checks, rotation, revocation,
  protocol negotiation, and capability negotiation.
- Implement CLI daemon client, JSON output envelopes, setup, doctor, status, and stop.
- Exit condition: allowed and denied matrices pass for every endpoint, origin, credential,
  protocol range, and lifecycle command.

### Stage 4 - Browser Extension and Session Ownership

- Build the Manifest V3 extension, service-worker reconnect loop, pairing surface,
  optional-origin permission flow, and generated protocol client.
- Implement browser discovery, explicit selection, tab ownership, content-script lifecycle,
  document generations, semantic snapshots, stale references, and visible overlays.
- Implement the first operation set without attention-sensitive submission.
- Exit condition: a temporary Chrome profile completes setup, pairing, session open,
  observation, safe actions, navigation, reconnect, and release while adopted tabs remain
  open.

### Stage 5 - MCP Interaction

- Implement the `rmcp` stdio server and tool schemas from `contracts/mcp-tools.md`.
- Translate tool calls into durable daemon requests before browser mutation.
- Implement event polling, bounded results, cancellation propagation, and adapter exit
  independence.
- Exit condition: two MCP clients share authoritative daemon state, adapter exit preserves
  confirmed work, and duplicate idempotency keys return one result.

### Stage 6 - Attention, Cancellation, and Reconciliation

- Classify effects, create attention requests, accept trusted extension decisions, and
  consume exact-scope approvals once. Support edit, deny, cancel, and expiry outcomes.
- Persist cancellation at safe boundaries. Reconcile uncertain effects without retry.
- Add browser fixtures for credentials, purchase confirmation, deletion, permission,
  legal acceptance, and ambiguous network completion.
- Exit condition: the sensitive-action matrix records zero untrusted approvals and zero
  automatic retries of uncertain effects.

### Stage 7 - Artifacts, Diagnostics, and Operations

- Implement browser-side sensitive-field masking, daemon-side structured redaction,
  content-addressed artifacts, tombstones, cleanup, diagnostic export, local metrics,
  and safe next-action mapping.
- Enforce retention with immutable security minimums and report each value's source.
- Exit condition: seeded secrets do not appear in any persisted or exported surface, and
  every injected failure yields the required diagnostic fields.

### Stage 8 - Packaging, Upgrade, and Release Proof

- Produce macOS, Linux, and Windows artifacts with checksums or signatures. Validate
  and publish `server.json` to the MCP Registry.
- Package the extension for Chrome Web Store review and unpacked development use.
- Implement transactional state migrations, pre-migration backup, downgrade rejection,
  and uninstall retention choices.
- Run the quickstart, full acceptance matrix, latency benchmark, four-tab concurrency run,
  crash matrix, and manual visible-browser release check.
- Exit condition: every requirement has passing evidence in the acceptance matrix and the
  first complete release contains no inert command, placeholder protocol, or deferred
  implementation inside declared scope.

## Delivery Strategy

Stages land in dependency order. A stage may merge only when its exit condition passes.
Stages 1-3 produce internal capabilities but are not a product release. Stage 4 produces
browser control for integration testing but not an advertised release. Stages 5-8 complete
the vertical product and release proof. No stage publishes a user-facing command or tool
before its backing behavior and diagnostics are complete.

## Complexity Tracking

| Choice | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| Five Rust crates plus one extension package | Process, storage, protocol, and browser runtimes have different dependency directions and test boundaries | One crate permits CLI, persistence, and daemon internals to couple; Rust cannot execute as a Chrome extension |
| Loopback HTTP and WebSocket server | Both native clients and the browser extension need one authenticated cross-platform daemon transport | Platform sockets still require a second extension transport |
| SQLite plus artifact files | Related state transitions need transactions while screenshots need bounded file storage | JSON files cannot atomically enforce request, operation, approval, and idempotency invariants |
