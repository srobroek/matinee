# Implementation Plan: Demonstrable Multi-Tab Browser MVP

**Branch**: `omp/agent/matinee-2im` | **Date**: 2026-09-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/006.5-demonstrable-browser-mvp/spec.md`

## Summary

Make Matinee drive at least two user-visible Chrome tabs from one MCP client
through one paired extension, and keep every external effect safe across crash
and restart. The MVP adds the four boundaries that Specs 005 and 006 left
unbuilt: a daemon process with a durable store, an authenticated native bootstrap
channel, a stdio MCP adapter, and an unpacked extension on a loopback WebSocket.
A local fixture site and a repeatable quickstart make the result observable.

Specs 005 and 006 supply protocol state machines and identity logic with no
transports and no persistence. This plan wires those pieces to real processes and
real storage without reimplementing them. Design decisions and their evidence are
in [research.md](./research.md); durable records are in
[data-model.md](./data-model.md).

## Technical Context

**Language/Version**: Rust 1.85 (constitution-pinned MSRV), edition 2024

**Primary Dependencies**: `tokio 1`, `rusqlite =0.34.0` with `bundled`
(`libsqlite3-sys 0.32.0`), `tokio-tungstenite =0.30.0`, `axum =0.8.9`,
`serde`/`serde_json`, `keyring 3.6.3` through the existing credential adapter.
Every pin compiled under `cargo +1.85.0 check`. No MCP SDK: see research D1.

**Storage**: One SQLite database in the state directory. WAL journal,
`PRAGMA synchronous = FULL`, `PRAGMA user_version = 1`, single writer.

**Testing**: `cargo test` with contract tests per boundary, integration tests
across boundaries, and crash-injection tests at each persistence barrier. The
quickstart is the end-to-end gate.

**Target Platform**: Local developer machine. The demonstration runs on macOS
with Chrome or Chromium; CI keeps building Linux, macOS, and Windows.

**Project Type**: Multi-process local toolchain: CLI, daemon, MCP adapter,
browser extension, fixture server.

**Performance Goals**: None claimed. `SC-003` and `SC-010` require 100
overlapping operations to complete without cross-tab mutation; correctness under
concurrency is the target, not latency.

**Constraints**: No in-process fake may replace a named boundary (`FR-057`).
Loopback binding only. No secret, cookie, or unredacted screenshot in the store.
A commit is the only persistence barrier.

**Scale/Scope**: One state directory, one daemon, one MCP principal, one
extension principal, two or more visible tabs, 12 MVP tools.

## Constitution Check

*GATE: passed before Phase 0. Re-checked after Phase 1 design.*

| Principle | How this design satisfies it |
|---|---|
| I. Human Authority | The MVP defers approval workflows and instead confines itself to the deterministic local fixture, so no governed effect occurs. Uncertain effects return `reconciliation_required` and never auto-replay (`FR-037`, `FR-038`). |
| II. Visible Browser Ownership | Control runs through the paired unpacked extension into user-visible tabs. The daemon owns each session; the extension mediates every tab access; the content script shows the active operation boundary (`FR-027`). |
| III. Durable Local State | The daemon is the single writer. Each confirmed Request has a stable identity, persisted transitions, and one terminal outcome. The Dispatch Record's `dispatched` phase commits before the extension receives a command, so recovery never repeats a recorded effect. |
| IV. Least Privilege | Endpoints bind `127.0.0.1` only. Every MCP, native, and extension connection authenticates. The extension requests `scripting`, `activeTab`, and host access for the fixture origin only. No browser credential store is copied. |
| V. Observable Contracts | Every tool returns a stable identifier, canonical state, timestamps, and a structured result or failure. Contracts live in `contracts/`. Protocol version mismatch rejects the peer rather than guessing. |

**Delivery gates**:

- Each implementation slice maps to one `FR-` requirement and one `SC-` criterion.
- Integration tests cross the MCP, daemon, extension, browser, and persistence
  boundaries.
- Crash, idempotency, origin-rejection, and redaction tests are deterministic.
- The quickstart demonstration runs before the work lands.

**Result**: PASS, no violations, no complexity exceptions.

## Project Structure

### Documentation (this feature)

```text
specs/006.5-demonstrable-browser-mvp/
├── spec.md                      # Approved specification
├── plan.md                      # This file
├── research.md                  # Phase 0 decisions with MSRV evidence
├── data-model.md                # Phase 1 durable records and transitions
├── quickstart.md                # Phase 1 demonstration procedure (FR-056)
├── checklists/requirements.md   # Specification quality checklist
└── contracts/
    ├── mcp-tools.md             # The 12 MVP tools and their schemas
    ├── daemon-protocol.md       # Native bootstrap and control messages
    └── extension-protocol.md    # Loopback WebSocket frames
```

### Source Code (repository root)

```text
crates/
├── matinee-cli/          # bin `matinee`: setup, status, doctor, stop, daemon, mcp, fixture
├── matinee-daemon/       # NEW lib: lifecycle, store, sessions, operations, transports
├── matinee-mcp/          # NEW lib: JSON-RPC stdio adapter and tool dispatch
├── matinee-fixture/      # NEW lib: deterministic two-route axum site
├── matinee-runtime/      # EXISTING: environment, config, enrollment host, errors
└── matinee-security/     # EXISTING: identity, channel handshakes, credentials

extension/                # NEW unpacked MV3 extension
├── manifest.json         # pinned `key`, scripting/activeTab, fixture host access
├── service-worker.js     # channel client, session registry, command router
└── content-script.js     # DOM actions, generation checks, boundary indicator
```

**Structure Decision**: The daemon, adapter, and fixture are libraries behind one
`matinee` binary, so the demonstration starts real processes without publishing
several binaries. This keeps `matinee-runtime` and `matinee-security` unchanged
as the identity and protocol foundation, and confines new durable state to
`matinee-daemon`, which owns the single writer.

## Complexity Tracking

No constitution violations, so no justification is required.
