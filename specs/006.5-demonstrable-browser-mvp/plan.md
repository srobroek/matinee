# Implementation Plan: Demonstrable Multi-Tab Browser MVP

**Branch**: `omp/agent/matinee-2im` | **Date**: 2026-09-20 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/006.5-demonstrable-browser-mvp/spec.md`

## Summary

Make Matinee drive at least two user-visible Chrome tabs from one MCP client
through one paired extension, and never report an effect the daemon did not
observe. The MVP adds the four boundaries that Specs 005 and 006 left unbuilt: a
daemon process, an authenticated native bootstrap channel, a stdio MCP adapter,
and an unpacked extension on a loopback WebSocket. A local fixture site and a
repeatable quickstart make the result observable.

The MVP keeps no durable state. `adr-10` records that scope limit and its
Constitution III exception, because `FR-018` confines every operation to the
local fixture, where repeating an action is inconsequential. Spec 007 owns the
durable store.

Specs 005 and 006 supply protocol state machines and identity logic with no
transports. This plan wires those pieces to real processes without reimplementing
them. Decisions and their evidence are in [research.md](./research.md); records
are in [data-model.md](./data-model.md).

## Technical Context

**Language/Version**: Rust 1.85 (constitution-pinned MSRV), edition 2024

**Primary Dependencies**: `tokio 1`, `tokio-tungstenite =0.30.0`, `axum =0.8.9`,
`serde`/`serde_json`, `uuid`, `keyring 3.6.3` through the existing credential
adapter. Every pin compiled under `cargo +1.85.0 check`. No MCP SDK and no
storage engine: see research D1 and D3.

**Storage**: None. All state lives in memory for one daemon run. The only file the
daemon holds is the advisory ownership lock in the state directory.

**Testing**: `cargo test` with contract tests per boundary and integration tests
across boundaries, including lost-boundary and restart-detection tests. The
quickstart is the end-to-end gate.

**Target Platform**: Local developer machine. The demonstration runs on macOS
with Chrome or Chromium; CI keeps building Linux, macOS, and Windows.

**Project Type**: Multi-process local toolchain: CLI, daemon, MCP adapter,
browser extension, fixture server.

**Performance Goals**: None claimed. `SC-003` and `SC-010` require 100
overlapping operations to complete without cross-tab mutation; correctness under
concurrency is the target, not latency.

**Constraints**: No in-process fake may replace a named boundary (`FR-057`).
Loopback binding only. No secret, cookie, or unredacted screenshot leaves its
owner. The daemon reports only outcomes it observed.

**Scale/Scope**: One state directory, one daemon, one MCP principal, one
extension principal, two or more visible tabs, 10 MVP tools.

## Constitution Check

*GATE: passed before Phase 0. Re-checked after Phase 1 design.*

| Principle | How this design satisfies it |
|---|---|
| I. Human Authority | The MVP defers approval workflows and instead confines itself to the deterministic local fixture, so no governed effect occurs. A lost outcome terminates as `failed` naming its boundary and is never retried automatically (`FR-037`, `FR-038`). |
| II. Visible Browser Ownership | Control runs through the paired unpacked extension into user-visible tabs. The daemon owns each session; the extension mediates every tab access; the content script shows the active operation boundary (`FR-027`). |
| III. Durable Local State | **Scoped exception, `adr-10`.** The MVP holds state in memory for one run and claims no crash safety. Within a run the daemon remains the single owner of every transition, each confirmed Request reaches one terminal outcome, and no unobserved effect is reported as success or replayed. The exception expires at the first specification that automates a non-fixture origin; Spec 007 supplies the durable store. |
| IV. Least Privilege | Endpoints bind `127.0.0.1` only. Every MCP, native, and extension connection authenticates. The extension requests `scripting`, `activeTab`, and host access for the fixture origin only. No browser credential store is copied. |
| V. Observable Contracts | Every tool returns a stable identifier, canonical state, timestamps, and a structured result or failure. Contracts live in `contracts/`. Protocol version mismatch rejects the peer rather than guessing. |

**Delivery gates**:

- Each implementation slice maps to one `FR-` requirement and one `SC-` criterion.
- Integration tests cross the MCP, daemon, extension, and browser boundaries.
- Lost-boundary, restart-detection, idempotency, origin-rejection, and redaction
  tests are deterministic.
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
├── matinee-daemon/       # NEW lib: lifecycle, in-memory registry, sessions, transports
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
several binaries. This keeps `matinee-runtime` and `matinee-security` unchanged as
the identity and protocol foundation. `FR-010` confines every state transition to
one daemon-owned interface, so Spec 007 can make that interface durable without
changing callers.

## Complexity Tracking

The Constitution III exception is scoped, dated, and recorded in `adr-10` with an
expiry condition and a replacement plan. No other principle is waived.
