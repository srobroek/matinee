<!--
SYNC IMPACT REPORT
==================
Version change: 1.1.0 -> 1.2.0
Bump rationale: MINOR -- materially corrected spec 005 scope and outcome to match
the released CLI plus shared private runtime seams, and assigned daemon lifecycle and
clock ownership to later specifications.

Changes this revision:
  - Amended spec 005 status to implemented.
  - Superseded spec 005's stale all-runtime-modes outcome.
  - Superseded `process modes` and `clocks` in spec 005 scope (in).
  - Assigned daemon lifecycle ownership to spec 007 and clock-seam ownership to spec
    009, preserving the existing roadmap's later-spec ownership.

Specs affected: 005
Open questions added/resolved: none

Notes: Spec 005 remains implemented, not verified. Roadmap verification remains gated
on merge of PR #5.
-->

# Matinee -- Spec Roadmap

This roadmap records Matinee's specifications and product constraints.
The project [constitution](constitution.md) governs every entry. An entry's status
records its lifecycle, not a delivery commitment.

Status legend: **undecided** · **needs-info** · **planned** · **specced** ·
**in-progress** · **implemented** · **verified** · **deferred** · **abandoned**.

---

## Vision & End States

- An MCP client controls an existing authenticated browser through a visible,
  user-owned tab without surrendering the browser profile to a hosted service.
- Interactive browser work survives MCP client and daemon interruptions without
  duplicating completed external effects.
- The user can identify Matinee-controlled tabs, inspect active operations, approve
  sensitive boundaries, cancel work, and diagnose failures from structured evidence.
- A new user can install Matinee, pair the extension, connect an MCP client, and
  complete a representative authenticated task through documented commands.

## Constraints & Decisions

- **C-01 -- Local ownership:** A persistent daemon on the user's machine owns sessions,
  requests, approvals, persistence, and recovery. This keeps authenticated browser
  state under user control.
- **C-02 -- Published MCP surface:** A thin stdio MCP adapter connects each client to
  the daemon. The adapter does not own durable product state.
- **C-03 -- Extension transport:** A Chrome or Chromium extension connects to an
  authenticated loopback WebSocket endpoint. Chrome Native Messaging is not the
  daemon transport.
- **C-04 -- Visible by default:** The first release acts in ordinary browser windows
  and marks the controlled tab and current operation boundary.
- **C-05 -- Interactive first:** MCP primitives and resumable requests serve live agent
  interaction. General workflow files, schedules, and unattended recurring jobs are
  outside the first release.
- **C-06 -- Explicit authority:** Credential entry, payments, destructive effects,
  legal acceptance, and uncertain side effects require user approval before execution.
- **C-07 -- Conservative recovery:** Stable request identities, persisted transitions,
  and recorded effect boundaries prevent completed effects from being replayed.
- **C-08 -- Measured performance:** Product claims compare warm and cold interaction
  scenarios against recorded baselines. Matinee does not claim universal superiority.
- **C-09 -- Deep module ownership:** Each implementation specification owns one
  module interface and its observable behavior. Architecture details belong in that
  specification's plan unless they change a product contract.
- **C-10 -- Journey acceptance:** Cross-spec acceptance gates preserve the five user
  journeys from spec 001. A module passing in isolation does not satisfy a journey.

## Specifications

### 001 -- Interactive Local Browser Automation  [status: specced]

- **Description:** Define Matinee's product behavior, architecture constraints,
  domain model, state machines, and external contracts for local browser automation.
- **Outcome:** Specs 005-016 can implement one coherent product without redefining
  ownership, authority, persistence, recovery, or protocol semantics.
- **Scope (in):** CLI, daemon, MCP, extension, browser, persistence, attention,
  artifacts, diagnostics, configuration, packaging, upgrades, and acceptance
  contracts.
- **Scope (out):** Implementation sequencing and module-specific implementation
  plans. Excluded product scope covers hosted services, remote machines, headless
  execution, Firefox, schedules, unattended recurring jobs, a stable public Rust
  library, and a general-purpose workflow language.
- **Depends on:** none
- **Governed by:** C-01, C-02, C-03, C-04, C-05, C-06, C-07, C-08, C-09, C-10
- **Spec dir:** `specs/001-interactive-browser-automation/`
- **Notes:** This specification is the normative umbrella. Its existing task graph
  remains available until replacement tasks for specs 005-016 exist, then retires
  without implementation.

### 002 -- Firefox Browser Support  [status: deferred]

- **Description:** Add Firefox after an extension and control path can preserve the
  browser-ownership, visibility, authentication, and recovery contracts from spec 001.
- **Outcome:** The acceptance scenarios from spec 001 pass against a supported Firefox
  release without weakening user authority or profile isolation.
- **Scope (in):** Firefox extension transport, capability negotiation, packaging, and
  parity validation.
- **Scope (out):** Browser-specific capabilities without a cross-engine contract.
- **Depends on:** 001
- **Governed by:** C-03, C-04, C-07

### 003 -- Remote Matinee Execution  [status: deferred]

- **Description:** Define remote execution only after local ownership and authorization
  semantics have production evidence.
- **Outcome:** A separately approved specification defines identity, trust, transport,
  browser custody, and failure handling for another machine.
- **Scope (in):** _to be defined_
- **Scope (out):** Implicit exposure of the local daemon or browser profile.
- **Depends on:** 001
- **Governed by:** C-01, C-06, C-07

### 004 -- Scheduled Browser Work  [status: deferred]

- **Description:** Define schedules and unattended execution after interactive request
  semantics, idempotency, and approval expiry are verified.
- **Outcome:** _to be defined_
- **Scope (in):** _to be defined_
### 005 -- Runtime Foundation  [status: implemented]

- **Description:** Preserve the released CLI while establishing the private runtime
  seams shared by the CLI and later product specifications.
- **Outcome:** The released CLI remains available, and contributors can exercise the
  shared private runtime seams for configuration, platform directories, state-root
  identity, diagnostics, and deterministic tests without creating a second ownership
  model.
- **Superseded outcome (1.1.0):** ~~Contributors can build and exercise each runtime
  mode through stable internal interfaces without creating a second ownership model.~~
- **Scope (in):** Cargo workspace shape, released CLI behavior, platform directories,
  configuration loading, shared identifiers, diagnostics, and deterministic test seams.
- **Superseded scope (1.1.0):** ~~process modes~~ and ~~clocks~~. Daemon lifecycle
  ownership belongs to spec 007. The clock seam belongs to spec 009.
- **Scope (out):** Network identity, browser control, and product workflows.
- **Depends on:** 001
- **Governed by:** C-01, C-02, C-09

### 006 -- Identity, Authorization, and Secure Channels  [status: planned]

- **Description:** Implement local principal identity, authorization, enrollment,
  revocation, and authenticated communication between Matinee processes.
- **Outcome:** Approved principals connect through the specified channels. Unknown,
  revoked, downgraded, or replayed peers fail before mutation.
- **Scope (in):** Credential-store integration, principal roles, ECDSA identity,
  key agreement, channel framing, origin checks, rotation, and revocation.
- **Scope (out):** Browser operations and human approval policy.
- **Depends on:** 005
- **Governed by:** C-01, C-02, C-03, C-06, C-09

### 007 -- Daemon Lifecycle and Durable Store  [status: planned]

- **Description:** Implement daemon ownership, singleton startup, storage migrations,
  transaction rules, readiness, shutdown, and recovery gating.
- **Outcome:** Concurrent starts converge on one daemon, committed state survives a
  restart, and storage failure blocks unsafe mutation with a diagnostic result.
- **Scope (in):** Local IPC endpoint, process lock, SQLite schema, migrations,
  transaction boundaries, startup recovery, readiness, and graceful shutdown.
- **Scope (out):** Request execution and browser-session behavior.
- **Depends on:** 005, 006
- **Governed by:** C-01, C-07, C-09

### 008 -- Browser Extension and Pairing  [status: planned]

- **Description:** Implement the Chrome or Chromium extension, its enrollment flow,
  daemon connection, permissions, reconnect behavior, and visible indicators.
- **Outcome:** A user pairs an approved extension without exposing browser-profile
  credentials, and the extension reconnects under the recorded identity.
- **Scope (in):** Extension package, manifest, pairing surface, loopback WebSocket,
  browser events, permission minimization, reconnect, and indicator shell.
- **Scope (out):** Session ownership and browser operation semantics.
- **Depends on:** 005, 006
- **Governed by:** C-03, C-04, C-06, C-09

### 009 -- MCP Adapter and Tool Contracts  [status: planned]

- **Description:** Implement the stateless stdio MCP adapter and exact public tool
  schemas defined by spec 001.
- **Outcome:** Two compatible MCP clients can use one daemon without owning its
  process or durable state. Incompatible clients receive a versioned failure.
- **Scope (in):** MCP lifecycle, tool discovery, schema validation, principal
  selection, daemon startup handoff, error mapping, and bounded responses.
- **Scope (out):** Browser implementation and request recovery rules.
- **Depends on:** 005, 006, 007
- **Governed by:** C-01, C-02, C-08, C-09

### 010 -- Durable Request Engine  [status: planned]

- **Description:** Implement request and operation state machines, idempotency,
  effect boundaries, dispatch records, restart recovery, and terminal outcomes.
- **Outcome:** A confirmed request survives client or daemon interruption and never
  repeats an external effect whose completion Matinee recorded.
- **Scope (in):** Request confirmation, operation ordering, idempotency keys,
  dispatch journal, deadlines, recovery classification, and result projection.
- **Scope (out):** Browser-specific execution and user-attention presentation.
- **Depends on:** 007, 009
- **Governed by:** C-05, C-07, C-09

### 011 -- Browser Discovery and Session Ownership  [status: planned]

- **Description:** Implement browser discovery, explicit profile and window
  selection, tab adoption or creation, exclusive ownership, rebind, and release.
- **Outcome:** Matinee controls exactly the selected visible tab, rejects ambiguous
  selection, and releases ownership according to the recorded close policy.
- **Scope (in):** Candidate revisions, browser events, session states, contention,
  tab lifecycle, visible ownership indicators, and reconnect deadlines.
- **Scope (out):** Element inspection and page actions.
- **Depends on:** 007, 008, 009
- **Governed by:** C-01, C-03, C-04, C-07, C-09

### 012 -- Semantic Observation, Actions, and Transfer  [status: planned]

- **Description:** Implement bounded page observation, document-scoped references,
  browser actions, screenshots, uploads, downloads, and artifact streaming.
- **Outcome:** An MCP client observes and acts on a visible authenticated page while
  Matinee rejects stale references and unapproved local file disclosure.
- **Scope (in):** Semantic snapshots, frames, element references, navigation, input,
  activation, cursor and highlight behavior, screenshots, and bounded byte streams.
- **Scope (out):** Approval decisions and durable cancellation policy.
- **Depends on:** 010, 011
- **Governed by:** C-04, C-05, C-06, C-08, C-09

### 013 -- Human Attention and Safe Effects  [status: planned]

- **Description:** Classify operations that need human attention, present them on
  trusted decision surfaces, enforce approval scope, and resume safely.
- **Outcome:** Matinee pauses before each governed effect and resumes only the exact
  operation authorized by a trusted user decision.
- **Scope (in):** Attention states, policy reasons, summaries, trusted surfaces,
  deadlines, approval invalidation, credential entry, and file disclosure.
- **Scope (out):** General policy scripting and unattended approval.
- **Depends on:** 010, 012
- **Governed by:** C-04, C-05, C-06, C-07, C-09

### 014 -- Concurrency, Cancellation, and Reconciliation  [status: planned]

- **Description:** Schedule concurrent work, enforce cancellation boundaries,
  reconcile uncertain effects, and isolate concurrent sessions.
- **Outcome:** Cancellation reaches the next safe boundary, and one request cannot
  corrupt another request or silently resolve an uncertain effect.
- **Scope (in):** Concurrency limits, tab contention, cancellation intent,
  non-interruptible operations, reconciliation states, and fairness rules.
- **Scope (out):** Scheduled or unattended recurring work.
- **Depends on:** 010, 011, 012, 013
- **Governed by:** C-05, C-06, C-07, C-08, C-09

### 015 -- Artifacts, Redaction, Diagnostics, and Retention  [status: planned]

- **Description:** Implement artifact ownership, redaction, retention, audit events,
  structured failures, status projections, and diagnostic export.
- **Outcome:** A user can inspect or export enough evidence to diagnose a failed
  boundary without exposing tokens, cookies, credentials, or secret page values.
- **Scope (in):** Artifact metadata, storage commit rules, redaction, retention,
  audit records, failure taxonomy, status output, and diagnostic bundles.
- **Scope (out):** Hosted telemetry and collection without explicit export.
- **Depends on:** 007, 010, 012, 013, 014
- **Governed by:** C-01, C-06, C-07, C-08, C-09

### 016 -- Distribution, Upgrade, Compatibility, and Acceptance  [status: planned]

- **Description:** Deliver published installation, extension distribution, protocol
  negotiation, upgrades, uninstall behavior, and end-to-end acceptance gates.
- **Outcome:** A clean supported machine completes all five spec 001 journeys using
  published artifacts, including one interruption and one attention decision.
- **Scope (in):** Package metadata, MCP Registry entry, release artifacts, extension
  delivery, upgrade and rollback rules, compatibility ranges, quickstart, journey
  acceptance, and recorded warm and cold performance baselines.
- **Scope (out):** Hosted distribution services and unsupported browser engines.
- **Depends on:** 005, 006, 007, 008, 009, 010, 011, 012, 013, 014, 015
- **Governed by:** C-01, C-02, C-03, C-04, C-05, C-06, C-07, C-08, C-09, C-10

## Open Questions

None. Deferred entries require a new product decision before their status changes.

## Cross-Cutting Notes

- Session, request, operation, attention, approval, artifact, and connection are
  distinct domain terms. Their state machines belong to spec 001.
- The external contract must separate client connection lifetime from daemon-owned
  request lifetime.
- Browser profile data remains browser-owned. Matinee stores references, grants, and
  redacted evidence rather than credential material.
- Journey 1, install, pair, and connect, gates specs 005-009 and 016.
- Journey 2, control a visible authenticated tab, gates specs 009-012 and 016.
- Journey 3, handle human attention, gates specs 010, 012, 013, and 016.
- Journey 4, recover interrupted work, gates specs 007, 010, 011, 013, 014, and 016.
- Journey 5, cancel and diagnose work, gates specs 014-016.

---

**Version**: 1.2.0 | **Ratified**: 2026-09-11 | **Last Amended**: 2026-09-16
