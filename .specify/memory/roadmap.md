<!--
SYNC IMPACT REPORT
==================
Version change: none -> 1.0.0
Bump rationale: MAJOR -- initial roadmap ratification

Changes this revision:
  - Added specced entry 001 -- Interactive Local Browser Automation
  - Added deferred specs 002-004
  - Recorded constraints C-01-C-08

Specs affected: 001, 002, 003, 004
Open questions added/resolved: none

Notes: The roadmap captures the approved grilling decisions from 2026-09-11.
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

## Specifications

### 001 -- Interactive Local Browser Automation  [status: specced]

- **Description:** Define and deliver the first complete Matinee product for MCP-driven
  interaction with a visible authenticated Chrome or Chromium tab.
- **Outcome:** A user installs and pairs Matinee, connects an MCP client, completes an
  authenticated browser task, handles an approval request, observes evidence, and
  resumes recoverable work after an injected interruption.
- **Scope (in):** CLI lifecycle, persistent daemon, stdio MCP adapter, extension pairing,
  browser-session ownership, interactive request execution, attention and approval,
  persistence, recovery, cancellation, artifacts, diagnostics, configuration,
  packaging, upgrades, protocol negotiation, and acceptance scenarios.
- **Scope (out):** Hosted services, remote machines, headless execution, Firefox,
  schedules, unattended recurring jobs, a stable public Rust library, and a
  general-purpose workflow language.
- **Depends on:** none
- **Governed by:** C-01, C-02, C-03, C-04, C-05, C-06, C-07, C-08
- **Spec dir:** `specs/001-interactive-browser-automation/`
- **Notes:** This is one vertical product slice. Partial implementations and inert
  surfaces do not satisfy the outcome.

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
- **Scope (out):** A general-purpose non-browser workflow engine.
- **Depends on:** 001
- **Governed by:** C-05, C-06, C-07

## Open Questions

None. Deferred entries require a new product decision before their status changes.

## Cross-Cutting Notes

- Session, request, operation, attention, approval, artifact, and connection are
  distinct domain terms. Their state machines belong to spec 001.
- The external contract must separate client connection lifetime from daemon-owned
  request lifetime.
- Browser profile data remains browser-owned. Matinee stores references, grants, and
  redacted evidence rather than credential material.

---

**Version**: 1.0.0 | **Ratified**: 2026-09-11 | **Last Amended**: 2026-09-11
