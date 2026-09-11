# Matinee Constitution

## Core Principles

### I. Human Authority

Matinee MUST preserve the user's control over browser activity. Before an operation
causes a governed effect, Matinee MUST request explicit approval. Governed effects
include:

- credential use
- payments
- destructive actions
- legal acceptance
- uncertain external side effects.

A timeout, client disconnect, or daemon restart MUST NOT imply approval. After
approval, Matinee MUST resume the same operation without repeating completed effects.

### II. Visible Browser Ownership

The first complete release MUST automate user-visible Chrome or Chromium tabs through
an explicitly paired extension. The daemon MUST own each Matinee session. The
extension MUST mediate browser-tab access. Matinee MUST identify the controlled tab
and display the current operation boundary.

Later headless execution or Firefox support MUST preserve this ownership contract.

### III. Durable Local State

The daemon MUST be the single writer for persistent Matinee state. Each confirmed
request MUST have:

- a stable identity
- persisted state transitions
- one terminal outcome

Process restart, MCP client disconnect, and extension reconnect MUST preserve
recoverable work.
After Matinee records an external effect's completion, recovery MUST NOT repeat that
effect.

### IV. Least Privilege

The first complete release MUST run on the user's machine. The daemon MUST:

- bind control endpoints to loopback
- authenticate every client and extension connection
- reject unknown origins

Browser-profile access MUST require explicit user pairing. Matinee MUST NOT copy
browser credential stores, export cookies, log secrets, or transmit browser data to a
hosted Matinee service.

### V. Observable Contracts

Each externally visible operation MUST expose:

- a stable identifier
- its state and timestamps
- a structured result or failure

User-facing diagnostics MUST name the failed boundary and the next safe action.
Contract tests MUST cover public MCP tools, CLI output modes, daemon protocol messages,
state transitions, and artifact formats. Protocol evolution MUST reject incompatible
peers instead of guessing compatibility.

## Product and Technical Constraints

- The supported product journey is interactive agent use in an existing authenticated
  Chrome or Chromium profile.
- The published product MUST provide an MCP adapter, persistent local daemon, browser
  extension, and setup, status, doctor, and stop CLI commands.
- The MCP adapter MUST remain stateless between client processes. The daemon owns
  persistent state.
- The first release MUST NOT provide hosted execution, remote-machine execution,
  scheduled jobs, unattended recurring jobs, a stable public Rust library, Firefox
  support, or a general-purpose workflow engine.
- Automation MUST use the browser extension transport. Chrome Native Messaging MUST
  NOT serve as the daemon transport.
- Browser selection MUST fail on ambiguity. Matinee MUST NOT silently choose an
  authenticated profile, window, or tab.
- Each performance claim MUST name its measured baseline and scenario. Claims apply
  only to measured browser scenarios.
- The Rust workspace MUST retain Rust 1.85 as its minimum supported version until an
  approved specification updates the package metadata and CI matrix.

## Delivery Gates

- Before code changes begin, each implementation slice MUST map to a requirement and
  an observable acceptance scenario.
- An integration test MUST cover behavior that crosses the MCP, daemon, extension,
  browser, persistence, or approval boundaries.
- Deterministic tests MUST cover crash recovery, cancellation, idempotency, approval
  expiry, origin rejection, token rejection, and redaction.
- A release candidate MUST pass formatting, linting, unit tests, contract tests,
  integration tests, and the documented end-to-end quickstart.
- A real supported browser with the extension installed MUST verify each user-visible
  browser change.
- Placeholder implementations, silent fallbacks, compatibility aliases, and partially
  migrated contracts MUST NOT ship.
- The specification or an accepted decision record MUST justify each security-sensitive
  dependency and browser permission.

## Governance

This constitution governs every Matinee specification, plan, Beads task graph, review,
and release. Contributors MUST amend a conflicting artifact before implementation
proceeds.

Each amendment requires an explicit rationale, migration-impact statement, and user
approval. The constitution uses semantic versioning:

- MAJOR for a removed or redefined principle
- MINOR for a new principle or materially expanded obligation
- PATCH for a clarification that does not change an obligation

Each feature plan MUST record a constitution check before design and after contract
design. Each review MUST identify a violated principle by number. An approved exception
MUST state its scope, expiry condition, and replacement plan.

**Version**: 1.0.0 | **Ratified**: 2026-09-11 | **Last Amended**: 2026-09-11
