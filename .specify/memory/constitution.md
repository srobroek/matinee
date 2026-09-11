# Matinee Constitution

## Core Principles

### I. Human Authority

Matinee MUST preserve the user's control over browser activity. Operations requiring
credentials, payments, destructive effects, legal acceptance, or uncertain external
side effects MUST stop before the effect and request explicit approval. A timeout,
client disconnect, or daemon restart MUST NOT imply approval. Matinee MUST resume the
same operation after approval without replaying completed effects.

### II. Visible Browser Ownership

The first complete release MUST automate user-visible Chrome or Chromium tabs through
an explicitly paired extension. The daemon MUST own each Matinee session, while the
extension MUST mediate access to browser tabs. Matinee MUST identify the controlled tab
and display the current operation boundary. Headless execution and Firefox support MUST
NOT weaken this contract when added.

### III. Durable Local State

The daemon MUST be the single writer for persistent Matinee state. A confirmed request
MUST have a stable identity, persisted state transitions, and one terminal outcome.
Process restart, MCP client disconnect, and extension reconnect MUST preserve recoverable
work. Recovery MUST NOT repeat an external effect whose completion was recorded.

### IV. Least Privilege

Matinee MUST run on the user's machine during the first complete release. The daemon
MUST bind control endpoints to loopback, authenticate every client and extension
connection, and reject unknown origins. Browser-profile access MUST require explicit
user pairing. Matinee MUST NOT copy browser credential stores, export cookies, log
secrets, or transmit browser data to a hosted Matinee service.

### V. Observable Contracts

Every externally visible operation MUST expose a stable identifier, state, timestamps,
and a structured result or structured failure. User-facing diagnostics MUST name the
failed boundary and the next safe action. Public MCP tools, CLI output modes, daemon
protocol messages, state transitions, and artifact formats MUST have contract tests.
Protocol evolution MUST reject incompatible peers instead of guessing compatibility.

## Product and Technical Constraints

- The supported product journey is interactive agent use in an existing authenticated
  Chrome or Chromium profile.
- The published product MUST provide an MCP adapter, a persistent local daemon, a browser
  extension, and a setup, status, doctor, and stop CLI.
- The MCP adapter MUST remain stateless between client processes. Persistent ownership
  belongs to the daemon.
- The first release MUST NOT provide hosted execution, remote-machine execution,
  scheduled jobs, unattended recurring jobs, a stable public Rust library, Firefox
  support, or a general-purpose workflow engine.
- Automation MUST use the browser extension transport. Chrome Native Messaging MUST NOT
  be the daemon transport.
- Browser selection MUST fail on ambiguity. Matinee MUST NOT silently choose an
  authenticated profile, window, or tab.
- Performance claims MUST name the measured baseline and scenario. The first release
  targets warm local latency and fewer agent round trips. Claims apply only to measured
  browser scenarios.
- The Rust workspace MUST retain Rust 1.85 as its minimum supported version until a
  reviewed change updates the package metadata and CI matrix.

## Delivery Gates

- Each implementation slice MUST map to a requirement and an observable acceptance
  scenario before code changes begin.
- Behavior that crosses the MCP, daemon, extension, browser, persistence, or approval
  boundaries MUST have an integration test.
- Crash recovery, cancellation, idempotency, approval expiry, origin rejection, token
  rejection, and redaction MUST have deterministic tests.
- A release candidate MUST pass formatting, linting, unit tests, contract tests,
  integration tests, and the documented end-to-end quickstart.
- A user-visible browser change MUST be verified in a real supported browser with the
  extension installed.
- Placeholder implementations, silent fallbacks, compatibility aliases, and partially
  migrated contracts MUST NOT ship.
- Security-sensitive dependencies and browser permissions MUST be justified in the
  specification or an accepted decision record.

## Governance

This constitution governs every Matinee specification, plan, task list, review, and
release. A conflicting artifact MUST be amended before implementation proceeds.

Amendments require an explicit rationale, a migration impact statement, and user
approval. The constitution uses semantic versioning: MAJOR for removed or redefined
principles, MINOR for new principles or materially expanded obligations, and PATCH for
clarifications that do not change obligations.

Every feature plan MUST record a constitution check before design and after contract
design. Reviews MUST identify each violated principle by number. An approved exception
MUST state its scope, expiry condition, and replacement plan.

**Version**: 1.0.0 | **Ratified**: 2026-09-11 | **Last Amended**: 2026-09-11
