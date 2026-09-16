# Tasks: Interactive Local Browser Automation

**Input**: Design documents from `specs/001-interactive-browser-automation/`

**Prerequisites**: [plan.md](plan.md), [spec.md](spec.md),
[research.md](research.md), [data-model.md](data-model.md), and [contracts/](contracts/)

**Tests**: Boundary, contract, recovery, security, redaction, and browser acceptance
tests are required by the specification and constitution.

## Phase 1: Workspace Setup

- [ ] T001 Convert the root package into the five-crate workspace defined in `Cargo.toml`
- [ ] T002 [P] Create the domain crate manifest and module skeleton in `crates/matinee-domain/`
- [ ] T003 [P] Create the protocol crate manifest and schema directories in `crates/matinee-protocol/`
- [ ] T004 [P] Create the store crate manifest and migration directories in `crates/matinee-store/`
- [ ] T005 [P] Create the daemon crate manifest and module skeleton in `crates/matinee-daemon/`
- [ ] T006 [P] Move the installed binary into the CLI crate and preserve 0.0.2 behavior in `crates/matinee-cli/`
- [ ] T007 [P] Create the pnpm TypeScript extension package and Manifest V3 build in `extension/`
- [ ] T008 Add workspace formatting, lint, test, schema-drift, and extension checks to `.github/workflows/ci.yml`
- [ ] T009 Add deterministic browser-site, secret, upload, and effect fixtures under `fixtures/`

## Phase 2: Foundational Contracts and Durable Runtime

**Goal**: Establish the shared contracts, states, persistence, authentication, and daemon
lifecycle required by every user story.

- [ ] T010 Write transition-table tests for every state and invariant in `crates/matinee-domain/tests/state_machines.rs`
- [ ] T011 [P] Write failure-envelope and effect-class tests in `crates/matinee-domain/tests/failures.rs`
- [ ] T012 Implement typed identifiers, clocks, digests, effect classes, and failure records in `crates/matinee-domain/src/`
- [ ] T013 Implement daemon, connection, session, request, operation, attention, approval, artifact, and idempotency transitions in `crates/matinee-domain/src/`
- [ ] T014 Write JSON round-trip and version-rejection tests for every external envelope in `crates/matinee-protocol/tests/contracts.rs`
- [ ] T015 Implement `matinee.daemon.v1`, `matinee.extension.v1`, `matinee.cli.v1`, `matinee.tools.v1`, and artifact types in `crates/matinee-protocol/src/`
- [ ] T016 Generate canonical JSON Schemas and TypeScript types with a drift check in `crates/matinee-protocol/schemas/` and `extension/src/protocol/`
- [ ] T017 Write migration, foreign-key, idempotency-conflict, and single-writer tests in `crates/matinee-store/tests/store.rs`
- [ ] T018 Write crash cases after every acknowledged transition and artifact boundary in `crates/matinee-store/tests/crash_matrix.rs`
- [ ] T019 Implement numbered SQLite migrations for every entity in `crates/matinee-store/migrations/`
- [ ] T020 Implement the dedicated database actor with WAL, foreign keys, full effect-boundary sync, and five-second busy timeout in `crates/matinee-store/src/actor.rs`
- [ ] T021 Implement transactional idempotency, audit chaining, retention metadata, and artifact commit or tombstone commands in `crates/matinee-store/src/`
- [ ] T022 Write daemon-election, readiness, draining, and concurrent-start tests in `crates/matinee-daemon/tests/lifecycle.rs`
- [ ] T023 Implement state-directory locking, startup recovery, readiness, and graceful draining in `crates/matinee-daemon/src/runtime/`
- [ ] T024 Write loopback-bind, bearer, origin, rotation, revocation, protocol-range, configuration-precedence, and security-floor tests in `crates/matinee-daemon/tests/security.rs` and `crates/matinee-daemon/tests/config.rs`
- [ ] T025 Implement platform credential-store integration and per-principal authentication in `crates/matinee-daemon/src/auth/`
- [ ] T026 Implement layered configuration with reported sources and bounded loopback HTTP and WebSocket routing in `crates/matinee-daemon/src/config.rs` and `crates/matinee-daemon/src/transport/`

**Checkpoint**: Domain transitions reject invalid paths, schemas match across languages,
SQLite survives injected boundaries, one daemon reaches readiness, and unauthenticated
connections cannot read state.

## Phase 3: User Story 1 - Install, Pair, and Connect (P1)

**Goal**: A clean user installs Matinee, pairs one extension, connects an MCP client,
and reads authoritative status.

**Independent Test**: Complete quickstart sections 1-3 on a clean supported machine in
10 minutes or less.

- [ ] T027 [US1] Write CLI JSON, exit-code, and read-only doctor contract tests in `crates/matinee-cli/tests/cli_contract.rs`
- [ ] T028 [P] [US1] Write one-time pairing, expiry, replay, wrong-origin, rotation, and revocation tests in `crates/matinee-daemon/tests/pairing.rs`
- [ ] T029 [P] [US1] Write extension service-worker reconnect and disposable-memory tests in `extension/tests/service-worker.test.ts`
- [ ] T030 [US1] Implement `setup`, `doctor`, `status`, `stop`, `version`, and JSON envelopes in `crates/matinee-cli/src/commands/`
- [ ] T031 [US1] Implement guarded daemon start and authenticated daemon client behavior in `crates/matinee-cli/src/client.rs`
- [ ] T032 [US1] Implement ten-minute single-use pairing and credential lifecycle in `crates/matinee-daemon/src/auth/pairing.rs`
- [ ] T033 [US1] Build the extension pairing surface and credential storage in `extension/src/surfaces/pairing.ts` and `extension/src/service-worker/`
- [ ] T034 [US1] Add extension negotiation, keepalive, reconnect, and resume messages in `extension/src/service-worker/connection.ts`
- [ ] T035 [US1] Implement the RMCP stdio adapter, supported protocol versions, and `matinee_status` tool in `crates/matinee-cli/src/mcp/`
- [ ] T036 [US1] Add the clean install, pair, two-client connect, adapter-exit, and status journey in `tests/journeys/install_pair_connect.rs`

**Checkpoint**: One published-shape binary and one unpacked extension complete the first
three quickstart sections without copying browser credentials or tying daemon lifetime
to an adapter.

## Phase 4: User Story 2 - Control a Visible Authenticated Tab (P1)

**Goal**: An MCP client acquires one explicit tab, observes it, performs the complete
first operation set, and releases it with visible user indicators.

**Independent Test**: Complete quickstart sections 4-5 against the authenticated fixture
profile and leave the adopted tab open.

- [ ] T037 [US2] Write browser-selection, ownership-race, rebind, and adopted-tab tests in `crates/matinee-daemon/tests/sessions.rs`
- [ ] T038 [P] [US2] Write document-generation, bounded-observation, stale-reference, and operation-order tests in `extension/tests/content.test.ts`
- [ ] T039 [P] [US2] Write overlay focus, pointer, target, release, and reduced-motion checks in `extension/tests/overlays.test.ts`
- [ ] T040 [US2] Implement browser candidate discovery and exact selection in `extension/src/service-worker/browser.ts` and `crates/matinee-daemon/src/browser/selection.rs`
- [ ] T041 [US2] Implement exclusive tab ownership, session persistence, reconnect, and release in `crates/matinee-daemon/src/browser/session.rs`
- [ ] T042 [US2] Implement optional per-origin host permission from a user gesture in `extension/src/surfaces/permissions.ts`
- [ ] T043 [US2] Implement isolated-world content injection, document generations, and semantic observations in `extension/src/content/`
- [ ] T044 [US2] Implement visible tab status, synthetic pointer, pre-activation target highlight, and cleanup in `extension/src/content/overlays.ts`
- [ ] T045 [US2] Dispatch navigation, click, type, key, scroll, select, upload, wait, and screenshots in `extension/src/content/operations.ts`
- [ ] T046 [US2] Implement per-tab queues, preflight, stale rejection, effect records, and safe retry limits in `crates/matinee-daemon/src/browser/operations.rs`
- [ ] T047 [US2] Implement browser, session, observation, and operation MCP tools from `contracts/mcp-tools.md` in `crates/matinee-cli/src/mcp/tools/`
- [ ] T048 [US2] Add the full visible authenticated-tab operation journey in `tests/journeys/visible_tab.rs`

**Checkpoint**: The operation journey shows every indicator, rejects ambiguity and stale
references before action, preserves per-tab order, and leaves an adopted tab open.

## Phase 5: User Story 3 - Handle Human Attention (P1)

**Goal**: Sensitive and uncertain effects pause for an exact, trusted, single-use user
decision in the extension.

**Independent Test**: Complete quickstart section 6 for approve, deny, edit, cancel, and
expiry. No MCP self-approval executes an effect.

- [ ] T049 [US3] Write pure policy and transition tests for every sensitive effect and decision in `crates/matinee-domain/tests/attention.rs`
- [ ] T050 [P] [US3] Write trusted-surface, wrong-principal, replay, scope-change, restart, and expiry tests in `crates/matinee-daemon/tests/attention.rs`
- [ ] T051 [P] [US3] Write keyboard, screen-reader, focus, and decision-state tests for the extension side panel in `extension/tests/attention.test.ts`
- [ ] T052 [US3] Implement effect-policy evaluation and durable attention creation in `crates/matinee-daemon/src/runtime/attention.rs`
- [ ] T053 [US3] Implement exact operation digests, single-use approval consumption, edit replacement, denial, cancellation, and expiry in `crates/matinee-domain/src/attention.rs` and `crates/matinee-store/src/attention.rs`
- [ ] T054 [US3] Implement the redacted trusted attention side panel and decision messages in `extension/src/sidepanel/attention.ts`
- [ ] T055 [US3] Connect operation pause and resume without replay in `crates/matinee-daemon/src/browser/operations.rs`
- [ ] T056 [US3] Expose redacted pending attention without approval mutation in `crates/matinee-cli/src/mcp/tools/attention.rs`
- [ ] T057 [US3] Add credential, payment, deletion, legal, permission, uncertain, edit, denial, cancel, and expiry journeys in `tests/journeys/attention.rs`

**Checkpoint**: Every sensitive fixture pauses before effect, approvals are exact and
single-use, and zero untrusted client approval shapes execute.

## Phase 6: User Story 4 - Recover an Interrupted Request (P1)

**Goal**: Daemon, adapter, extension, and browser interruptions preserve authoritative
state without replaying completed or uncertain effects.

**Independent Test**: Complete quickstart section 7 and the 100-case daemon restart plus
100-case adapter disconnect criteria.

- [ ] T058 [US4] Write operation-classification and reconciliation tests in `crates/matinee-domain/tests/recovery.rs`
- [ ] T059 [P] [US4] Write daemon restart, adapter disconnect, extension reconnect, browser exit, and incompatible-peer tests in `crates/matinee-daemon/tests/recovery.rs`
- [ ] T060 [US4] Implement startup classification for interrupted operations in `crates/matinee-daemon/src/runtime/recovery.rs`
- [ ] T061 [US4] Prove extension tab and document rebinding in `extension/src/service-worker/resume.ts`
- [ ] T062 [US4] Preserve completed effects, retry safe observations, and block uncertain effects in `crates/matinee-daemon/src/browser/reconcile.rs`
- [ ] T063 [US4] Implement request resync after event-history gaps in `crates/matinee-cli/src/client.rs` and `crates/matinee-cli/src/mcp/`
- [ ] T064 [US4] Add the boundary crash matrix and disconnect soak journey in `tests/journeys/recovery.rs`

**Checkpoint**: Every injected interruption yields one authoritative state, no recorded
completed effect repeats, and uncertainty blocks instead of retrying.

## Phase 7: User Story 5 - Cancel and Diagnose Work (P2)

**Goal**: Users inspect, cancel, retain, expire, redact, and export operational evidence
without affecting unrelated sessions or exposing secrets.

**Independent Test**: Complete quickstart section 8 with two tabs, cancellation, forced
failure, diagnostic export, and a zero-match secret scan.

- [ ] T065 [US5] Write cancellation-boundary, late-result, and independent-session tests in `crates/matinee-daemon/tests/cancellation.rs`
- [ ] T066 [P] [US5] Write artifact transaction, tombstone, partial-failure, and retention tests in `crates/matinee-store/tests/artifacts.rs`
- [ ] T067 [P] [US5] Write seeded secret tests for logs, events, screenshots, artifacts, status, and export in `crates/matinee-daemon/tests/redaction.rs`
- [ ] T068 [US5] Implement persisted cancellation intent, safe interruption, and late-result reconciliation in `crates/matinee-daemon/src/runtime/cancellation.rs`
- [ ] T069 [US5] Implement browser-side sensitive-field masking and unsafe-capture rejection in `extension/src/content/artifacts.ts`
- [ ] T070 [US5] Implement structured redaction and content-addressed artifact lifecycle in `crates/matinee-daemon/src/artifacts/`
- [ ] T071 [US5] Implement failure classification and safe next-action mapping in `crates/matinee-daemon/src/diagnostics/failures.rs`
- [ ] T072 [US5] Implement bounded local metrics, status summaries, audit verification, and diagnostic export in `crates/matinee-daemon/src/diagnostics/`
- [ ] T073 [US5] Implement history and artifact retention cleanup with durable tombstones in `crates/matinee-store/src/retention.rs`
- [ ] T074 [US5] Add request, cancellation, attention-list, artifact, and `diagnostic_export` MCP tools in `crates/matinee-cli/src/mcp/tools/`
- [ ] T075 [US5] Add the two-tab cancellation, failure, export, and secret-scan journey in `tests/journeys/diagnostics.rs`

**Checkpoint**: Cancellation is idempotent, unrelated sessions continue, each failure is
actionable, and no seeded secret reaches persisted or exported bytes.

## Phase 8: Packaging and Release Proof

- [ ] T076 Write migration-upgrade, failed-migration restore, and downgrade-rejection tests in `crates/matinee-store/tests/upgrades.rs`
- [ ] T077 Implement transactional migration backup and compatibility checks in `crates/matinee-store/src/migration.rs`
- [ ] T078 Implement explicit retain or delete uninstall behavior in `crates/matinee-cli/src/commands/uninstall.rs`
- [ ] T079 Add reproducible macOS, Linux, and Windows archives with checksums or signatures and a validated MCP Registry `server.json` in `.github/workflows/release.yml` and `server.json`
- [ ] T080 Add Chrome Web Store and unpacked-development extension packaging with manifest validation in `.github/workflows/release.yml` and `extension/manifest.json`
- [ ] T081 Add Rust 1.85 minimum-version, current stable, extension, schema, and browser acceptance jobs in `.github/workflows/ci.yml`
- [ ] T082 Run and record the 1,000-request latency benchmark in `tests/benchmarks/dispatch.rs` and `specs/001-interactive-browser-automation/evidence/performance.json`
- [ ] T083 Run and record the four-tab 100-operation concurrency proof in `specs/001-interactive-browser-automation/evidence/concurrency.json`
- [ ] T084 Run every row in `contracts/acceptance-matrix.md` and link its artifact or test result in that file
- [ ] T085 Complete the real-browser release journey from `quickstart.md` and record accessibility plus visual evidence under `specs/001-interactive-browser-automation/evidence/`
- [ ] T086 Verify `.specify/memory/roadmap.md` records spec 001 as specced and `.specify/memory/constitution.md` contains no temporary review report
- [ ] T087 Update `README.md` to the verified installation, pairing, MCP, attention, recovery, and diagnostics behavior
- [ ] T088 Verify format, lint, tests, generated-schema drift, prose, package contents, checksums, and the complete quickstart through the repository release gate

## Dependencies

```text
Phase 1 -> Phase 2 -> US1 -> US2 -> US3 -> US4 -> US5 -> Packaging
```

- US1 requires the foundational daemon, protocol, authentication, and store.
- US2 requires paired extension transport and MCP status from US1.
- US3 requires session ownership and operation preflight from US2.
- US4 requires persisted requests, operations, attention, and session rebinding from
  US1-US3.
- US5 requires cancellation and diagnostic evidence from all prior behavior.
- Packaging requires every user-story checkpoint and acceptance row.

## Parallel Execution Examples

- After T001, T002-T007 can proceed in parallel because they create disjoint packages.
- In Phase 2, domain tests T010-T011, protocol tests T014, store tests T017-T018, and
  lifecycle tests T022 can begin against the approved contracts in parallel.
- In US1, pairing tests T028 and extension reconnect tests T029 are independent after
  foundational schemas exist.
- In US2, content semantics T038 and visual overlay tests T039 can proceed in parallel.
- In US3, daemon trust tests T050 and extension accessibility tests T051 can proceed in
  parallel after T049 fixes the transition contract.
- In US5, artifact tests T066 and redaction tests T067 can proceed in parallel after the
  artifact and sensitivity schemas stabilize.

## Implementation Strategy

The first releasable increment is the complete vertical path through US1-US4 plus the
US5 security and diagnostic gates. US1 alone is a developer checkpoint, not a product
release. Each phase lands only after its checkpoint passes. No public command, MCP tool,
or extension control ships with inert backing behavior.
