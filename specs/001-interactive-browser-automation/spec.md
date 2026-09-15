# Feature Specification: Interactive Local Browser Automation

**Feature Branch**: `001-interactive-browser-automation`

**Created**: 2026-09-11

**Status**: Ready for implementation

**Input**: Deliver the first complete Matinee product for MCP-driven interaction
with a visible, existing, authenticated Chrome or Chromium browser.

## User Scenarios & Testing

### User Story 1 - Install, Pair, and Connect (Priority: P1)

An MCP client user installs Matinee, starts the local runtime, pairs the browser
extension, and connects an MCP client. Matinee reports each boundary and does not
copy the browser profile or ask the user to sign in again.

**Why this priority**: No browser operation can begin until the user establishes
local trust between the client, daemon, extension, and browser.

**Independent Test**: On a clean supported machine, install the published package,
run setup, pair one browser, configure one MCP client, and query Matinee status.
The result identifies one ready daemon, one paired extension, and no active session.

**Acceptance Scenarios**:

1. **Given** no Matinee state, **When** the user runs setup and confirms pairing in
   the extension, **Then** Matinee creates local credentials and reports the paired
   browser without reading or copying browser credentials.
2. **Given** a healthy daemon, **When** an MCP client starts the adapter, **Then**
   the adapter connects to that daemon and exposes the compatible tool set.
3. **Given** no daemon, **When** an MCP client starts the adapter, **Then** the
   adapter starts one daemon, waits for readiness, and reports a bounded startup
   failure if readiness is not reached.
4. **Given** an unknown extension or client token, **When** it connects, **Then**
   Matinee rejects it and records a redacted security event.
5. **Given** two compatible MCP clients, **When** both connect, **Then** each sees
   the same daemon-owned session state without owning the daemon process.

---

### User Story 2 - Control a Visible Authenticated Tab (Priority: P1)

An agent opens or adopts an explicitly selected browser tab, observes its state,
and performs browser operations. The user can see the controlled tab, cursor,
active target, and operation boundary while actions occur.

**Why this priority**: Visible interaction with an existing authenticated browser
is Matinee's primary product value.

**Independent Test**: Use an MCP client to select a paired browser, open a session,
navigate an authenticated test site, inspect the page, activate a control, enter
non-secret text, and close the session. The browser remains open and the operation
history is queryable.

**Acceptance Scenarios**:

1. **Given** one paired browser and one eligible tab, **When** the client requests
   a session for that tab, **Then** Matinee returns a stable session identifier and
   marks the tab as controlled.
2. **Given** two eligible tabs or browsers, **When** the client omits selection,
   **Then** Matinee returns an ambiguity error and lists redacted candidates.
3. **Given** an active session, **When** an operation targets an element, **Then**
   the extension displays the Matinee cursor and target highlight before activation.
4. **Given** an active session, **When** the agent requests page state, **Then**
   Matinee returns a bounded semantic snapshot and stable references for the current
   document generation.
5. **Given** navigation or a document replacement, **When** the client reuses an old
   element reference, **Then** Matinee rejects it as stale without acting.
6. **Given** session closure, **When** Matinee releases the tab, **Then** it removes
   Matinee indicators and leaves the user's browser and tab open unless Matinee
   created the tab and the client explicitly requested closure.

---

### User Story 3 - Handle Human Attention (Priority: P1)

Matinee pauses before a sensitive or uncertain external effect, explains the exact
pending action, and asks the user to approve, deny, edit, or cancel it. The agent
can continue after the user's decision without replaying completed operations.

**Why this priority**: Existing authenticated profiles make accidental external
side effects materially consequential.

**Independent Test**: Run a task that reaches a test purchase boundary. Verify that
Matinee pauses before submission, presents redacted context, rejects client-side
self-approval, accepts a user decision from a trusted surface, and resumes exactly
once after approval.

**Acceptance Scenarios**:

1. **Given** an operation that enters a credential, confirms a payment, deletes data,
   accepts legal terms, or causes an uncertain external effect, **When** it reaches
   the effect boundary, **Then** Matinee creates one attention request and pauses.
2. **Given** a pending attention request, **When** an MCP client sends an approval
   without proof of a trusted user decision, **Then** Matinee rejects it.
3. **Given** a pending request, **When** the user approves the displayed action,
   **Then** Matinee records the decision, executes the approved operation once, and
   resumes the request.
4. **Given** a pending request, **When** the user denies or cancels it, **Then**
   Matinee leaves the operation undispatched and returns the selected terminal outcome.
5. **Given** a pending request, **When** its deadline expires, **Then** Matinee marks
   it expired and does not infer approval.
6. **Given** an operation whose scope changed after approval, **When** execution
   resumes, **Then** Matinee invalidates the approval and asks again with new details.

---

### User Story 4 - Recover an Interrupted Request (Priority: P1)

An agent or user can reconnect after an MCP client exit, extension disconnect, or
daemon restart and discover the authoritative state of a confirmed request.
Matinee resumes only operations whose safety can be established.

**Why this priority**: Durable recovery distinguishes Matinee from a client-owned
browser-control subprocess.

**Independent Test**: Inject a daemon termination between two operations and an MCP
client disconnect during a pending approval. Restart and reconnect. Verify the same
request and approval identifiers, no duplicate completed effect, and one terminal
request outcome.

**Acceptance Scenarios**:

1. **Given** a confirmed request with completed operations, **When** its MCP client
   disconnects, **Then** Matinee preserves the request and exposes it after reconnect.
2. **Given** a daemon restart, **When** recovery completes, **Then** Matinee restores
   durable sessions, requests, approvals, and artifact references before accepting
   new mutations.
3. **Given** an operation recorded as completed, **When** recovery runs, **Then**
   Matinee does not execute that operation again.
4. **Given** an operation whose external effect is uncertain, **When** recovery runs,
   **Then** Matinee marks the request blocked for reconciliation rather than retrying.
5. **Given** a temporary extension disconnect, **When** the same paired extension
   reconnects before the deadline, **Then** Matinee rebinds the browser session and
   resumes from the durable boundary.
6. **Given** an incompatible extension after restart, **When** it reconnects, **Then**
   Matinee rejects mutation, preserves state, and reports the required upgrade.

---

### User Story 5 - Cancel and Diagnose Work (Priority: P2)

A user or client can inspect active and historical requests, cancel eligible work,
and export redacted diagnostics. Failures identify the boundary, classification,
request state, and safe next action.

**Why this priority**: Durable state without cancellation and diagnostics would leave
users unable to control or support the runtime.

**Independent Test**: Start two requests in separate sessions, cancel one during an
interruptible operation, force the other to fail, and inspect status plus its exported
diagnostic bundle. Neither request affects the other.

**Acceptance Scenarios**:

1. **Given** an interruptible active operation, **When** an authorized actor cancels
   its request, **Then** Matinee stops before the next effect boundary and records a
   cancelled terminal outcome.
2. **Given** an operation already crossing a non-interruptible browser boundary,
   **When** cancellation arrives, **Then** Matinee records cancellation intent,
   reconciles the operation, and reports whether the effect completed.
3. **Given** concurrent sessions, **When** one fails or is cancelled, **Then** Matinee
   preserves the other session unless they contend for the same tab.
4. **Given** a failed request, **When** the user inspects it, **Then** diagnostics name
   one failure class, one failed boundary, and at least one safe next action.
5. **Given** a diagnostic export, **When** it is created, **Then** it excludes tokens,
   cookies, credentials, secret form values, and unredacted sensitive page content.

### Edge Cases

- The daemon receives two start attempts at the same time.
- Two clients submit the same idempotency key with different request bodies.
- Two sessions attempt to own the same tab.
- The user manually navigates, closes, or detaches a controlled tab.
- The extension reconnects with a rotated or revoked pairing credential.
- The browser exits while a request is active or awaiting approval.
- The target frame, document, or element changes between observation and action.
- An operation returns after its request was cancelled.
- The machine clock moves backward or forward during a deadline.
- Persistent storage is locked, full, missing, or fails an integrity check.
- An artifact write succeeds but its metadata transaction fails, or the reverse.
- Redaction removes all useful page content from an artifact.
- The installed adapter, daemon, and extension support incompatible protocol ranges.
- A configured retention policy expires artifacts referenced by a retained request.
- The user selects a browser profile that is already controlled by another runtime.

## Requirements

### Functional Requirements

#### Installation and Lifecycle

- **FR-001**: Matinee MUST ship a published MCP Registry entry and an installation path
  that provides the CLI, daemon, and stdio MCP adapter without a source checkout.
- **FR-002**: The CLI MUST provide `setup`, `doctor`, `status`, `stop`, `mcp`,
  `diagnostics export`, `version`, `uninstall`, and `help` commands with human-readable
  output where applicable and a versioned JSON output mode.
- **FR-003**: Setup MUST bootstrap the first native principal only through inherited OS
  IPC, resume safely across crashes before or after principal commit, install or locate
  an approved extension package, bind enrollment to its expected identity, create local
  runtime state, and print MCP client configuration.
- **FR-004**: Doctor MUST check supported browser availability, extension pairing,
  local endpoint reachability, storage integrity, protocol compatibility, and file
  permissions without mutating browser or request state.
- **FR-005**: Status MUST report daemon identity, readiness, protocol version, paired
  extensions, active sessions, active requests, pending attention, and degraded
  dependencies without exposing secrets.
- **FR-006**: Stop MUST request graceful shutdown, preserve recoverable state, report
  operations that could not reach a safe boundary, and return a nonzero result when
  the daemon cannot be stopped safely.
- **FR-007**: Concurrent daemon starts MUST converge on one authoritative daemon for
  one state directory. A losing process MUST connect to or report the winner.

#### Surface Ownership

- **FR-008**: A persistent local daemon MUST own sessions, requests, operations,
  attention requests, artifacts, configuration resolution, and recovery.
- **FR-009**: Each stdio MCP adapter MUST require one non-secret MCP principal ID,
  resolve exactly that principal's private key and pinned daemon identity from the platform
  credential store, translate one client connection into daemon requests, and terminate
  without terminating daemon-owned work. It MUST reject an administrator principal.
- **FR-010**: The extension MUST mediate browser discovery, tab ownership, semantic
  observation, visible indicators, browser actions, and trusted user decisions.
- **FR-011**: The CLI MUST manage installation and runtime lifecycle. It MUST NOT
  become a second browser-control or persistence implementation.
- **FR-012**: The first release MUST NOT expose a stable public Rust library API.

#### Pairing, Connections, and Compatibility

- **FR-013**: The daemon MUST bind control endpoints to loopback interfaces only. Every
  state-bearing peer MUST authenticate the daemon and establish encryption before sending
  a product payload. First-principal bootstrap MUST use inherited OS IPC, not loopback.
- **FR-014**: Setup MUST create separate ECDSA P-256 keypairs for the daemon, each extension,
  and each MCP client. Private keys MUST remain in their owning platform credential store
  or extension storage. Identity MUST support rotation and live revocation.
- **FR-015**: Every state-bearing connection MUST mutually authenticate and encrypt
  payloads before reading state or invoking an operation. Every route, tool, event, and
  object lookup MUST authorize capability and ownership before disclosing object existence.
- **FR-016**: Peers MUST negotiate a protocol range and capability set before mutation.
  Incompatible peers MUST receive a structured upgrade error.
- **FR-017**: Reconnection and object access MUST bind only to durable identities owned
  by the same principal or to an explicit extension grant for that principal's session.

#### Browser and Session Ownership

- **FR-018**: The first release MUST support declared stable Chrome and Chromium
  versions through the paired extension. Other engines MUST report unsupported.
- **FR-019**: Matinee MUST use the user's existing browser process and authenticated
  profile. It MUST NOT copy, parse, or export the profile's credential stores.
- **FR-020**: Session open MUST either adopt one listed candidate or create one visible
  tab in an explicitly selected browser, authenticated profile, and window. Selection
  MUST be explicit whenever more than one eligible candidate, browser, profile, or window
  exists.
- **FR-021**: One tab MUST have at most one mutating Matinee session owner. Read-only
  inspection MAY be shared when the returned state identifies the owner and age.
- **FR-022**: A session MUST retain a stable identity across extension reconnects and
  daemon restarts while its tab can be safely rebound.
- **FR-023**: The extension MUST show a visible Matinee indicator on a controlled tab,
  a synthetic cursor during pointer operations, and a target highlight before an
  activation changes page state.
- **FR-024**: Matinee MUST clear its visible indicators when a session releases a tab.
- **FR-025**: Matinee MUST distinguish tabs it created from tabs it adopted. Session
  closure MUST leave adopted tabs open by default.

#### Observation and Operations

- **FR-026**: Matinee MUST expose bounded semantic page observations with document-
  generation-scoped element references and explicit truncation metadata.
- **FR-027**: Navigation or document replacement MUST invalidate earlier element
  references. An invalid reference MUST fail before an action is sent.
- **FR-028**: The first operation set MUST cover browser and tab discovery, session
  open and close, navigation, semantic observation, element activation, text entry,
  key input, scrolling, selection, trusted-user file selection and upload, waiting,
  and screenshots. A `file_upload` request MUST NOT provide or receive a local source
  path or source-file bytes. Authorized Matinee-generated artifact resources are separate.
- **FR-029**: Every mutating operation MUST declare its target, expected document
  generation, timeout, and idempotency key. The daemon and extension MUST compute the
  effective effect class. A client hint can only raise that class. A persisted screenshot
  is a local durable mutation.
- **FR-030**: Matinee MUST serialize mutating operations per tab and MAY execute
  operations concurrently on different tabs subject to configured limits.
- **FR-031**: A client retry with the same idempotency key and equivalent request MUST
  return the authoritative prior result. A different request body with that key MUST
  fail as a conflict.
- **FR-032**: Matinee MUST retry only operations that its effective policy classifies as
  safe and transient. Disagreement or insufficient evidence MUST classify as uncertain.
  Retry limits and backoff MUST remain visible in the request record.

#### Requests, Attention, and Cancellation

- **FR-033**: A confirmed MCP mutation MUST create a durable request before its first
  browser effect. The daemon MUST assign stable request and operation identifiers.
- **FR-034**: A request MUST have exactly one terminal outcome: succeeded, failed,
  cancelled, or expired.
- **FR-035**: Matinee MUST request human attention before credential entry, payment
  confirmation, destructive action, legal acceptance, permission grant, local-file
  disclosure, or an external effect whose safety classification is uncertain.
- **FR-036**: An attention request MUST identify the pending operation, reason,
  redacted target and value summary, destination origin, requested decisions, creation
  time, deadline, and trusted decision surface. File disclosure MUST also identify the
  selected control plus each file's name, media type, size, and content digest.
- **FR-037**: User decisions MUST be approve, deny, edit, or cancel. Approval MUST bind
  to exact operation content and, for upload, one user-selected immutable file identity
  and destination. The daemon MUST consume the approval at most once.
- **FR-038**: MCP clients MUST NOT self-assert trusted approval or choose local file
  paths. The daemon MUST accept decisions only from a paired approved extension identity.
- **FR-039**: Timeout, disconnect, restart, and reconnect MUST preserve a non-approved
  state. Credential revocation MUST close live channels, invalidate unconsumed approvals,
  and prevent later decisions from that principal.
- **FR-040**: Cancellation MUST be idempotent, persist intent before interrupting work,
  and reconcile any operation already crossing an effect boundary.

#### Persistence, Recovery, and Artifacts

- **FR-041**: The daemon MUST persist every confirmed request and every state transition
  required to recover before acknowledging it to the caller.
- **FR-042**: Recovery MUST complete and expose a readiness result before the daemon
  accepts new mutating requests.
- **FR-043**: Recovery MUST classify interrupted operations as safe to retry, completed,
  failed, or requiring reconciliation. It MUST NOT retry an uncertain external effect.
- **FR-044**: Matinee MUST retain structured request history for 30 days by default.
  Users MUST be able to configure shorter or longer retention.
- **FR-045**: Screenshots and page-derived artifacts MUST be opt-in per request or
  generated for a declared diagnostic reason. A persisted capture MUST be idempotent and
  return its prior artifact on equivalent retry. Default artifact retention is 7 days.
- **FR-046**: Artifact metadata MUST include owner, request, operation, media type,
  byte size, digest, redaction status, creation time, and expiry time.
- **FR-047**: Deleting or expiring an artifact MUST preserve a tombstone while its
  request history is retained.
- **FR-048**: Persistence and artifact cleanup MUST be safe under concurrent startup,
  process interruption, and partial filesystem failure.

#### Configuration and Diagnostics

- **FR-049**: Ordinary configuration precedence MUST be defaults, user configuration,
  project configuration, environment variables, then command-line arguments. Higher
  layers override only allowed keys they define.
- **FR-050**: Only user configuration or an explicit CLI argument MAY select the state
  directory, daemon endpoint, native principal, or development extension identity.
  Project and environment configuration MUST NOT set these keys or weaken mutual
  authentication, loopback binding, redaction, authorization, or approval requirements.
- **FR-051**: Resolved non-secret configuration and each value's source MUST be
  available through status diagnostics.
- **FR-052**: Failures MUST use one primary class: input, selection, authentication,
  authorization, compatibility, browser, stale-state, timeout, cancellation,
  persistence, artifact, recovery, resource-limit, or internal.
- **FR-053**: Every structured failure MUST include a stable code, class, summary,
  failed boundary, retryability, request and operation identifiers when assigned,
  and safe next actions.
- **FR-054**: Logs and exported diagnostics MUST redact connection material, enrollment
  keys, private keys, cookies, authorization headers, credentials, secret form values,
  and page content marked sensitive before writing to disk.
- **FR-055**: Matinee MUST expose bounded local metrics for request latency, queue depth,
  retry count, attention wait, recovery, and failures through a local authenticated
  diagnostics surface.

#### Stability, Packaging, and Upgrade

- **FR-056**: Every persisted schema and external contract MUST have an explicit
  compatibility version. This includes the state schema, fixed secure-channel context,
  selected daemon and extension application contracts, CLI JSON, MCP tools, failure
  codes, state transitions, and artifact metadata.
- **FR-057**: The initial public contract is unstable before 1.0. Every release MUST
  document contract changes and reject incompatible peers; it MUST NOT retain silent
  aliases for removed contracts.
- **FR-058**: Upgrades MUST preserve supported durable state through an explicit,
  transactional migration. Downgrade over migrated state MUST fail unless declared
  safe by that release.
- **FR-059**: The supported installation path MUST provide signed platform artifacts
  plus matching checksums for macOS, Linux, and Windows. Production pairing MUST match
  the configured Origin, Chrome Web Store update URL, `normal` install type, and version.
  An unpacked build MUST use a distinct ID and an explicit interactive allowance.
- **FR-060**: Uninstall MUST stop the daemon, revoke local registrations, and offer a
  separate explicit choice to retain or delete history and artifacts.

### Key Entities

- **Daemon Instance**: The single active writer for one local state directory.
- **Principal**: An authenticated MCP client registration or paired extension.
- **Connection**: A transient authenticated channel with negotiated capabilities.
- **Browser Target**: A paired browser, profile reference, window, or tab candidate.
- **Browser Session**: Durable ownership of one controlled tab and its rebinding data.
- **Request**: A durable client intent with one terminal outcome.
- **Operation**: One ordered browser interaction inside a request.
- **Attention Request**: A pause requiring a trusted user decision.
- **Approval**: A single-use decision scoped to one exact operation.
- **Artifact**: Redacted evidence or diagnostic content with retention metadata.
- **Audit Event**: An append-only security or lifecycle fact without secret content.
- **Idempotency Record**: The request digest and authoritative result for one key.

## Success Criteria

### Measurable Outcomes

- **SC-001**: A new user completes install, extension pairing, MCP configuration, and
  a successful status query in 10 minutes or less using the published quickstart.
- **SC-002**: In 100 injected daemon restarts at persisted operation boundaries, every
  request returns one terminal outcome and no recorded completed effect is repeated.
- **SC-003**: In 100 MCP adapter disconnects, confirmed daemon-owned requests remain
  discoverable after reconnect and the daemon stays available.
- **SC-004**: Every operation in the sensitive-action acceptance set pauses before its
  effect; zero untrusted client approvals execute an effect.
- **SC-005**: With a ready daemon and paired idle extension, the median time from MCP
  tool receipt to the extension receiving a no-op observation request is at most
  100 milliseconds on the reference machine. The 95th percentile is at most 250
  milliseconds across 1,000 sequential requests.
- **SC-006**: With a ready daemon, one extension, and four clients, 100 operations on
  four tabs complete without cross-session state leakage or per-tab order violation.
- **SC-007**: All public failure paths in the acceptance matrix return a stable code,
  class, failed boundary, and safe next action.
- **SC-008**: Automated secret-seeding tests place tokens, cookies, credentials, and
  marked sensitive values at every logging and artifact boundary. Zero seeded values
  appear in persisted logs, diagnostics, screenshots, or exported bundles.
- **SC-009**: The reference authenticated browser journey completes in a visible tab,
  displays operation indicators, handles one approval, and leaves the adopted tab open.
- **SC-010**: A clean upgrade from the prior supported state version preserves all
  retained request outcomes, pending attention, artifact tombstones, and pairings.

## Assumptions

- The user controls the local account, browser profile, extension installation, and
  MCP client configuration.
- The extension runtime selected and installed by the user is trusted to report its
  Chrome-provided self metadata faithfully.
- The supported browser permits the Matinee extension to inspect and act on tabs the
  user explicitly grants.
- Websites can change between observation and action; document generation and target
  validation detect this condition rather than promising site stability.
- Matinee does not bypass website authentication, authorization, anti-automation
  controls, or legal restrictions.
- Network availability to the target website is outside Matinee's control. Matinee
  remains responsible for classifying and reporting resulting failures.
- The performance reference machine and browser build are recorded with benchmark
  results before a public latency claim is made.

## Explicit Non-Goals

- Hosted Matinee infrastructure or a remote control plane.
- Executing browser work on another machine.
- Headless browser execution in the first complete release.
- Firefox, Safari, or mobile browser support in the first complete release.
- Cron schedules, unattended recurring jobs, or a general workflow-definition language.
- A stable public Rust embedding API.
- Silent submission of credentials, payments, destructive actions, permissions, or
  legal acceptance.
- Compatibility with arbitrary extensions or every browser profile arrangement.
- Replacing website-specific authorization or abuse controls.
- Defending against a browser or installed extension runtime already replaced by an
  attacker with the user's local-account authority.
