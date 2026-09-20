# Feature Specification: Demonstrable Multi-Tab Browser MVP

**Feature Branch**: `omp/agent/matinee-3bn`

**Created**: 2026-09-20

**Status**: Ready

**Input**: Prove Matinee's product loop through one MCP client, one paired Chrome or Chromium profile, one daemon, and at least two independently controlled visible tabs before implementing post-MVP hardening.

## Purpose and MVP Boundary

This specification is an integration and acceptance slice across the module seams owned by Specs 007-012. It permits narrow implementations needed for one deterministic demonstration.

The MVP is not a release candidate and does not automate arbitrary websites. It operates only against the deterministic local fixture and rejects origins or operations outside that fixture contract. This restriction defers attention policy without permitting unreviewed external effects.

### Why Pre-Dispatch Durability Is Required

Navigation, tab creation, clicks, and typing cross an external effect boundary. A browser or website may apply the effect before the daemon receives or persists the result. Repeating the operation after a timeout or crash can submit a form twice, activate a control twice, or replace browser state the user already saw.

Before dispatching an effectful operation, the daemon therefore commits its operation identity, idempotency key, target session, expected document generation, and `prepared` state. It then commits `dispatched` before sending the command to the extension. If the daemon loses authoritative result evidence after dispatch, the operation becomes `unknown`. Matinee reserves that identity, returns `reconciliation_required`, and never dispatches it automatically again.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Pair One Browser and Connect One MCP Client (Priority: P1)

A user starts from a clean development checkout, pairs one unpacked extension with one Matinee state directory, and connects one MCP client to the resulting daemon.

**Why this priority**: Browser control requires authenticated daemon, extension, and MCP identities bound to one state directory.

**Independent Test**: Bootstrap the native administrator through inherited operating-system IPC. Use that administrator to register one MCP principal and issue one extension enrollment. Pair the unpacked extension on `/v1/pair`, then start the MCP adapter and list the MVP tools.

**Acceptance Scenarios**:

1. **Given** no initialized state or principal, **When** trusted setup starts, **Then** it creates the native administrator through inherited operating-system IPC and exposes no loopback bootstrap listener.
2. **Given** the native administrator, **When** it registers the MVP MCP principal and issues an extension enrollment, **Then** both operations use the authenticated native channel and owner-controlled Spec 006 interfaces.
3. **Given** an unpacked extension identity, **When** the administrator explicitly allows development pairing, **Then** the user sees a persistent development warning before the invitation is issued.
4. **Given** the invitation, **When** the extension submits it to `/v1/pair` from the configured development origin, **Then** the daemon atomically consumes the invitation and registers the extension key before the extension stores its private key.
5. **Given** a paired extension, **When** it opens the loopback WebSocket, **Then** both peers authenticate the fixed secure-channel context before accepting application frames.
6. **Given** the configured MCP principal, **When** its adapter starts over stdio, **Then** it ensures one daemon is running and authenticates without writing durable state itself.
7. **Given** an unknown, revoked, replayed, downgraded, or wrong-state peer, **When** it attempts any channel, **Then** authentication fails before product mutation.
8. **Given** a second MCP principal or browser profile, **When** it attempts to join the MVP, **Then** the daemon returns a stable unsupported-MVP result without revealing existing identities.

---

### User Story 2 - Control Multiple Visible Tabs Independently (Priority: P1)

One MCP client opens or adopts at least two visible tabs in the paired profile and controls each tab through its own durable session and opaque handle.

**Why this priority**: Independent multi-tab control proves that Matinee routes operations by explicit ownership rather than ambient browser focus.

**Independent Test**: Open fixture tabs A and B. Move user focus to an unrelated tab while A and B receive overlapping operations. Type distinct values, activate distinct controls, observe both documents, and capture both screenshots. Each result must remain attached to its selected session and tab.

**Acceptance Scenarios**:

1. **Given** the paired extension and deterministic fixture, **When** `browser_list` runs, **Then** it returns an expiring candidate revision with opaque browser, profile, window, and tab references.
2. **Given** a current candidate revision, **When** `session_open` selects or creates two tabs, **Then** each visible tab receives a distinct durable session and non-repeating tab incarnation.
3. **Given** sessions A and B, **When** `page_navigate` sends each to a different fixture route, **Then** each operation affects only its selected tab.
4. **Given** user focus on an unrelated tab, **When** A and B receive overlapping operations, **Then** each tab preserves its own order and neither operation follows ambient focus.
5. **Given** current observations for both tabs, **When** `element_type` enters `alpha` in A and `beta` in B, **Then** `page_observe` returns the corresponding value only from each owning session.
6. **Given** one current button reference per tab, **When** `element_click` activates each, **Then** each fixture counter changes once without cross-tab effects.
7. **Given** click or type preflight, **When** the extension prepares the action, **Then** the visible indicator identifies the active tab, operation boundary, synthetic cursor, and target highlight before activation.
8. **Given** either session, **When** `page_screenshot` runs, **Then** it returns a persisted redacted `ArtifactSummary` with an authorized MCP resource URI; an equivalent retry returns the same artifact.
9. **Given** that resource URI, **When** the owning MCP principal reads it, **Then** the adapter reauthorizes the principal and streams at most 32 MiB.
10. **Given** unsafe or unverifiable screenshot masking, **When** capture runs, **Then** it fails closed without persisting an artifact or returning image bytes.
11. **Given** an element reference from A, **When** it is submitted to B or after A changes document generation, **Then** Matinee rejects it before dispatch.
12. **Given** the user changes or closes a controlled tab, **When** the next operation runs, **Then** Matinee rejects the stale incarnation or generation and never retargets another tab.

---

### User Story 3 - Survive Restart Without Replaying an Unknown Effect (Priority: P1)

A user can restart the daemon after confirmed work and can observe an uncertain operation without Matinee repeating it.

**Why this priority**: A visually successful demonstration is unsafe if restart can duplicate an external action.

**Independent Test**: Commit normal requests, restart the daemon, and recover both session records. Inject a crash before dispatch, then inject one after a fixture click is dispatched but before its result commits. Verify safe rejection of the prepared-only operation. Verify that the clicked counter changes once while the dispatched operation returns `reconciliation_required` and never dispatches again.

**Acceptance Scenarios**:

1. **Given** any mutating MCP tool, **When** the daemon confirms it, **Then** a durable Request records its identity, principal, mutation context, state, and ordered Operation before the first browser effect.
2. **Given** either `session_open` selection variant with the canonical current candidate revision, **When** the daemon validates and prepares it, **Then** the daemon preallocates Request, Operation, and `opening` Session identities. The existing-tab descriptor receives the selected tab incarnation and generation. The new-tab descriptor receives the validated browser, profile, window, and revision with no tab incarnation or generation.
3. **Given** a committed private `prepared` dispatch phase, **When** dispatch is authorized, **Then** the Operation enters canonical `dispatching`. The private `dispatched` phase crosses the persistence barrier before the extension receives the command.
4. **Given** a crash before the private `dispatched` phase, **When** the daemon restarts, **Then** the Operation becomes `cancelled` and its Request fails with `daemon.stopped_before_dispatch`. Any preallocated `session_open` Session becomes `failed`, and the daemon never dispatches the Operation automatically.
5. **Given** loss of authoritative terminal evidence after the private `dispatched` phase, **When** the daemon detects a crash, disconnect, closed target, or `operation.uncertain`, **Then** the Operation becomes `uncertain` and its Request enters `reconciliation_required`. For `session_open` or `session_close`, the Session becomes `failed` and remains quarantined.
6. **Given** an equivalent retry of a terminal or reconciliation-required Request, **When** the daemon resolves its idempotency key, **Then** it returns the original Request, Operation, and outcome without dispatch.
7. **Given** different content with an existing idempotency key, **When** the daemon compares the fingerprint, **Then** it returns a stable conflict and preserves the original record without dispatch.
8. **Given** a new-tab result, **When** the daemon binds it, **Then** the extension supplies a fresh non-repeating tab incarnation and initial document generation for the preallocated session.
9. **Given** two confirmed sessions and terminal requests, **When** the daemon restarts, **Then** the MCP client can recover both request and session records and reconnect to the paired extension.
10. **Given** an Operation in canonical `uncertain` state for tab A, **When** the client operates tab B, **Then** unrelated tab B work can continue while A's Unknown Reservation remains.

---

### User Story 4 - Diagnose and Stop the MVP (Priority: P2)

A user can determine whether the MVP daemon, store, MCP adapter, and extension are usable and can stop the daemon without discarding durable records.

**Why this priority**: The demonstration needs a repeatable start, diagnosis, and cleanup path.

**Independent Test**: Run doctor before setup, after pairing, with the fixture unavailable, with the extension disconnected, and after daemon restart. After all effects are terminal, stop the daemon and verify that it leaves browser tabs open. Also verify that an uncertain in-flight effect blocks clean stop.

**Acceptance Scenarios**:

1. **Given** missing setup or pairing, **When** doctor runs, **Then** it reports the failed boundary and exact safe next action without mutating state.
2. **Given** ready MVP state, **When** doctor runs, **Then** daemon, store, MCP, extension, and fixture checks pass without sending a browser mutation.
3. **Given** a disconnected extension or unavailable fixture, **When** an MCP tool runs, **Then** it returns a bounded structured failure and does not queue hidden work.
4. **Given** every dispatched effect has a terminal result, **When** an authenticated native principal requests stop, **Then** the daemon enters draining through the dispatch-admission boundary. It rejects prepared work without dispatch, disconnects the extension, leaves tabs open, and exits cleanly.
5. **Given** an unknown effect, **When** an authenticated native principal requests stop or session release, **Then** the request returns a stable blocked or reconciliation-required result. The daemon remains running and retains target quarantine.
6. **Given** an unauthenticated or extension principal, **When** stop is requested, **Then** authorization fails before lifecycle state changes.

### Edge Cases

- Setup and the MCP adapter start concurrently while no daemon owns the state root.
- Setup ends between local identity creation and extension pairing commit.
- The extension service worker reconnects while its previous channel is closing.
- A candidate revision expires between `browser_list` and `session_open`.
- The user focuses another tab while an owned-tab operation is pending.
- A document navigates between observation and element action.
- The extension returns a result with the wrong session, operation, or document generation.
- The daemon exits before dispatch, after dispatch, or after receiving the result but before durable terminal commit.
- Tab A has an unknown operation while tab B receives safe work.
- The fixture or extension disappears during screenshot capture.
- Durable storage becomes unavailable before pre-dispatch commit.

## Requirements *(mandatory)*

### Functional Requirements

#### MVP Shape and Communication

- **FR-001**: Before opening the store or endpoint, the MVP MUST obtain exclusive ownership for the selected state directory. One daemon MAY own it.
- **FR-002**: When setup and the MCP adapter race to start the daemon, one process MUST obtain ownership. Every loser MUST return `daemon.start_conflict` without store mutation. Spec 007 later replaces this conflict with convergence on the winner.
- **FR-003**: The MVP MUST have one native administrator, exactly one MCP client principal, and one paired Chrome or Chromium extension principal.
- **FR-004**: The MVP MUST reject additional MCP principals and browser profiles through an indistinguishable unsupported-MVP result.
- **FR-005**: Initial setup before the first principal exists MUST use an inherited operating-system IPC channel with no independently discoverable listener.
- **FR-006**: The MCP client MUST communicate with its stateless adapter over stdio. The adapter MUST communicate with the daemon through the Spec 006 authenticated native channel.
- **FR-007**: The paired extension MUST communicate with the daemon through one authenticated loopback WebSocket using the Spec 006 secure-channel context.
- **FR-008**: The extension channel MUST route frames by daemon-assigned session and operation identities for at least two tabs. It MUST NOT support multiple MCP principals, profiles, or simultaneous channel generations.
- **FR-009**: Only setup and the MCP adapter MAY ensure that the daemon is running. The MVP MUST NOT add a public start command.
- **FR-010**: The MVP MAY use narrow module implementations, but all durable state mutation MUST cross one daemon-owned durable-transition interface.

#### Pairing and Authority

- **FR-011**: Bootstrap MUST create the native administrator through the verified Spec 006 inherited-IPC interface.
- **FR-012**: The native administrator MUST register the MVP MCP principal and issue extension enrollment through authenticated owner-controlled Spec 006 interfaces.
- **FR-013**: Pairing an unpacked extension MUST require the administrator's explicit interactive development allowance and MUST display the Spec 006 development-identity warning.
- **FR-014**: The extension MUST submit its invitation through `/v1/pair` on the configured loopback WebSocket origin. The daemon MUST atomically consume the invitation and register the extension key before the extension stores its private key.
- **FR-015**: Unknown, revoked, replayed, downgraded, wrong-origin, or wrong-state peers MUST fail before product mutation.
- **FR-016**: Private daemon, administrator, and MCP keys MUST remain in their platform credential stores. The extension private key MUST remain non-exportable in its Spec 006 extension-local WebCrypto storage. No private key may enter the product store, logs, diagnostics, screenshots, or MCP results.
- **FR-017**: The daemon MUST derive principal, request, session, operation, and tab ownership from authenticated records. Clients MUST NOT submit authoritative ownership fields.

#### Browser and Tab Control

- **FR-018**: The MVP MUST control only Chrome or Chromium tabs in the paired profile and only against the configured deterministic fixture origin.
- **FR-019**: `browser_list` MUST return opaque candidates with a revision and expiry. The daemon MUST reject omitted, expired, or stale selection.
- **FR-020**: `session_open` MUST explicitly select one candidate or create one visible fixture tab. Both variants MUST supply the canonical current candidate revision and preallocate a Session in `opening` before dispatch. The daemon MUST validate that revision and selection before preparing the Operation.
- **FR-021**: The MVP MUST support at least two simultaneously controlled visible tabs with independent session ownership and per-tab operation ordering.
- **FR-022**: The MVP MCP surface MUST expose `browser_list`, `session_open`, `session_get`, `session_close`, `page_observe`, `page_navigate`, `element_click`, `element_type`, `page_screenshot`, and `request_get` with their `matinee.tools.v1` meanings.
- **FR-023**: `page_observe` MUST return a bounded semantic snapshot, current document generation, and generation-scoped element references. It MUST exclude password values, cookies, storage, authorization headers, and secret-marked values.
- **FR-024**: Every mutating tool MUST accept the canonical mutation context: `idempotency_key`, `deadline_ms`, and `effect_hint`. Page and element mutations MUST also require the owning session and expected document generation. `session_close` retains its canonical session-only target.
- **FR-025**: An element operation MUST require a current reference issued for the same session, tab incarnation, and document generation.
- **FR-026**: For an existing tab, the extension MUST verify session, operation, tab incarnation, and document generation. For new-tab creation, the extension MUST verify the daemon-authenticated target descriptor containing the preallocated session and validated browser, profile, window, and candidate revision.
- **FR-027**: The extension MUST assign each created or adopted tab a non-repeating opaque incarnation. A document generation MUST never repeat within that incarnation.
- **FR-028**: During click and type, the extension MUST show the owning indicator, current operation boundary, synthetic cursor, and pre-activation target highlight.
- **FR-029**: User closure, navigation, or ownership change MUST invalidate stale control state and MUST NOT cause implicit retargeting.
- **FR-030**: `page_screenshot` MUST persist one bounded redacted artifact and return its canonical `ArtifactSummary` with a resource URI. The adapter MUST reauthorize each resource read against the owning MCP principal and stream at most 32 MiB. Image bytes and their digest MUST cross the persistence barrier before metadata becomes `available`. An equivalent retry MUST return the same artifact. Failed masking or incomplete persistence MUST expose no artifact identity or bytes. Orphaned unavailable bytes MAY be removed after restart.

#### Durable Effect Boundary

- **FR-031**: Before confirming any mutating tool, the daemon MUST durably commit a Request with stable identity, principal, mutation context, state, and ordered Operation list.
- **FR-032**: Before browser dispatch, each effectful Operation in canonical `preflight` MUST commit a private Dispatch Record in phase `prepared`. The record MUST contain its Request identity, Operation identity, fingerprint, and target descriptor.
- **FR-033**: An existing-tab target descriptor MUST contain the session, tab incarnation, and expected document generation. A new-tab target descriptor MUST contain a preallocated session plus browser, profile, window, and candidate revision with no tab incarnation or generation.
- **FR-034**: A durable commit acknowledged by this MVP MUST survive daemon termination, operating-system crash, and power-loss recovery on supported local storage. The daemon MUST NOT advance a canonical Operation state or private Dispatch Record phase until the required persistence barrier succeeds.
- **FR-035**: Before sending an effectful command to the extension, the daemon MUST atomically persist `effect_started_at`, move the canonical Operation to `dispatching`, and move its private Dispatch Record to `dispatched`.
- **FR-036**: Whenever recovery or stop terminates an effectful Operation that has no Dispatch Record in phase `dispatched`, the daemon MUST atomically move that Operation to `cancelled` and fail its owning Request with `daemon.stopped_before_dispatch`. This includes an Operation with no Dispatch Record at all. For either `session_open` variant, the same transaction MUST move its preallocated Session from `opening` to `failed`. Equivalent retry MUST return that failure without dispatch.
- **FR-037**: After the private `dispatched` phase, loss of authoritative terminal evidence MUST move the canonical Operation to `uncertain` and its Request to `reconciliation_required`. This includes process exit, extension disconnect, target loss, and `operation.uncertain`.
- **FR-038**: The daemon MUST persist an Unknown Reservation for each such `uncertain` Operation. It MUST reserve the Request, Operation, and idempotency identities and MUST NOT dispatch automatically.
- **FR-039**: An equivalent retry of a terminal or reconciliation-required Request MUST return its original identities and result without dispatch.
- **FR-040**: Reusing an idempotency key with a different Request fingerprint MUST return a stable conflict without changing the original record or dispatching.
- **FR-041**: A successful new-tab result MUST bind a fresh tab incarnation and initial document generation to the preallocated Session. If any `session_open` or `session_close` Operation becomes `uncertain`, the same transaction MUST move its Session to `failed` and its Request to `reconciliation_required`. The Unknown Reservation and target quarantine MUST remain, and Matinee MUST NOT retarget or automatically manipulate any tab that might have changed.
- **FR-042**: The daemon MUST authenticate each extension result and verify request, operation, session, tab incarnation, and document generation before committing a terminal result.
- **FR-043**: Storage failure before any required persistence barrier MUST prevent browser dispatch.
- **FR-044**: An Unknown Reservation MUST quarantine its owning target against conflicting work and ownership release. `session_close` MUST return `reconciliation_required` while quarantine remains. Unrelated tabs MAY continue.

#### Minimal Persistence and Restart

- **FR-045**: The MVP durable store MUST use one version-1 schema. It MUST reject any other version without migration or mutation.
- **FR-046**: The store MUST contain only state identity, public principal and pairing records, Requests, Operations, Dispatch Records, idempotency records, session/tab ownership, terminal results, Unknown Reservations, MVP screenshot artifacts, and the last daemon exit.
- **FR-047**: The store MUST NOT contain browser cookies, browser storage, authentication headers, private keys, password values, or unredacted screenshots.
- **FR-048**: Restart MUST restore pairing, Requests, Operations, Dispatch Records, session/tab ownership, terminal results, artifacts, and Unknown Reservations before accepting new operations.
- **FR-049**: Restart MUST NOT replay an Operation represented by a private `prepared` or `dispatched` phase or by an Unknown Reservation.
- **FR-050**: When durable storage becomes unavailable or corrupt, the MVP MUST enter `failed`, block new browser dispatch, and return a safe restart action. Only a new daemon process MAY retry storage access.

#### Diagnosis, Stop, and Demonstration

- **FR-051**: Doctor MUST check setup, state-store version and accessibility, daemon reachability, MCP configuration, extension authentication, and fixture reachability without product mutation.
- **FR-052**: Public failures MUST include stable code, class, summary, failed boundary, retryability, assigned identifiers, and safe next actions with protected values redacted.
- **FR-053**: Any authenticated native principal MAY request stop. Extension and unauthenticated principals MUST be denied before lifecycle mutation, as recorded by `adr-7`.
- **FR-054**: Stop MUST enter `draining` through the same serialized admission boundary that permits a canonical Operation to move from `preflight` to `dispatching`. After entering `draining`, the daemon MUST reject new operations. It MUST terminate every Operation with no Dispatch Record in phase `dispatched`, including Operations in `planned`, `queued`, `preflight`, or `awaiting_attention`, under the FR-036 cancellation and Session projection. If any Operation is or becomes `uncertain`, stop MUST return `daemon.stop_blocked`, remain `draining`, retain target quarantine, and MUST NOT commit a clean exit. Otherwise, stop MUST wait for every `dispatching` Operation to reach a terminal result. It MUST then disconnect the extension, leave tabs open, commit a clean exit, and stop. External forced termination records an unclean exit.
- **FR-055**: The repository MUST provide one deterministic fixture with two independently observable tab routes, editable fields, increment controls, manually established authenticated state, and a crash-injection boundary after browser dispatch.
- **FR-056**: The implementation MUST provide `specs/006.5-demonstrable-browser-mvp/quickstart.md`. That procedure MUST state exact prerequisites, invocations, expected boundary results, restart steps, unknown-effect injection, and cleanup for the repeatable demonstration.
- **FR-057**: The procedure MUST use the real daemon process, stdio MCP adapter, authenticated native channel, loopback extension WebSocket, unpacked extension, visible browser tabs, durable store, and platform credential store. It MUST NOT replace a named boundary with an in-process fake.
- **FR-058**: The procedure MUST write a sanitized machine-readable report to `target/mvp-demo/evidence.json`. The report MUST include component versions, redacted identity fingerprints, session and tab identities, and Request and Operation identities with canonical states. It MUST also include screenshot artifact digests, resource-read results, restart checkpoints, and evidence that an affected Request entered `reconciliation_required`. It MUST contain no secrets, raw page text, or private browser data.

### Key Entities

- **MVP State Directory**: One initialized local authority containing the version-1 store and bindings to credential-store identities.
- **Native Administrator**: The bootstrap identity that registers the one MVP MCP principal and enrolls the one extension.
- **MCP Principal**: The one authenticated client identity authorized for MVP browser control.
- **Extension Principal**: The one paired Chrome or Chromium profile identity.
- **Browser Candidate**: An opaque revision-scoped browser, profile, window, or tab selection returned by `browser_list`.
- **Tab Incarnation**: A non-repeating opaque identity for one browser tab lifetime, distinct from a reusable browser tab number.
- **Browser Session**: Durable ownership of one selected or preallocated visible tab, its incarnation, and current document generation.
- **Request**: One confirmed MCP mutation with principal, canonical mutation context, state, and ordered Operation list.
- **Operation**: One browser command with stable identity, Request linkage, target descriptor, fingerprint, and durable state.
- **Dispatch Record**: A private durable record for one effectful Operation with `prepared` and `dispatched` phases. It does not add public Request or Operation states.
- **Artifact**: One bounded redacted screenshot with the canonical `ArtifactSummary` returned by `page_screenshot`.
- **Unknown Reservation**: Durable quarantine for one canonical `uncertain` Operation. It reserves identities and forbids automatic replay without adding a public Operation state.
- **MVP Fixture**: The deterministic local site used to prove authenticated-profile control, independent tabs, and crash-safe effects.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A clean development checkout completes administrator bootstrap, MCP registration, explicit development-extension allowance, `/v1/pair` enrollment, MCP connection, and tool discovery through `specs/006.5-demonstrable-browser-mvp/quickstart.md`.
- **SC-002**: One MCP client controls at least two visible fixture tabs in one paired profile during the same daemon run.
- **SC-003**: While user focus remains on an unrelated third tab, tabs A and B retain distinct navigation, typed values, counters, generations, screenshots, and histories across 100 overlapping alternating operations without cross-tab mutation.
- **SC-004**: Every stale, cross-session, wrong-incarnation, wrong-generation, unknown-principal, and wrong-origin fixture is rejected before browser dispatch.
- **SC-005**: In 100 concurrent setup/MCP starts, one process obtains exclusive state ownership, every loser returns `daemon.start_conflict`, and no loser mutates the store.
- **SC-006**: At every crash point after the private `prepared` phase commits and before `dispatched` commits, recovery cancels the Operation and fails its Request with `daemon.stopped_before_dispatch`. For either `session_open` variant, it also moves the preallocated Session to `failed`. It dispatches zero browser commands.
- **SC-007**: At every loss point after the private `dispatched` phase commits and before a terminal result commits, the Operation becomes `uncertain` and its Request enters `reconciliation_required`. An affected `session_open` or `session_close` Session becomes `failed` and retains its Unknown Reservation. This includes live extension disconnect and daemon restart, and the daemon dispatches zero additional times.
- **SC-008**: Every equivalent retry returns the original Request, Operation, and result. Every different fingerprint using the same idempotency key returns conflict without dispatch.
- **SC-009**: After clean daemon restart, session records and all terminal or reconciliation-required Requests remain available with their canonical Operations and artifacts.
- **SC-010**: An Unknown Reservation in tab A prevents conflicting A work, ownership release, and clean stop. During that interval, 100 safe tab B observations and fixture operations complete without crossing ownership.
- **SC-011**: Every successful screenshot makes artifact metadata available only after matching image bytes and digest are durable, and equivalent retry returns that artifact. Crash injection at each file-and-metadata boundary exposes no missing, corrupt, or orphaned available artifact. Every failed or indeterminate masking case exposes zero artifact identities and bytes.
- **SC-012**: Forced daemon termination, operating-system crash simulation, and power-loss recovery preserve every acknowledged persistence barrier and never advance an uncommitted operation state.
- **SC-013**: Secret-seeding checks place marked values at every credential, channel, observation, screenshot, log, diagnostic, and storage boundary. Zero marked secrets appear outside their permitted owner.
- **SC-014**: A manually established fixture login remains browser-owned while both tabs remain controllable after daemon restart; Matinee stores or returns zero fixture credentials or session cookies.
- **SC-015**: Doctor identifies every missing MVP prerequisite without creating state or dispatching a browser command.
- **SC-016**: Stop cancels every `planned`, `queued`, `preflight`, or `awaiting_attention` Operation with no Dispatch Record in phase `dispatched`, fails each owning Request with `daemon.stopped_before_dispatch`, and moves every preallocated `session_open` Session to `failed`. At every race between stop admission and a `preflight` to `dispatching` transition, exactly one wins the shared boundary. If dispatch wins, stop observes the Operation and cannot exit before its terminal result.
- **SC-017**: Authorized stop leaves every visible fixture tab open and preserves terminal and reconciliation-required records. Unauthorized stop changes no lifecycle state.
- **SC-018**: The demonstration produces `target/mvp-demo/evidence.json`, and schema validation confirms every FR-058 field while secret-seeding confirms zero prohibited values.

## Assumptions

- Specs 005 and 006 remain verified foundations and are reused rather than reimplemented.
- The demonstration uses one supported Chrome or Chromium release and an unpacked development extension.
- The fixture is local and deterministic. It contains no production credentials or consequential external actions. The user establishes its test login in the browser before Matinee control.
- The MVP tools retain their `matinee.tools.v1` meanings and mutation contexts. Any later specification that changes these boundaries MUST retain SC-006 through SC-012 and SC-016 as regression criteria.
- `adr-9` governs the vertical-MVP sequencing. `adr-8` governs the later multi-principal and profile multiplexing model.
- Specs 007-012 replace narrow implementations with deeper modules without moving durable-store ownership outside the daemon.

## Explicitly Deferred Work

- Multiple MCP principals, extension profiles, browser windows, and channel generations.
- Arbitrary website automation and human-attention policy.
- Automatic storage repair or in-process recovery.
- Idle daemon shutdown and advanced lifecycle policy.
- State-schema migration beyond rejecting non-version-1 stores.
- State relocation, backup, downgrade, and release administration.
- Uploads, downloads, retention policy beyond the persisted MVP screenshot lifecycle, audit export, and diagnostic bundles.
- Canceling requests, scheduling work, fairness policy, and workflows that resolve uncertain effects.
- Packaged extension distribution and published installation workflows.
