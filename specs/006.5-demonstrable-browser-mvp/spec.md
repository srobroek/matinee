# Feature Specification: Demonstrable Multi-Tab Browser MVP

**Feature Branch**: `omp/agent/matinee-3bn`

**Created**: 2026-09-20

**Status**: Ready

**Input**: Prove Matinee's product loop through one MCP client, one paired Chrome or Chromium profile, one daemon, and at least two independently controlled visible tabs before implementing post-MVP hardening.

## Purpose and MVP Boundary

This specification is an integration and acceptance slice across the module seams owned by Specs 007-012. It permits narrow implementations needed for one deterministic demonstration.

The MVP is not a release candidate and does not automate arbitrary websites. It operates only against the deterministic local fixture and rejects origins or operations outside that fixture contract. This restriction defers attention policy without permitting unreviewed external effects.

### Why This MVP Keeps No Durable State

Navigation, tab creation, clicks, and typing cross an external effect boundary. A
browser or website may apply the effect before the daemon learns the result, so a
blind retry can activate a control twice.

A durable pre-dispatch journal is the general answer, and Spec 007 owns it. This
MVP does not carry one, because `FR-018` confines every operation to the
deterministic local fixture, where repeating an action is inconsequential and
visible on screen. The MVP therefore makes no crash-safety claim.

Instead the daemon reports only what it observed. It never claims an outcome it
did not observe, never retries an operation whose result it lost, and stamps every
response with its process instance identity so a client detects a restart rather
than silently continuing against an empty daemon. `adr-10` records this scope
limit and its Constitution III exception.

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
6. **Given** the configured MCP principal, **When** its adapter starts over stdio, **Then** it ensures one daemon is running and authenticates without holding state itself.
7. **Given** an unknown, revoked, replayed, downgraded, or wrong-state peer, **When** it attempts any channel, **Then** authentication fails before product mutation.
8. **Given** a second MCP principal or browser profile, **When** it attempts to join the MVP, **Then** the daemon returns a stable unsupported-MVP result without revealing existing identities.

---

### User Story 2 - Control Multiple Visible Tabs Independently (Priority: P1)

One MCP client opens or adopts at least two visible tabs in the paired profile and controls each tab through its own session and opaque handle.

**Why this priority**: Independent multi-tab control proves that Matinee routes operations by explicit ownership rather than ambient browser focus.

**Independent Test**: Open fixture tabs A and B. Move user focus to an unrelated tab while A and B receive overlapping operations. Type distinct values, activate distinct controls, and observe both documents while focus stays away. Capture each screenshot, which activates its owned tab for the capture and then restores the previously active tab. Each result must remain attached to its selected session and tab.

**Acceptance Scenarios**:

1. **Given** the paired extension and deterministic fixture, **When** `browser_list` runs, **Then** it returns an expiring candidate revision with opaque browser, profile, window, and tab references.
2. **Given** a current candidate revision, **When** `session_open` selects or creates two tabs, **Then** each visible tab receives a distinct session and non-repeating tab incarnation.
3. **Given** sessions A and B, **When** `page_navigate` sends each to a different fixture route, **Then** each operation affects only its selected tab.
4. **Given** user focus on an unrelated tab, **When** A and B receive overlapping operations, **Then** each tab preserves its own order and neither operation follows ambient focus.
5. **Given** current observations for both tabs, **When** `element_type` enters `alpha` in A and `beta` in B, **Then** `page_observe` returns the corresponding value only from each owning session.
6. **Given** one current button reference per tab, **When** `element_click` activates each, **Then** each fixture counter changes once without cross-tab effects.
7. **Given** click or type preflight, **When** the extension prepares the action, **Then** the visible indicator identifies the active tab, operation boundary, synthetic cursor, and target highlight before activation.
8. **Given** either session, **When** `page_screenshot` runs, **Then** it activates only its owned tab for the capture, restores the previously active tab, and returns a redacted `ArtifactSummary` with an authorized MCP resource URI; an equivalent retry returns the same artifact.
9. **Given** that resource URI, **When** the owning MCP principal reads it, **Then** the adapter reauthorizes the principal and streams at most 32 MiB.
10. **Given** unsafe or unverifiable screenshot masking, **When** capture runs, **Then** it fails closed without exposing an artifact identity or image bytes.
11. **Given** an element reference from A, **When** it is submitted to B or after A changes document generation, **Then** Matinee rejects it before dispatch.
12. **Given** the user changes or closes a controlled tab, **When** the next operation runs, **Then** Matinee rejects the stale incarnation or generation and never retargets another tab.

---

### User Story 3 - Never Claim an Unobserved Outcome (Priority: P1)

A user can lose the extension, the tab, or the whole daemon and still trust what
Matinee reported.

**Why this priority**: A visually successful demonstration is misleading if the
daemon reports success for an effect it never confirmed.

**Independent Test**: Stall the fixture, dispatch a click, then break the
boundary two ways. First disconnect the extension and confirm the operation ends
`failed` naming that boundary. Then kill the daemon, restart it, and confirm the
client's next call fails with `daemon.restarted` naming its last action sequence,
that the daemon holds zero sessions, and that the fixture counter advanced at most
once.

**Acceptance Scenarios**:

1. **Given** any mutating MCP tool, **When** the daemon confirms it, **Then** it records the Request identity, principal, mutation context, state, and ordered Operation in memory before the first browser effect.
2. **Given** either `session_open` selection variant with the canonical current candidate revision, **When** the daemon validates and prepares it, **Then** the daemon preallocates Request, Operation, and `opening` Session identities. The existing-tab descriptor receives the selected tab incarnation and generation. The new-tab descriptor receives the validated browser, profile, window, and revision with no tab incarnation or generation.
3. **Given** a dispatched Operation, **When** the daemon loses its outcome evidence through extension disconnect, target loss, or deadline expiry, **Then** the Operation terminates as `failed` naming that boundary, and the daemon neither reports success nor dispatches again.
4. **Given** a `failed` Operation whose outcome was never observed, **When** the client sends conflicting work for the same target, **Then** the daemon refuses it for the rest of the run while unrelated tabs continue.
5. **Given** a client holding a prior instance identity, **When** it calls any tool after a daemon restart, **Then** the call fails with `daemon.restarted`, names the client's last action sequence, states that its outcome is unobserved, and dispatches nothing.
6. **Given** an equivalent retry of a terminal Request in the same run, **When** the daemon resolves its idempotency key, **Then** it returns the original Request, Operation, and outcome without dispatch.
7. **Given** different content with an existing idempotency key, **When** the daemon compares the fingerprint, **Then** it returns a stable conflict and preserves the original record without dispatch.
8. **Given** a new-tab result, **When** the daemon binds it, **Then** the extension supplies a fresh non-repeating tab incarnation and initial document generation for the preallocated session.
9. **Given** a restarted daemon, **When** any client connects, **Then** it receives a new instance identity, zero sessions, and zero requests, and every browser tab from the previous run remains open.

---

### User Story 4 - Diagnose and Stop the MVP (Priority: P2)

A user can determine whether the MVP daemon, MCP adapter, and extension are usable, and can stop the daemon without disturbing browser tabs.

**Why this priority**: The demonstration needs a repeatable start, diagnosis, and cleanup path.

**Independent Test**: Run doctor before setup, after pairing, with the fixture unavailable, with the extension disconnected, and after daemon restart. Then stop the daemon and verify that it leaves every browser tab open and writes no state.

**Acceptance Scenarios**:

1. **Given** missing setup or pairing, **When** doctor runs, **Then** it reports the failed boundary and exact safe next action without mutating state.
2. **Given** ready MVP state, **When** doctor runs, **Then** daemon, MCP, extension, and fixture checks pass without sending a browser mutation.
3. **Given** a disconnected extension or unavailable fixture, **When** an MCP tool runs, **Then** it returns a bounded structured failure and does not queue hidden work.
4. **Given** an authenticated native principal, **When** it requests stop, **Then** the daemon enters draining through the dispatch-admission boundary, rejects new operations, disconnects the extension, leaves tabs open, and exits.
5. **Given** a stop request racing a dispatch, **When** both reach the admission boundary, **Then** exactly one proceeds and no operation dispatches after stop wins.
6. **Given** an unauthenticated or extension principal, **When** stop is requested, **Then** authorization fails before lifecycle state changes.

### Edge Cases

- Setup and the MCP adapter start concurrently while no daemon owns the state root.
- Setup ends between local identity creation and extension pairing commit.
- The extension service worker reconnects while its previous channel is closing.
- A candidate revision expires between `browser_list` and `session_open`.
- The user focuses another tab while an owned-tab operation is pending.
- A document navigates between observation and element action.
- The extension returns a result with the wrong session, operation, or document generation.
- The daemon exits before dispatch, after dispatch, or after the extension applied an effect it never reported.
- Tab A has an unobserved failed operation while tab B receives safe work.
- The fixture or extension disappears during screenshot capture.
- A client keeps calling with the instance identity of a daemon that already exited.

## Requirements *(mandatory)*

### Functional Requirements

#### MVP Shape and Communication

- **FR-001**: Before binding any endpoint, the MVP MUST obtain exclusive ownership for the selected state directory. One daemon MAY own it.
- **FR-002**: When setup and the MCP adapter race to start the daemon, one process MUST obtain ownership. Every loser MUST return `daemon.start_conflict` without mutating the state directory. Spec 007 later replaces this conflict with convergence on the winner.
- **FR-003**: The MVP MUST have one native administrator, exactly one MCP client principal, and one paired Chrome or Chromium extension principal.
- **FR-004**: The MVP MUST reject additional MCP principals and browser profiles through an indistinguishable unsupported-MVP result.
- **FR-005**: Initial setup before the first principal exists MUST use an inherited operating-system IPC channel with no independently discoverable listener.
- **FR-006**: The MCP client MUST communicate with its stateless adapter over stdio. The adapter MUST communicate with the daemon through the Spec 006 authenticated native channel.
- **FR-007**: The paired extension MUST communicate with the daemon through one authenticated loopback WebSocket using the Spec 006 secure-channel context.
- **FR-008**: The extension channel MUST route frames by daemon-assigned session and operation identities for at least two tabs. It MUST NOT support multiple MCP principals, profiles, or simultaneous channel generations.
- **FR-009**: Only setup and the MCP adapter MAY ensure that the daemon is running. The MVP MUST NOT add a public start command.
- **FR-010**: The MVP MAY use narrow module implementations, but every state transition MUST cross one daemon-owned transition interface, so Spec 007 can make that interface durable without changing callers.

#### Pairing and Authority

- **FR-011**: Bootstrap MUST create the native administrator through the verified Spec 006 inherited-IPC interface.
- **FR-012**: The native administrator MUST register the MVP MCP principal and issue extension enrollment through authenticated owner-controlled Spec 006 interfaces.
- **FR-013**: Pairing an unpacked extension MUST require the administrator's explicit interactive development allowance and MUST display the Spec 006 development-identity warning.
- **FR-014**: The extension MUST submit its invitation through `/v1/pair` on the configured loopback WebSocket origin. The daemon MUST atomically consume the invitation and register the extension key before the extension stores its private key.
- **FR-015**: Unknown, revoked, replayed, downgraded, wrong-origin, or wrong-state peers MUST fail before product mutation.
- **FR-016**: Private daemon, administrator, and MCP keys MUST remain in their platform credential stores. The extension private key MUST remain non-exportable in its Spec 006 extension-local WebCrypto storage. No private key may enter logs, diagnostics, screenshots, or MCP results.
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
- **FR-030**: `page_screenshot` MUST return one bounded redacted `ArtifactSummary` with a resource URI valid for the current daemon run. Capture MUST activate its owned tab, record that activation on the Operation, and restore the previously active tab before returning. The adapter MUST reauthorize each resource read against the owning MCP principal and stream at most 32 MiB. An equivalent retry within the run MUST return the same artifact. Failed masking MUST expose no artifact identity or bytes.

#### In-Run Effect Boundary

This MVP keeps no durable state and makes no crash-safety claim. `FR-018`
confines it to the deterministic local fixture, where repeating an action is
inconsequential. A real site requires the durable boundary that Spec 007 owns;
`adr-10` records that scope limit and its Constitution III exception.

- **FR-031**: Before confirming any mutating tool, the daemon MUST create a Request with stable identity, principal, mutation context, state, and ordered Operation list.
- **FR-032**: The daemon MUST hold all Request, Operation, Session, idempotency, and artifact state in memory for one daemon run. It MUST NOT write that state to a file, a database, or any other durable medium.
- **FR-033**: An existing-tab target descriptor MUST contain the session, tab incarnation, and expected document generation. A new-tab target descriptor MUST contain a preallocated session plus browser, profile, window, and candidate revision with no tab incarnation or generation.
- **FR-034**: The daemon MUST generate one instance identity at each process start, return it to every client on connect, and stamp it on every response.
- **FR-035**: The daemon MUST assign a monotonic action sequence per session and return it with every Operation. A sequence value MUST NOT repeat within a session.
- **FR-036**: A request carrying an instance identity other than the current one MUST fail with `daemon.restarted`. The failure MUST name the client's last known action sequence, MUST state that its outcome is unobserved, and MUST state that the daemon retains no state.
- **FR-037**: When the daemon loses the evidence needed to observe a dispatched Operation's outcome, including extension disconnect, target loss, or deadline expiry, that Operation MUST terminate as `failed` with a code naming the lost boundary. The daemon MUST NOT report success, and MUST NOT re-dispatch.
- **FR-038**: The daemon MUST NOT retry an Operation whose outcome it did not observe. Only an explicit new client request may act again.
- **FR-039**: An equivalent retry of a terminal Request within the same run MUST return its original identities and result without dispatch.
- **FR-040**: Reusing an idempotency key with a different Request fingerprint MUST return a stable conflict without changing the original record or dispatching.
- **FR-041**: A successful new-tab result MUST bind a fresh tab incarnation and initial document generation to the preallocated Session. If a `session_open` or `session_close` Operation terminates as `failed`, its Session MUST become `failed`, and Matinee MUST NOT retarget or automatically manipulate any tab that might have changed.
- **FR-042**: The daemon MUST authenticate each extension result and verify request, operation, session, tab incarnation, and document generation before accepting a terminal result.
- **FR-043**: The daemon MUST reject a mutating request that it cannot record in memory, and MUST NOT dispatch it.
- **FR-044**: A `failed` Operation whose outcome was never observed MUST block conflicting work on its target for the rest of the run. Unrelated tabs MAY continue.

#### Diagnosis, Stop, and Demonstration

- **FR-051**: Doctor MUST check setup, daemon reachability, MCP configuration, extension authentication, and fixture reachability without product mutation.
- **FR-052**: Public failures MUST include stable code, class, summary, failed boundary, retryability, assigned identifiers, and safe next actions with protected values redacted.
- **FR-053**: Any authenticated native principal MAY request stop. Extension and unauthenticated principals MUST be denied before lifecycle mutation, as recorded by `adr-7`.
- **FR-054**: Stop MUST enter `draining` through the same serialized admission boundary that permits a canonical Operation to move from `preflight` to `dispatching`, so a stop and a dispatch cannot both proceed. After entering `draining`, the daemon MUST reject new operations, abandon its in-memory state, disconnect the extension, leave every browser tab open, and exit.
- **FR-055**: The repository MUST provide one deterministic fixture with two independently observable tab routes, editable fields, increment controls, manually established authenticated state, and a crash-injection boundary after browser dispatch.
- **FR-056**: The implementation MUST provide `specs/006.5-demonstrable-browser-mvp/quickstart.md`. That procedure MUST state exact prerequisites, invocations, expected boundary results, restart steps, unknown-effect injection, and cleanup for the repeatable demonstration.
- **FR-057**: The procedure MUST use the real daemon process, stdio MCP adapter, authenticated native channel, loopback extension WebSocket, unpacked extension, visible browser tabs, and platform credential store. It MUST NOT replace a named boundary with an in-process fake.
- **FR-058**: The procedure MUST write a sanitized machine-readable report to `target/mvp-demo/evidence.json`. The report MUST include component versions, redacted identity fingerprints, the daemon instance identity, session and tab identities, and Request and Operation identities with canonical states and action sequences. It MUST also include screenshot artifact digests, resource-read results, and evidence that a lost boundary terminated an Operation as `failed`. It MUST contain no secrets, raw page text, or private browser data.

### Key Entities

- **MVP State Directory**: One initialized local authority holding the ownership lock and bindings to credential-store identities.
- **Native Administrator**: The bootstrap identity that registers the one MVP MCP principal and enrolls the one extension.
- **MCP Principal**: The one authenticated client identity authorized for MVP browser control.
- **Extension Principal**: The one paired Chrome or Chromium profile identity.
- **Browser Candidate**: An opaque revision-scoped browser, profile, window, or tab selection returned by `browser_list`.
- **Tab Incarnation**: A non-repeating opaque identity for one browser tab lifetime, distinct from a reusable browser tab number.
- **Browser Session**: In-run ownership of one selected or preallocated visible tab, its incarnation, and current document generation.
- **Request**: One confirmed MCP mutation with principal, canonical mutation context, state, and ordered Operation list.
- **Operation**: One browser command with stable identity, Request linkage, target descriptor, fingerprint, action sequence, and canonical state.
- **Daemon Instance**: One process-lifetime identity that every response carries, so a client detects a restart.
- **Artifact**: One bounded redacted screenshot with the canonical `ArtifactSummary` returned by `page_screenshot`.
- **MVP Fixture**: The deterministic local site used to prove authenticated-profile control and independent tabs.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A clean development checkout completes administrator bootstrap, MCP registration, explicit development-extension allowance, `/v1/pair` enrollment, MCP connection, and tool discovery through `specs/006.5-demonstrable-browser-mvp/quickstart.md`.
- **SC-002**: One MCP client controls at least two visible fixture tabs in one paired profile during the same daemon run.
- **SC-003**: While user focus remains on an unrelated third tab, tabs A and B retain distinct navigation, typed values, counters, generations, and histories across 100 overlapping alternating operations without cross-tab mutation.
- **SC-004**: Every stale, cross-session, wrong-incarnation, wrong-generation, unknown-principal, and wrong-origin fixture is rejected before browser dispatch.
- **SC-005**: In 100 concurrent starts, one process obtains exclusive state-directory ownership and every loser returns `daemon.start_conflict`.
- **SC-006**: Every request carrying a prior daemon instance identity fails with `daemon.restarted`, names the client's last action sequence, and dispatches zero browser commands.
- **SC-007**: At every point where the daemon loses outcome evidence for a dispatched Operation, including extension disconnect and deadline expiry, the Operation terminates as `failed` naming the lost boundary, the daemon reports no success, and it dispatches zero additional times.
- **SC-008**: Every equivalent retry within a run returns the original Request, Operation, and result. Every different fingerprint using the same idempotency key returns conflict without dispatch.
- **SC-009**: Action sequences increase monotonically per session and never repeat within a run.
- **SC-010**: An unobserved `failed` Operation in tab A prevents conflicting A work for the rest of the run, while 100 safe tab B observations and fixture operations complete without crossing ownership.
- **SC-011**: Every successful screenshot returns a redacted artifact whose digest matches its bytes, and an equivalent retry returns that artifact. Every failed or indeterminate masking case exposes zero artifact identities and bytes.
- **SC-012**: A killed daemon leaves no Matinee state file behind, every visible tab stays open, and a restarted daemon starts with zero sessions and zero requests.
- **SC-013**: Secret-seeding checks place marked values at every credential, channel, observation, screenshot, log, diagnostic, and storage boundary. Zero marked secrets appear outside their permitted owner.
- **SC-014**: A manually established fixture login remains browser-owned and both tabs stay controllable for the whole run; Matinee stores or returns zero fixture credentials or session cookies.
- **SC-015**: Doctor identifies every missing MVP prerequisite without creating state or dispatching a browser command.
- **SC-016**: At every race between stop admission and a `preflight` to `dispatching` transition, exactly one wins the shared boundary. Stop rejects new operations, and no operation dispatches after stop wins.
- **SC-017**: Authorized stop leaves every visible fixture tab open. Unauthorized stop changes no lifecycle state.
- **SC-018**: The demonstration produces `target/mvp-demo/evidence.json`, and schema validation confirms every FR-058 field while secret-seeding confirms zero prohibited values.
- **SC-019**: Every screenshot activates only its owned tab, records that activation, and restores the previously active tab. No other operation changes the active tab.

## Assumptions

- Specs 005 and 006 remain verified foundations and are reused rather than reimplemented.
- The demonstration uses one supported Chrome or Chromium release and an unpacked development extension.
- The fixture is local and deterministic. It contains no production credentials or consequential external actions. The user establishes its test login in the browser before Matinee control.
- The MVP tools retain their `matinee.tools.v1` meanings and mutation contexts. Any later specification that changes these boundaries MUST retain SC-006 through SC-012 and SC-016 as regression criteria.
- `adr-10` governs the in-memory scope limit and its Constitution III exception. `adr-9` governs the vertical-MVP sequencing. `adr-8` governs the later multi-principal and profile multiplexing model.
- Specs 007-012 replace narrow implementations with deeper modules and add the durable store that this MVP omits.

## Explicitly Deferred Work

- Multiple MCP principals, extension profiles, browser windows, and channel generations.
- Arbitrary website automation and human-attention policy.
- All durable state: the pre-dispatch journal, restart recovery, storage repair, and schema migration. Spec 007 owns them.
- Idle daemon shutdown and advanced lifecycle policy.
- State relocation, backup, downgrade, and release administration.
- Uploads, downloads, artifact retention beyond the current daemon run, audit export, and diagnostic bundles.
- Canceling requests, scheduling work, fairness policy, and workflows that reconcile unobserved effects.
- Packaged extension distribution and published installation workflows.
