# Acceptance Matrix

Each row names the proof that closes one requirement.
Test identifiers stay stable. Implementation assigns concrete paths.
Each proof must show the stated behavior and fail when that behavior changes.

| Requirement | Observable proof |
|---|---|
| FR-001 | `PKG-01`: install each platform artifact on a clean runner and execute `matinee version` without a source checkout |
| FR-002 | `CLI-01`: snapshot human and `matinee.cli.v1` JSON output for every required command |
| FR-003 | `JNY-01`: clean setup bootstraps the first native principal through inherited OS pipes, survives crashes before and after principal commit without orphaning it, pairs the selected Chrome package, and emits two independently usable MCP configurations |
| FR-004 | `CLI-02`: doctor fault matrix detects browser, extension, endpoint, storage, protocol, and permission faults without state mutation |
| FR-005 | `CLI-03`: status fixture exposes every declared summary and redacts seeded secrets |
| FR-006 | `CLI-04`: stop drains safe work, reports uncertain operations, and returns nonzero when safe shutdown fails |
| FR-007 | `RUN-01`: 20 simultaneous starts elect one daemon and every loser identifies the winner |
| FR-008 | `ARCH-01`: integration boundary test proves all durable mutations pass through the daemon and database actor |
| FR-009 | `MCP-01`: generated schemas validate every tool example and rejection fixture; adapter termination preserves a confirmed request and daemon process |
| FR-010 | `EXT-01`: extension journey proves discovery, ownership, observation, indicators, actions, and decisions |
| FR-011 | `ARCH-02`: CLI contract tests invoke daemon APIs and contain no alternate browser or store implementation |
| FR-012 | `PKG-02`: release package exports no supported library API and documentation declares CLI/MCP contracts only |
| FR-013 | `SEC-01`: bind matrix rejects IPv4 and IPv6 non-loopback addresses |
| FR-014 | `SEC-02`: two MCP configurations select independent signing principals; swapped, missing, revoked, and administrator principal selectors fail before MCP initialization; rotation closes the prior epoch |
| FR-015 | `SEC-03`: malicious-listener, observer, relay, replay, wrong-direction, malformed, wrong-origin, expired, revoked, downgrade, cross-version replay, and first-frame substitution matrices reveal no product payload and obtain no state access |
| FR-016 | `CON-01`: the fixed `matinee.secure-channel.v1` context signs one application-contract selection; intersection succeeds while disjoint ranges, downgraded selection, cross-version replay, and substituted first frames fail before mutation |
| FR-017 | `SEC-04`: two MCP principals, one extension principal, and one administrator probe every route, tool, resource, event stream, status view, object type, capability ceiling, extension grant, and administrator-only action; unauthorized probes return indistinguishable `object.not_found` or `authorization.denied` without data |
| FR-018 | `EXT-02`: declared Chrome and Chromium versions pass; unsupported engines return `compatibility` failures |
| FR-019 | `SEC-05`: profile fixture proves operation through existing authentication while filesystem and API probes detect no browser credential-store reads; daemon storage contains principal public keys but no private client keys |
| FR-020 | `OWN-01`: zero, one, and multiple-candidate fixtures prove stable explicit adoption; a selected-browser fixture creates one visible Matinee-owned tab |
| FR-021 | `SES-01`: concurrent ownership race produces one mutating owner and a structured conflict for the loser |
| FR-022 | `SES-02`: extension and daemon restart rebind the same session identifier and tab |
| FR-023 | `UI-01`: real-browser evidence shows tab indicator, cursor, and pre-activation target highlight |
| FR-024 | `UI-02`: session release removes all Matinee indicators from the adopted tab |
| FR-025 | `SES-03`: closing adopted and Matinee-created sessions applies their distinct tab-close defaults |
| FR-026 | `OBS-01`: bounded observation fixtures verify generation, stable references, truncation reason, and limits |
| FR-027 | `OBS-02`: navigation invalidates every prior reference before an extension action is sent |
| FR-028 | `OPS-01`: one browser journey exercises every operation kind; upload requires trusted user file selection and returns no local path or bytes to MCP |
| FR-029 | `OPS-02`: schema and preflight tests reject missing required context; client and extension attempts to lower the daemon-assigned effect class fail closed |
| FR-030 | `CONC-01`: four-tab run permits cross-tab concurrency and detects no per-tab reorder |
| FR-031 | `IDEM-01`: equivalent duplicate keys return one result; conflicting bodies return a conflict without a second effect |
| FR-032 | `RETRY-01`: transient matrix retries only independently classified safe operations within recorded limits; sensitive, uncertain, and persisted-capture effects never auto-retry |
| FR-033 | `REQ-01`: crash after request acknowledgment always recovers its stable request and operation identifiers |
| FR-034 | `REQ-02`: transition mutation tests cannot produce zero or two terminal outcomes |
| FR-035 | `ATT-01`: credential, payment, deletion, legal, permission, local-file disclosure, and uncertain-effect fixtures cannot dispatch before trusted attention |
| FR-036 | `ATT-02`: attention schema fixture contains exact operation, reason, redacted summaries, decisions, times, and surface |
| FR-037 | `ATT-03`: approve, deny, edit, and cancel paths execute only exact-scope approval once |
| FR-038 | `ATT-04`: every MCP self-approval shape fails while the paired extension decision succeeds |
| FR-039 | `ATT-05`: timeout atomically expires attention, operation, and request; disconnect, restart, and reconnect preserve non-approved state; revoked principals cannot decide later |
| FR-040 | `CAN-01`: repeated cancellation records one intent and reconciles in-flight boundaries |
| FR-041 | `CRASH-01`: process termination after every acknowledgment recovers the acknowledged transition |
| FR-042 | `REC-01`: mutation attempts during startup recovery fail with not-ready until the committed report exists |
| FR-043 | `REC-02`: interrupted-operation matrix classifies retry, completed, failed, and reconcile without uncertain replay |
| FR-044 | `RET-01`: default and configured history retention expire records at declared boundaries |
| FR-045 | `ART-01`: screenshots exist only for explicit request or declared diagnostic reason, equivalent duplicate keys return one artifact, and default retention is seven days |
| FR-046 | `ART-02`: artifact schema and persisted fixtures contain every metadata field and a matching digest |
| FR-047 | `ART-03`: cleanup removes bytes and preserves a request-linked tombstone |
| FR-048 | `ART-04`: concurrent startup and crash matrix leaves no available missing file or orphaned committed file |
| FR-049 | `CFG-01`: full precedence matrix records the winning value and source for each layer |
| FR-050 | `CFG-02`: every project-level attempt to weaken a security floor is rejected |
| FR-051 | `CFG-03`: status displays resolved non-secret values and sources while redacting credentials |
| FR-052 | `ERR-01`: failure corpus maps each injected fault to exactly one declared primary class |
| FR-053 | `ERR-02`: schema assertion requires code, class, summary, boundary, retryability, identifiers, and safe actions |
| FR-054 | `RED-01`: seeded tokens, cookies, headers, credentials, values, and page text appear in zero persisted or exported bytes |
| FR-055 | `OBS-03`: authenticated diagnostics fixture exposes every metric with bounded labels and rejects unauthenticated access |
| FR-056 | `CON-02`: schema inventory fails when a public surface lacks an explicit compatibility version |
| FR-057 | `CON-03`: incompatible-peer tests reject removed contracts; release notes enumerate each contract change |
| FR-058 | `MIG-01`: supported old state migrates transactionally; injected failure restores backup; unsupported downgrade fails |
| FR-059 | `PKG-03`: release verifies signed platform artifacts and checksums; store pairing accepts exact normal-install metadata; ordinary unpacked builds require a distinct ID and explicit allowance; a hostile same-ID runtime is recorded as an installed-runtime trust-boundary case |
| FR-060 | `PKG-04`: uninstall retains or deletes data exactly according to the required explicit choice |

## Success Criteria Proof

| Criterion | Observable proof |
|---|---|
| SC-001 | Time five clean-user quickstart runs; each completes in 10 minutes or less |
| SC-002 | Run 100 boundary crash cases; assert one terminal outcome and zero replayed completed effects |
| SC-003 | Run 100 adapter disconnects; assert each request remains discoverable and daemon-ready |
| SC-004 | Run the full sensitive-action set; assert every effect pauses and zero client assertions approve |
| SC-005 | Record reference hardware and browser; benchmark 1,000 warm requests at median ≤100 ms and p95 ≤250 ms |
| SC-006 | Complete 100 operations across four tabs without leakage or order violation |
| SC-007 | Validate every failure fixture against the required diagnostic fields |
| SC-008 | Scan all persisted and exported bytes after secret seeding; find zero seeded values |
| SC-009 | Record real-browser journey evidence for indicators, approval, completion, and adopted-tab preservation |
| SC-010 | Migrate the prior supported state fixture and compare outcomes, attention, tombstones, and pairings |
