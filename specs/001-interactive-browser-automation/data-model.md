# Domain Model: Interactive Local Browser Automation

## Terminology

| Term | Definition | Not This |
|---|---|---|
| Daemon | The single active process that owns one Matinee state directory | An MCP client subprocess |
| Principal | One registered MCP client or paired browser extension identity | An operating-system user account |
| Extension enrollment | One expiring, single-use authority to activate the expected extension package | A reusable extension credential |
| Connection | One transient authenticated channel from a principal to the daemon | A durable request or session |
| Browser target | A paired browser, profile reference, window, frame, or tab candidate | Copied browser profile data |
| Session | Durable exclusive mutating ownership of one tab | A WebSocket connection |
| Request | One durable client intent with one terminal outcome | A general workflow file |
| Operation | One ordered browser interaction within a request | An arbitrary background job |
| Effect boundary | The point after which an operation may have changed external state | Successful response receipt only |
| Attention request | A durable pause that requires a trusted user decision | A notification that implies consent |
| Approval | A single-use authorization for one exact operation digest | General permission for later actions |
| Artifact | Redacted evidence or diagnostic content with retention metadata | An automatic recording of every page |
| Audit event | An append-only lifecycle or security fact | Unredacted debug logging |
| Idempotency record | The canonical request digest and result associated with one client key | A retry counter |
| Reconciliation | Determining the outcome of an operation that crossed an uncertain effect boundary | Automatic retry |

## Entity Relationships

```text
Daemon Instance
├── authenticates Principal ──< Connection
├── owns Browser Session >── Browser Target
├── owns Request ──< Operation
│   ├── may create Attention Request ──0..1 Approval
│   ├── may produce Artifact
│   └── is indexed by Idempotency Record
└── appends Audit Event
```

A connection can disappear without changing the identity or lifecycle of its principal,
session, request, operation, attention request, approval, artifact, or idempotency record.

## Common Value Objects

### Identifier

- UUID version 7 encoded as lowercase canonical text.
- The public type identifies its entity: `request_id`, `operation_id`, `session_id`,
  `attention_id`, `artifact_id`, `principal_id`, `connection_id`, or `daemon_id`.
- An identifier is immutable and never reused.

### Timestamp and Deadline

- Persisted timestamps use UTC with microsecond precision.
- A persisted deadline stores an absolute UTC expiry.
- A live process also tracks a monotonic deadline.
- If wall-clock movement makes a restarted approval deadline uncertain, the attention
  request expires.

### Digest

- SHA-256 over a canonical byte representation.
- Request, operation, approval-scope, artifact, and audit-chain digests have distinct
  value types.
- Equality uses constant-time comparison where the digest protects authentication or
  authorization data.

## Daemon Instance

### Fields

- `daemon_id`
- `state_directory_id`
- `identity_public_key_fingerprint`
- `process_id`
- `started_at`
- `protocol_min` and `protocol_max`
- `state`
- `readiness_revision`
- `last_recovery_report`
- `shutdown_requested_at`

### State Machine

```text
starting -> recovering -> ready -> draining -> stopped
    |           |          |         |
    +---------->failed<-----+---------+
```

| State | Meaning | Allowed exits |
|---|---|---|
| `starting` | The process holds the daemon election lock but accepts no requests | `recovering`, `failed` |
| `recovering` | Migrations, integrity checks, operation classification, and artifact reconciliation run | `ready`, `failed` |
| `ready` | Authenticated reads and mutations are accepted | `draining`, `failed` |
| `draining` | New mutations are rejected while active operations reach safe boundaries | `stopped`, `failed` |
| `stopped` | Shutdown completed and the election lease was released | none |
| `failed` | Readiness or runtime integrity failed | `stopped` after diagnostic capture |

### Invariants

1. One state directory has at most one `starting`, `recovering`, `ready`, or `draining`
   daemon lease.
2. A daemon does not acknowledge readiness before recovery commits its report.
3. `draining` rejects new mutating requests.
4. An unclean process exit does not write `stopped`; the next daemon detects lease loss.

## Principal and Connection

### Principal Fields

- `principal_id`
- `kind`: `native_admin`, `mcp_client`, or `browser_extension`
- `display_name`
- `ecdsa_p256_public_key` and `credential_fingerprint`
- `authentication_epoch`
- `paired_extension_origin` when kind is `browser_extension`
- `extension_install_channel`, ID, version, and update URL when kind is `browser_extension`
- `extension_grants` when kind is `mcp_client`
- `created_at`, `last_authenticated_at`, `revoked_at`
- `capability_ceiling`

### Connection State Machine

```text
connecting -> selecting_contract -> authenticating -> capability_negotiating -> ready
    |                 |                   |                    |
    +-----------------+-------------------+-------------------> rejected
ready -> closing -> closed
```

### Invariants
1. Every handshake uses fixed channel context `matinee.secure-channel.v1`.
2. The signed transcript selects one application contract before key derivation.
3. A connection reads no daemon state before both peers authenticate and derive
   directional encryption keys.
4. An extension connection matches the pinned daemon identity, approved extension
   origin, authentication epoch, and WebSocket subprotocol.
5. Negotiated capabilities are the intersection of daemon, principal, and peer
   capabilities.
6. Connection closure does not cancel confirmed requests or close durable sessions.
7. Rotation or revocation increments the authentication epoch and closes every live
   connection for that principal. A stale epoch cannot send an accepted message.
8. Object access checks capability, owner, and extension grant before existence disclosure.

## Extension Enrollment

### Fields

- `enrollment_id`
- `one_time_ecdsa_p256_public_key` and fingerprint
- expected extension origin, install channel, version range, update URL, daemon identity
  fingerprint, and endpoint
- `created_at`, `expires_at`, optional `consumed_at`
- failed proof count and state: `pending`, `consumed`, `expired`, or `revoked`

### Invariants

1. SQLite contains the one-time public key but never its PKCS#8 private key.
2. Only a matching browser-supplied origin and one-time transcript signature can consume
   a pending enrollment.
3. Consumption and long-term extension-principal creation commit atomically.
4. A consumed, expired, revoked, or rate-limited enrollment can never authenticate.

## Browser Target

### Fields

- `browser_id`: opaque extension-scoped identifier
- `profile_ref`: opaque reference, never a filesystem profile path in public output
- `window_id`, `tab_id`, and optional `frame_id`
- `origin`, redacted `title`, and `document_generation`
- `created_by_matinee`
- `eligibility` and `ineligibility_reason`
- `observed_at`

### Invariants

1. Candidate identifiers are scoped to one paired extension principal.
2. More than one eligible candidate requires explicit selection.
3. Browser credential, cookie, and authorization-header values are never target fields.
4. A navigation that replaces the document increments `document_generation`.

## Browser Session

### Fields

- `session_id`
- `owner_principal_id`
- `browser_id`, `window_id`, `tab_id`
- `created_by_matinee`
- `close_created_tab_on_release`
- `state`
- `document_generation`
- `opened_at`, `last_bound_at`, `rebind_deadline`, `closed_at`
- `active_operation_id`
- `revision`

### State Machine

```text
opening -> active -> releasing -> closed
   |         |  ^         |
   |         v  |         +-> failed
   +-----> rebinding -----+
```

| State | Meaning | Allowed exits |
|---|---|---|
| `opening` | Selection and exclusive ownership are being established | `active`, `failed` |
| `active` | The extension is bound and operations may be queued | `rebinding`, `releasing`, `failed` |
| `rebinding` | The connection or browser binding was lost within its recovery deadline | `active`, `releasing`, `failed` |
| `releasing` | New operations are rejected and indicators are being removed | `closed`, `failed` |
| `closed` | Ownership and indicators were released | none |
| `failed` | Ownership cannot be established or safely retained | `releasing`, `closed` |

### Invariants

1. One browser tab has at most one session in `opening`, `active`, `rebinding`, or
   `releasing` with mutating ownership.
2. One session has at most one operation in `preflight`, `dispatching`, or
   `reconciling`.
3. Element references match the current session and `document_generation`.
4. An adopted tab remains open when the session closes unless the user explicitly
   authorized closure.
5. A session cannot return from `closed`.
6. The daemon commits `releasing` before it sends `session.release`.
7. The session reaches `closed` only after the extension reports that ownership and
   indicators ended and whether the authorized tab-close action completed.

## Request

### Fields

- `request_id`
- `principal_id`
- `client_request_key`
- `request_digest`
- `session_id`
- `state`
- `created_at`, `confirmed_at`, `started_at`, `terminal_at`
- `cancellation_requested_at`
- `terminal_outcome` and optional `failure_id`
- `revision`

### State Machine

```text
received -> confirmed -> queued -> running -----------------> succeeded
    |           |          |         |  |  |                   failed
    |           |          |         |  |  +-> cancelling ---> cancelled
    |           |          |         |  +----> awaiting_attention
    |           |          |         |            |
    |           |          |         |            +-> running
    |           |          |         |            +-> cancelling
    |           |          |         |            +-> expired
    |           |          |         +------> reconciliation_required
    |           |          |                      |
    |           |          |                      +-> running
    |           |          |                      +-> failed
    |           |          +-----------------------------> expired
    +----------------------------------------------------> rejected
```

`received` and `rejected` are transport-level states and need not outlive the connection.
Every state from `confirmed` onward is durable.

### Invariants

1. The daemon persists `confirmed` before acknowledging a mutating request.
2. One request has exactly one terminal state: `succeeded`, `failed`, `cancelled`, or
   `expired`.
3. A terminal request never returns to a nonterminal state.
4. An equivalent client idempotency key maps to one `request_id` and one authoritative
   result.
5. A conflicting digest for an existing idempotency key is rejected before queueing.
6. Client disconnect does not change a confirmed request's state.
7. A request becomes `succeeded` only when all required operations succeeded and no
   unresolved attention or reconciliation remains.
8. When attention reaches its deadline, one transaction moves the pending attention,
   associated operation, and owning request to `expired`. It moves undispatched sibling
   operations to `cancelled` and forbids later browser dispatch for that request.

## Operation

### Fields

- `operation_id`, `request_id`, `session_id`
- `ordinal`
- `kind`
- `target` and `expected_document_generation`
- `input_digest` and redacted `input_summary`
- `client_effect_hint`, optional `extension_effect_observation`, and authoritative
  `effective_effect_class`: `read_only`, `local_reversible`, `external_idempotent`,
  `external_sensitive`, or `uncertain`
- `state`
- `attempt_count` and `retry_policy`
- `queued_at`, `started_at`, `effect_started_at`, `completed_at`
- `result_digest`, optional `failure_id`, and optional `artifact_ids`
- `revision`

### State Machine

```text
planned -> queued -> preflight -> dispatching -> succeeded
   |         |          |             +-------> failed
   |         |          |             +-------> uncertain -> reconciling
   |         |          |                                      |  |  |
   |         |          +-> awaiting_attention                 |  |  +-> uncertain
   |         |                    |  |  |                       |  +----> failed
   |         |                    |  |  +-> expired              +-------> succeeded
   |         |                    |  +----> cancelled (deny or cancel)
   |         |                    +-------> preflight (approve)
   |         +-----------------------------------------------> cancelled
   +---------------------------------------------------------> cancelled
```

### Invariants

1. Operation ordinals are unique and strictly ordered within a request.
2. `preflight` validates session ownership, document generation, target freshness,
   authorization, attention policy, cancellation state, and effective effect class.
3. The daemon persists `effect_started_at` before dispatching a mutating operation.
4. A read-only safe operation may retry within its declared limit.
5. Daemon policy and extension preflight compute the effective effect class. A client
   or extension can raise but cannot lower it. Disagreement becomes `uncertain`.
6. An `external_sensitive` or `uncertain` operation never retries automatically after
   dispatch begins.
7. A persisted screenshot is a local durable mutation keyed by idempotency record.
8. Completion persists before a success result is returned.
9. `uncertain` requires reconciliation and cannot be treated as success or failure by
   inference.
10. An edit cancels the original operation with reason `edited` and creates a replacement
    operation in `planned`. The replacement passes classification and attention again.

## Attention Request and Approval

### Attention Request Fields

- `attention_id`, `request_id`, `operation_id`
- `reason_code`
- `operation_digest`
- redacted `target_summary` and `value_summary`
- `allowed_decisions`
- `trusted_surface_principal_id`
- `state`
- `created_at`, `expires_at`, `decided_at`
- `decision` and optional `edited_operation_digest`
- `revision`
- allowed decisions, trusted surface principal ID, and redacted surface label

### Attention State Machine

```text
pending -> approved -> consumed
    |          |
    |          +-> invalidated
    +-> denied
    +-> edited
    +-> cancelled
    +-> expired
```

An `edited` decision creates a new operation revision and, if still sensitive, a new
attention request. It does not mutate the approved scope in place.

### Approval Fields

- `approval_id`, `attention_id`, `operation_id`
- `approved_operation_digest`
- `deciding_principal_id`
- `created_at`, `expires_at`, `consumed_at`, `invalidated_at`

### Invariants

1. One operation has at most one pending attention request.
2. Only the designated, approved, non-revoked extension principal can decide a request.
3. Approval scope equals the exact operation digest presented to the user.
4. File approval also binds destination, control, browser-selected metadata, content
   digests, volatile handles, and one upload.
5. An approval can be consumed once.
6. Expiry, denial, cancellation, edit, or invalidation never authorizes dispatch.
7. Restart and connection loss preserve `pending`, never convert it to `approved`.
8. A changed operation digest invalidates any existing approval before dispatch.
9. Principal rotation or revocation invalidates unconsumed approvals and fails attention
   assigned to that principal.
## Artifact

### Fields

- `artifact_id`, `principal_id`, `request_id`, optional `operation_id`
- `kind`, `media_type`, `byte_size`, `content_digest`
- `redaction_state`: `not_required`, `redacted`, `unsafe`, or `failed`
- `state`
- `relative_path`
- `created_at`, `expires_at`, `tombstoned_at`
- `failure_id` when unavailable

### State Machine

```text
staging -> available -> tombstoned
    |          |
    +-> failed +-> corrupt
```

### Invariants

1. No metadata row becomes `available` before the durable file digest matches.
2. No unsafe or failed-redaction content becomes `available`.
3. A tombstone preserves identifier, digest, reason, and deletion time without content.
4. Artifact paths are relative to the configured artifact root and cannot escape it.
5. Retention cleanup is idempotent.

## Audit Event

### Fields

- `audit_sequence`
- `daemon_id`
- optional principal, connection, session, request, operation, and attention identifiers
- `event_kind`
- `occurred_at`
- redacted structured attributes
- `previous_digest` and `event_digest`

### Invariants

1. Audit sequence increases within one daemon instance.
2. `event_digest` covers the event payload and `previous_digest`.
3. Audit attributes pass redaction before persistence.
4. Audit chaining detects local alteration but does not claim external non-repudiation.

## Idempotency Record

### Fields

- `principal_id`
- `client_request_key`
- `request_digest`
- `request_id`
- `created_at`, `expires_at`
- optional `terminal_result_digest`

### Invariants

1. `(principal_id, client_request_key)` is unique.
2. The first committed request digest is immutable.
3. Equivalent retries return the original request identity and authoritative state.
4. A conflicting digest fails without changing the existing request.
5. An idempotency record is retained at least as long as its request history.

## Failure Record

### Fields

- `failure_id`
- `code` and primary `class`
- `summary`
- `boundary`
- `retryability`: `never`, `client_after_change`, `automatic_safe`, or
  `reconciliation_required`
- request, operation, session, and connection identifiers when assigned
- redacted `details`
- ordered `safe_next_actions`
- `occurred_at`

### Invariants

1. One failure has one primary class.
2. A failure never exposes a secret or unredacted sensitive page value.
3. `automatic_safe` is valid only for an operation whose effect class permits retry.
4. `reconciliation_required` cannot include a retry action until reconciliation finishes.
