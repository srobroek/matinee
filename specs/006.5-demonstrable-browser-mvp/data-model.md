# Data Model: Demonstrable Multi-Tab Browser MVP

**Feature**: [spec.md](./spec.md) | **Date**: 2026-09-20

One SQLite database in the state directory holds every record below. The daemon is
the only writer. Schema version 1 lives in `PRAGMA user_version`; the daemon
rejects any other value without migrating (`FR-045`).

Public `Request`, `Operation`, and `Session` states stay inside the
`matinee.tools.v1` enumerations. The `Dispatch Record` is private and adds no
public state (`FR-032`).

## State ownership

| Record | Public | Written by | Read by |
|---|---|---|---|
| State Directory | no | daemon | daemon |
| Principal | partly | daemon | daemon |
| Pairing | partly | daemon | daemon |
| Session | yes | daemon | MCP clients |
| Request | yes | daemon | MCP clients |
| Operation | yes | daemon | MCP clients |
| Dispatch Record | no | daemon | daemon recovery |
| Idempotency Record | no | daemon | daemon |
| Unknown Reservation | no | daemon | daemon recovery |
| Artifact | yes | daemon | MCP clients |
| Daemon Exit | no | daemon | doctor, recovery |

## State Directory

Fields: `state_id` (UUID), `canonical_path`, `schema_version`, `created_at`.

The daemon binds one `state_id` to one canonical filesystem identity and persists
both, so a copied directory cannot silently become a second authority
(`FR-001`). Exclusive ownership uses an advisory lock file inside the directory
holding the owning process id and start time; `matinee_runtime`'s `LockIdentity`
supplies the identity value but performs no locking.

## Principal

Fields: `identity_id` (UUID), `kind` (`native-admin` | `mcp` | `extension`),
`credential_reference`, `epoch`, `status` (`active` | `revoked`), `created_at`.

Private keys never enter this table. `credential_reference` names the platform
credential-store locator, except the extension principal, whose private key stays
non-exportable in extension-local WebCrypto storage (`FR-016`).

## Pairing

Fields: `pairing_id`, `extension_identity_id`, `origin`, `public_key`,
`fingerprint`, `development_allowance`, `status`, `created_at`, `rotated_at`.

`origin` pins one `chrome-extension://<id>`. A rotation retires the previous
fingerprint and quarantines it against reuse.

## Session

Fields: `session_id`, `mcp_principal_id`, `pairing_id`, `browser`, `profile`,
`window`, `tab_incarnation`, `document_generation`, `state`, `created_at`,
`closed_at`.

`state` uses the canonical `SessionSummary` enumeration: `opening`, `active`,
`rebinding`, `releasing`, `closed`, `failed`.

Transitions:

- `opening` to `active` when a bind result confirms a tab incarnation and initial
  document generation.
- `opening` to `failed` when the owning Operation is cancelled before dispatch, or
  when a `session_open` Operation becomes `uncertain` (`FR-036`, `FR-041`).
- `active` to `rebinding` on extension reconnect, then back to `active` after the
  incarnation and generation verify.
- `active` or `rebinding` to `releasing` on `session_close`, then to `closed`.
- `releasing` to `failed` when a `session_close` Operation becomes `uncertain`.

`tab_incarnation` is daemon-issued and non-repeating. The Chrome tab id is a
routing hint only and never an identity (`FR-023`). `document_generation` holds
the Chrome `documentId`.

## Request

Fields: `request_id`, `mcp_principal_id`, `tool`, `idempotency_key`,
`fingerprint`, `deadline_ms`, `effect_hint`, `state`, `created_at`,
`terminal_at`, `failure_code`.

`state` uses the canonical enumeration, and every confirmed Request reaches
exactly one terminal value: `succeeded`, `failed`, `cancelled`, `expired`, or
`reconciliation_required`.

`fingerprint` is a stable digest of the tool name, principal, target, and
arguments. Reusing an idempotency key with a different fingerprint returns a
conflict without dispatch (`FR-040`).

## Operation

Fields: `operation_id`, `request_id`, `sequence`, `target_descriptor`,
`fingerprint`, `state`, `effect_started_at`, `terminal_at`, `result`.

`state` uses the canonical enumeration: `planned`, `queued`, `preflight`,
`dispatching`, `awaiting_attention`, `succeeded`, `failed`, `uncertain`,
`reconciling`, `expired`, `cancelled`.

`target_descriptor` for an existing tab holds the session, tab incarnation, and
expected document generation. For new-tab creation it holds the preallocated
session plus the validated browser, profile, window, and candidate revision, with
no incarnation or generation (`FR-033`).

## Dispatch Record

Fields: `operation_id`, `request_id`, `phase` (`prepared` | `dispatched`),
`fingerprint`, `target_descriptor`, `prepared_at`, `dispatched_at`.

This private record is the two-phase journal:

1. The daemon commits `prepared` while the Operation is `preflight`.
2. The daemon commits `dispatched` and moves the Operation to `dispatching` in one
   transaction, before the extension receives the command (`FR-035`).

Recovery reads the phase:

- No record in phase `dispatched`: cancel the Operation, fail the Request with
  `daemon.stopped_before_dispatch`, and fail any preallocated `session_open`
  Session (`FR-036`).
- Phase `dispatched` with no terminal result: move the Operation to `uncertain`
  and the Request to `reconciliation_required` (`FR-037`).

## Idempotency Record

Fields: `idempotency_key`, `mcp_principal_id`, `request_id`, `fingerprint`,
`created_at`. Unique on (`mcp_principal_id`, `idempotency_key`).

## Unknown Reservation

Fields: `operation_id`, `request_id`, `session_id`, `target_descriptor`,
`created_at`.

A reservation quarantines its target against conflicting work, ownership release,
and clean daemon stop until an operator resolves it. It forbids automatic replay
and adds no public Operation state (`FR-038`, `FR-044`).

## Artifact

Fields: `artifact_id`, `operation_id`, `kind` (`screenshot`), `digest`,
`byte_length`, `relative_path`, `redaction_status`, `availability`, `created_at`.

The daemon writes the image bytes and their digest, commits them, and only then
sets `availability` to `available` (`FR-030`). Failed or indeterminate masking
leaves no row and no bytes reachable. Orphaned unavailable bytes may be removed
after restart.

## Daemon Exit

Fields: `exit_id`, `kind` (`clean` | `unclean`), `recorded_at`, `reason`.

A clean stop commits this record last. Its absence at startup means the previous
process died, so recovery runs before the daemon accepts operations (`FR-048`).

## Invariants

1. No browser command is sent before its Dispatch Record reaches `dispatched`.
2. No public state advances before its persistence barrier commits.
3. One writer holds the state directory; every loser returns
   `daemon.start_conflict`.
4. Every confirmed Request reaches exactly one terminal state.
5. An `uncertain` Operation is never retried automatically.
6. Artifact metadata never becomes `available` before its bytes and digest are
   durable.
7. No secret, cookie, or unredacted screenshot is stored (`FR-047`).
