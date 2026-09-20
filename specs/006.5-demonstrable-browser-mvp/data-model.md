# Data Model: Demonstrable Multi-Tab Browser MVP

**Feature**: [spec.md](./spec.md) | **Date**: 2026-09-20

The daemon holds every record below in memory for one process run. Nothing is
written to a file or a database. `adr-10` records that scope limit and its
Constitution III exception; Spec 007 owns the durable store.

Public `Request`, `Operation`, and `Session` states stay inside the
`matinee.tools.v1` enumerations.

## State ownership

| Record | Public | Lifetime |
|---|---|---|
| State Directory Lock | no | held for the process run |
| Daemon Instance | yes | one per process run |
| Principal | partly | process run |
| Pairing | partly | process run |
| Session | yes | process run |
| Request | yes | process run |
| Operation | yes | process run |
| Idempotency Record | no | process run |
| Artifact | yes | process run |

The only thing the daemon leaves on disk is the advisory ownership lock, which
the operating system releases when the process exits.

## State Directory Lock

Fields: `canonical_path`, `owning_process_id`, `started_at`.

Startup acquires this lock before binding any endpoint, so two daemons cannot own
one state directory. Every loser returns `daemon.start_conflict` and mutates
nothing (`FR-001`, `SC-005`).

## Daemon Instance

Fields: `instance_id` (UUID), `started_at`.

Generated once per process start. Every response carries it. A request bearing a
different value fails with `daemon.restarted`, naming the client's last action
sequence and stating that its outcome is unobserved (`FR-034`, `FR-036`).

This is the crash-detection mechanism that replaces recovery: a restarted daemon
is a visibly different daemon, so a client cannot mistake an empty daemon for one
that still holds its work.

## Principal

Fields: `identity_id` (UUID), `kind` (`native-admin` | `mcp` | `extension`),
`credential_reference`, `epoch`, `status` (`active` | `revoked`).

Private keys live in the platform credential store, except the extension key,
which stays non-exportable in extension-local WebCrypto storage (`FR-016`).

## Pairing

Fields: `pairing_id`, `extension_identity_id`, `origin`, `public_key`,
`fingerprint`, `development_allowance`, `status`.

`origin` pins one `chrome-extension://<id>`.

## Session

Fields: `session_id`, `mcp_principal_id`, `pairing_id`, `browser`, `profile`,
`window`, `tab_incarnation`, `document_generation`, `state`, `next_sequence`.

`state` uses the canonical enumeration: `opening`, `active`, `rebinding`,
`releasing`, `closed`, `failed`.

Transitions:

- `opening` to `active` when a bind result confirms a tab incarnation and initial
  document generation.
- `opening` to `failed` when its owning Operation terminates as `failed`
  (`FR-041`).
- `active` to `rebinding` on extension reconnect, then back to `active` once the
  incarnation and generation verify.
- `active` or `rebinding` to `releasing` on `session_close`, then to `closed`.
- `releasing` to `failed` when the closing Operation terminates as `failed`.

`tab_incarnation` is daemon-issued and non-repeating within the run. The Chrome
tab id is a routing hint, never an identity (`FR-023`). `document_generation`
holds the Chrome `documentId`.

`next_sequence` issues the monotonic action sequence for this session
(`FR-035`).

## Request

Fields: `request_id`, `mcp_principal_id`, `tool`, `idempotency_key`,
`fingerprint`, `deadline_ms`, `effect_hint`, `state`, `failure_code`.

`state` uses the canonical enumeration, and every confirmed Request reaches
exactly one terminal value: `succeeded`, `failed`, `cancelled`, or `expired`.

`fingerprint` digests the tool, principal, target, and arguments. Reusing an
idempotency key with a different fingerprint returns
`idempotency.conflict` without dispatch (`FR-040`).

## Operation

Fields: `operation_id`, `request_id`, `sequence`, `action_sequence`,
`target_descriptor`, `fingerprint`, `state`, `effect_started_at`, `result`.

`state` uses the canonical enumeration: `planned`, `queued`, `preflight`,
`dispatching`, `awaiting_attention`, `succeeded`, `failed`, `expired`,
`cancelled`.

`target_descriptor` for an existing tab holds the session, tab incarnation, and
expected document generation. For new-tab creation it holds the preallocated
session plus the validated browser, profile, window, and candidate revision, with
no incarnation or generation (`FR-033`).

When the daemon loses the evidence needed to observe a dispatched Operation, the
Operation terminates as `failed` with a code naming the lost boundary, such as
extension disconnect, target loss, or deadline expiry. The daemon reports no
success and never re-dispatches (`FR-037`, `FR-038`).

## Idempotency Record

Fields: `idempotency_key`, `mcp_principal_id`, `request_id`, `fingerprint`.
Unique on (`mcp_principal_id`, `idempotency_key`) within the run.

## Artifact

Fields: `artifact_id`, `operation_id`, `kind` (`screenshot`), `digest`,
`byte_length`, `bytes`, `redaction_status`, `resource_uri`.

Bytes live in memory and the `resource_uri` is valid for the current run only.
Failed masking yields no artifact identity and no bytes (`FR-030`).

## Invariants

1. No Operation reports success unless the daemon observed its result.
2. No Operation is retried automatically after its outcome is lost.
3. One process holds the state-directory lock; every loser returns
   `daemon.start_conflict`.
4. Every confirmed Request reaches exactly one terminal state within the run.
5. Every response carries the current instance identity, and a stale one is
   rejected.
6. Action sequences increase monotonically per session and never repeat.
7. An unobserved `failed` Operation blocks conflicting work on its target for the
   rest of the run (`FR-044`).
8. No secret, cookie, or unredacted screenshot is exposed (`FR-047`).
