# Contract: MVP MCP Tools

**Feature**: [spec.md](../spec.md) | **Protocol**: `matinee.tools.v1` subset

The adapter speaks newline-delimited JSON-RPC 2.0 on stdio. `stdout` carries only
protocol messages; logs go to `stderr`. The adapter holds no durable state: the
daemon owns it (`FR-051`).

Supported methods: `initialize`, `tools/list`, `tools/call`, `resources/read`.

`initialize` returns the daemon instance identity. Every response carries that
identity, and every Operation result carries its session's monotonic action
sequence.

## Mutation context

Every mutating tool accepts:

| Field | Type | Meaning |
|---|---|---|
| `idempotency_key` | string | Caller-supplied opaque key, unique per principal |
| `deadline_ms` | integer | Client deadline; the daemon rejects past-deadline work |
| `effect_hint` | string | `read` or `mutate`, for caller intent only |

Page and element mutations additionally require `session_id` and
`expected_document_generation`. `session_close` takes `session_id` only
(`FR-024`).

## Tools

### browser_list

Read-only. Returns candidates plus `revision` and `expires_at`. Candidate
references are opaque; they carry no browser path, profile directory, or tab id
(`FR-019`).

### session_open

Selects one candidate or creates one fixture tab. Both variants require
`candidate_revision`. Both preallocate a `Session` in `opening` before dispatch
(`FR-020`).

Returns `SessionSummary`: `session_id`, `state`, `tab_incarnation`,
`document_generation`.

### session_get

Read-only. Returns the current `SessionSummary`.

### session_close

Releases ownership. `close_tab` is optional and defaults to false. A target with
an unobserved `failed` Operation refuses conflicting work and release for the
rest of the daemon run (`FR-044`).

### page_observe

Read-only. Returns bounded element references scoped to the owning session, tab
incarnation, and current document generation. A reference is invalid in any other
session or generation (`FR-025`).

### page_navigate

Mutating. Navigates the owned tab to a fixture-origin URL. A non-fixture origin
fails before dispatch (`FR-018`).

### element_click

Mutating. Activates one element reference. The extension shows the owning
indicator, operation boundary, synthetic cursor, and target highlight before
activation (`FR-028`).

### element_type

Mutating. Enters text into one element reference.

### page_screenshot

Mutating, because it changes the active tab. Activates the owned tab, captures,
and restores the previously active tab. Returns one bounded redacted
`ArtifactSummary` whose `resource_uri` is valid for the current daemon run; the
artifact remains in memory and is not persisted (`FR-030`, `SC-019`).

Returns `ArtifactSummary`: `artifact_id`, `digest`, `byte_length`, `resource_uri`,
`redaction_status`.

### request_get

Read-only. Returns the Request with canonical state, its Operations with canonical
states, timestamps, and the structured result or failure.

## Resource reads

`resources/read` on an `ArtifactSummary.resource_uri` reauthorizes the owning MCP
principal and streams at most 32 MiB. A principal that does not own the artifact
receives `authorization.denied` (`FR-030`).

## Failure envelope

Every failure carries `code`, `class`, `summary`, `failed_boundary`,
`retryable`, assigned identifiers, and safe next actions, with protected values
redacted (`FR-052`).

Codes this MVP defines:

| Code | Meaning |
|---|---|
| `daemon.start_conflict` | Another process owns the state directory |
| `daemon.restarted` | The client's instance identity is stale, its named action's outcome is unobserved, and the daemon retains no state |
| `operation.extension_disconnected` | The extension disconnected before the Operation outcome was observed |
| `operation.target_lost` | The Operation target disappeared before its outcome was observed |
| `operation.deadline_expired` | The Operation deadline elapsed before its outcome was observed |
| `candidate.revision_stale` | The candidate revision expired or changed |
| `generation.stale` | The document generation changed before dispatch |
| `incarnation.stale` | The tab incarnation no longer exists |
| `idempotency.conflict` | The key was reused with a different fingerprint |
| `authorization.denied` | The principal does not own the target |
| `origin.rejected` | The origin is not the pinned fixture or extension origin |
