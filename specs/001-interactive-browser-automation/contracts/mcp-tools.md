# MCP Tool Contract

The stdio adapter advertises MCP protocol versions supported by `rmcp` and tool contract
`matinee.tools.v1`. It starts with one required native principal ID, loads that principal's
private key and pinned daemon identity from the platform credential store, and creates no
durable state outside the daemon.

## Common Inputs

Every mutating tool accepts:

- `idempotency_key`: nonempty client-generated string, at most 128 bytes.
- `deadline_ms`: required caller deadline bounded by daemon policy.
- `effect_hint`: optional client lower-bound hint; the daemon and extension compute the
  authoritative effect class and can only raise it.
- `session_id`: required for tab operations.
- `expected_document_generation`: required for an observed document or element target.

## Common Result

```json
{
  "contract": "matinee.tools.v1",
  "request_id": "0199...",
  "state": "succeeded",
  "result": {},
  "artifacts": [],
  "next_actions": []
}
```

A nonterminal result includes `state`, `revision`, and a next action to poll, cancel, or
wait for trusted user attention. Tool errors preserve the common failure fields in
structured content. Human-readable content summarizes rather than replaces them.

## Tools

| Tool | Mutation | Purpose |
|---|---:|---|
| `matinee_status` | no | Read daemon, extension, session, request, and attention summaries |
| `browser_list` | no | List redacted eligible browser, window, and tab candidates |
| `session_open` | yes | Adopt one listed tab or create one visible tab and return a session |
| `session_get` | no | Read authoritative session state and document generation |
| `session_close` | yes | Release ownership and optionally close a Matinee-created tab |
| `page_observe` | no | Return a bounded semantic snapshot and element references |
| `page_navigate` | yes | Navigate the owned tab to an HTTP or HTTPS URL |
| `element_click` | yes | Activate one current element after visible preflight |
| `element_type` | yes | Enter text into one current editable element |
| `keyboard_press` | yes | Send one validated key chord to the owned tab |
| `page_scroll` | yes | Scroll the page or one current element |
| `element_select` | yes | Select declared values in one current control |
| `file_upload` | yes | Ask the trusted user to select and disclose files to one control and origin |
| `page_wait` | no | Wait for a bounded semantic condition or document transition |
| `page_screenshot` | yes | Create one idempotent redacted evidence artifact |
| `request_get` | no | Read one durable request and its operation summaries |
| `request_cancel` | yes | Persist cancellation intent and return reconciliation state |
| `attention_list` | no | List redacted pending attention requests for display to the agent |
| `artifact_get` | no | Read metadata or an authorized bounded artifact reference |
| `diagnostic_export` | yes | Create one redacted diagnostic bundle for an authorized request |

## Principal authorization

An MCP principal sees only extension identities granted to it, sessions and requests it
created, and operations, attention summaries, artifacts, diagnostics, and events owned
by those requests. It cannot read or mutate another MCP principal's objects, administer
principals, or submit extension events. Unknown and unauthorized identifiers return the
same `object.not_found` failure. The adapter filters status and events before encoding.

## Selection rules

`browser_list` returns a `candidate_revision`, expiry, and bounded candidates. A
`session_open` request supplies that revision and exactly one selection:

- `candidate` names one returned `candidate_id` and its document generation.
- `new_tab` names one returned `browser_id`, opaque `profile_ref`, and opaque `window_ref`.

Matinee never selects a candidate, browser, profile, or window implicitly. It accepts no
URL matcher. An expired revision, a mismatched revision, or a `browser.changed` event
returns `selection.stale`. The client must call `browser_list` again.

## Observation Rules

`page_observe` accepts depth, node-count, text-byte, and role filters bounded by daemon
maximums. Its result includes truncation reason, document generation, observed time,
and stable element references scoped to that generation. It excludes password values,
secret-marked inputs, cookies, storage, and authorization headers.

## Mutation rules

A mutation returns only after the daemon confirms its durable request and the operation
reaches a terminal, attention, or reconciliation boundary. A client timeout does not
cancel confirmed work. The client uses `request_get` or `request_cancel` with the
returned `request_id`.

Client `effect_hint` and text sensitivity values are untrusted lower bounds. Daemon
policy classifies operation kind, destination, target semantics, and requested values.
Extension preflight independently reports observed target semantics. The effective class
is the highest severity. Missing evidence or disagreement becomes `uncertain`, which
requires attention and cannot retry automatically.

`element_type` declares `sensitivity` as `normal`, `personal`, or `credential`. The
effective policy can raise but cannot lower it. Credential input requires attention.

## Attention rules

MCP exposes pending attention for agent awareness but no approve tool. The tool result
instructs the agent that the user must decide in the approved extension side panel.
`file_upload` always creates attention and lets the user choose files through that side
panel. An MCP client cannot supply a path, bytes, file handle, or approval. After the
decision, the request continues or reaches its selected terminal outcome.

## Cancellation Rules

MCP cancellation tokens cancel adapter waiting. They do not silently cancel a confirmed
daemon request. The adapter sends `request_cancel` only when the MCP request maps to a
single confirmed request and the MCP client explicitly requested product cancellation.
