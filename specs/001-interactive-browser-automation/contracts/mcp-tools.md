# MCP Tool Contract

The stdio adapter advertises MCP protocol versions supported by `rmcp` and tool contract
`matinee.tools.v1`. It creates no durable state outside the daemon.

## Common Inputs

Every mutating tool accepts:

- `idempotency_key`: nonempty client-generated string, at most 128 bytes.
- `deadline_ms`: optional caller deadline bounded by daemon policy.
- `session_id`: required for tab operations.
- `expected_document_generation`: required when using an observed element reference.

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
| `session_open` | yes | Acquire one explicitly selected tab and return a session |
| `session_get` | no | Read authoritative session state and document generation |
| `session_close` | yes | Release ownership and optionally close a Matinee-created tab |
| `page_observe` | no | Return a bounded semantic snapshot and element references |
| `page_navigate` | yes | Navigate the owned tab to an HTTP or HTTPS URL |
| `element_click` | yes | Activate one current element after visible preflight |
| `element_type` | yes | Enter text into one current editable element |
| `keyboard_press` | yes | Send one validated key chord to the owned tab |
| `page_scroll` | yes | Scroll the page or one current element |
| `element_select` | yes | Select declared values in one current control |
| `file_upload` | yes | Attach declared local files after policy and attention checks |
| `page_wait` | no | Wait for a bounded semantic condition or document transition |
| `page_screenshot` | no | Capture explicitly requested redacted evidence |
| `request_get` | no | Read one durable request and its operation summaries |
| `request_cancel` | yes | Persist cancellation intent and return reconciliation state |
| `attention_list` | no | List redacted pending attention requests for display to the agent |
| `artifact_get` | no | Read metadata or an authorized bounded artifact reference |
| `diagnostic_export` | yes | Create one redacted diagnostic bundle for an authorized request |

## Selection Rules

`session_open` accepts exact `browser_id`, `window_id`, and `tab_id` candidates returned
by `browser_list`, or a URL matcher that must resolve to exactly one eligible tab. It
never selects the first candidate implicitly. Candidate references expire after 30
seconds or any `browser.changed` event.

## Observation Rules

`page_observe` accepts depth, node-count, text-byte, and role filters bounded by daemon
maximums. Its result includes truncation reason, document generation, observed time,
and stable element references scoped to that generation. It excludes password values,
secret-marked inputs, cookies, storage, and authorization headers.

## Mutation Rules

A mutation returns only after the daemon confirms its durable request and the operation
reaches a terminal, attention, or reconciliation boundary. A client timeout does not
cancel confirmed work. The client uses `request_get` or `request_cancel` with the
returned `request_id`.

`element_type` declares `sensitivity` as `normal`, `personal`, or `credential`. The
daemon can raise sensitivity but cannot lower a credential classification supplied by
the client or extension. Credential input always requires trusted attention.

## Attention Rules

MCP exposes pending attention for agent awareness but no approve tool. The tool result
instructs the agent that the user must decide in the paired browser extension. After the
decision, the request continues or reaches its selected terminal outcome.

## Cancellation Rules

MCP cancellation tokens cancel adapter waiting. They do not silently cancel a confirmed
daemon request. The adapter sends `request_cancel` only when the MCP request maps to a
single confirmed request and the MCP client explicitly requested product cancellation.
