# MCP tool schemas

This file defines every `matinee.tools.v1` tool input and result. Rust JSON Schema is
the generated machine form. Every object sets `additionalProperties: false` unless a
field explicitly uses `JsonValue`.

## Scalar types

| Type | JSON shape | Constraint |
|---|---|---|
| `Id` | string | Lowercase canonical UUIDv7 |
| `IdempotencyKey` | string | 1 to 128 UTF-8 bytes |
| `DocumentGeneration` | integer | 0 to $2^{53}-1$ |
| `ElementRef` | string | 1 to 256 bytes, scoped to one session and generation |
| `DeadlineMs` | integer | 1 to 1,800,000 |
| `Url` | string | Absolute HTTP or HTTPS URL, at most 8,192 bytes |
| `ArtifactUri` | string | `matinee://artifacts/<artifact-id>` |
| `Timestamp` | string | RFC 3339 UTC with microseconds |
| `Sensitivity` | string enum | `normal`, `personal`, or `credential` |

Every optional field accepts omission, not JSON `null`, unless its type includes `null`.
Arrays state their bounds below. All string lengths count UTF-8 bytes.

## Shared objects

### `MutationContext`

| Field | Type | Required |
|---|---|---:|
| `idempotency_key` | `IdempotencyKey` | yes |
| `deadline_ms` | `DeadlineMs` | yes |
| `effect_hint` | effect-class enum | no; untrusted lower bound |

### `SessionContext`

| Field | Type | Required |
|---|---|---:|
| `session_id` | `Id` | yes |
| `expected_document_generation` | `DocumentGeneration` | yes for element or document mutation |

## Result shapes

### `ExtensionSummary`

| Field | Shape |
|---|---|
| `extension_id`, `browser_id` | `Id` |
| `browser_name` | `chrome` or `chromium` |
| `browser_version` | String |
| `install_channel` | `store` or `development` |
| `connection_state` | `connected`, `disconnected`, or `revoked` |
| `granted_origins` | At most 128 origins |
| `capabilities` | At most 64 strings |
| `last_seen_at` | Timestamp |

### `BrowserCandidate`

| Field | Shape |
|---|---|
| `candidate_id`, `extension_id`, `browser_id` | `Id` |
| `profile_ref`, `window_ref`, `tab_ref` | Opaque string |
| `title` | Nullable redacted string, at most 512 characters |
| `origin` | `Origin` |
| `document_generation` | Integer |
| `visible`, `active`, `created_by_matinee` | Boolean |
| `eligibility` | `eligible` or `ineligible` |
| `ineligibility_reason` | Nullable string |

### `SessionSummary`

| Field | Shape |
|---|---|
| `session_id`, `extension_id`, `browser_id` | `Id` |
| `window_ref`, `tab_ref` | Opaque string |
| `state` | `opening`, `active`, `rebinding`, `releasing`, `closed`, or `failed` |
| `origin` | `Origin` |
| `title` | Nullable redacted string, at most 512 bytes |
| `created_by_matinee`, `close_created_tab_on_release` | Boolean |
| `document_generation`, `revision` | Integer |
| `opened_at`, `last_bound_at`, `rebind_deadline`, `closed_at` | Timestamp; last three nullable |

### `RequestSummary`

| Field | Shape |
|---|---|
| `request_id` | `Id` |
| `state` | Request state-machine value |
| `session_ids`, `operation_ids` | At most 1,024 `Id` values each |
| `outcome` | Nullable `JsonValue` |
| `failure` | Nullable `Failure` |
| `created_at`, `updated_at` | Timestamp |
| `terminal_at` | Nullable timestamp |
| `revision` | Integer |

### `OperationSummary`

| Field | Shape |
|---|---|
| `operation_id`, `request_id`, `session_id` | `Id` |
| `kind` | Operation-set value |
| `state` | Operation state-machine value |
| `effective_effect_class` | Effect enum |
| `attention_id` | Nullable `Id` |
| `result` | Nullable `JsonValue` |
| `failure` | Nullable `Failure` |
| `created_at`, `updated_at` | Timestamp |

### `AttentionSummary`

| Field | Shape |
|---|---|
| `attention_id`, `request_id`, `operation_id` | `Id` |
| `operation` | `OperationSummary` without result data |
| `reason_code`, `operation_digest` | String |
| `target_summary`, `value_summary` | Redacted string, at most 2,048 characters each |
| `allowed_decisions` | Nonempty subset of `approve`, `deny`, `edit`, and `cancel` |
| `trusted_surface_principal_id` | Extension principal `Id` |
| `state` | Attention state-machine value |
| `created_at`, `expires_at` | Timestamp |
| `decided_at` | Nullable timestamp |
| `decision` | Nullable allowed-decision value |
| `edited_operation_digest` | Nullable string |
| `revision` | Integer |

This shape excludes credentials, file data, raw typed values, and unredacted page text.

### `ArtifactSummary`

| Field | Shape |
|---|---|
| `artifact_id`, `principal_id`, `request_id` | `Id` |
| `operation_id` | Nullable `Id` |
| `kind`, `media_type`, `content_digest` | String |
| `byte_size` | Integer from 0 to 33,554,432 |
| `redaction_state` | `not_required`, `redacted`, `unsafe`, or `failed` |
| `state` | `staging`, `available`, `tombstoned`, `failed`, or `corrupt` |
| `resource_uri` | Nullable string |
| `created_at`, `expires_at` | Timestamp |
| `tombstoned_at` | Nullable timestamp |
| `failure_id` | Nullable `Id` |

### `ResolvedConfigValue`

| Field | Shape |
|---|---|
| `key` | String |
| `value` | Redacted `JsonValue` |
| `source` | `default`, `user`, `project`, `environment`, or `cli` |
| `security_locked` | Boolean |

Credential references may appear. Private keys and enrollment values never appear.

### `Failure`

| Field | Shape |
|---|---|
| `code` | Stable code |
| `class` | Failure taxonomy class |
| `summary` | Bounded safe string |
| `boundary` | Failed boundary |
| `retryability` | Retry taxonomy value |
| `request_id`, `operation_id` | Nullable `Id` |
| `safe_next_actions` | At most 20 structured actions |
| `details` | Optional redacted `JsonValue` with no page or credential secret |

### `ToolResult<T>`

| Field | Type | Required |
|---|---|---:|
| `contract` | constant `matinee.tools.v1` | yes |
| `request_id` | `Id` | yes after durable confirmation |
| `state` | request-state enum | yes |
| `revision` | integer from 0 | yes |
| `result` | `T` | when the requested boundary has a result |
| `failure` | common failure envelope | on failure or reconciliation |
| `artifacts` | array of `ArtifactSummary`, 0 to 100 | yes |
| `next_actions` | array of structured next actions, 0 to 20 | yes |

A read-only tool that creates no request omits `request_id` and reports `state: succeeded`.
A response contains at most one of `result` and `failure`.


## Tool schemas

### `matinee_status`

**Input**

- `requests`: optional enum `active` or `all`; default `active`.
- `limit`: optional integer 1 to 100; default 20.

**Result**

`daemon` summary, `extensions: ExtensionSummary[]`, `sessions: SessionSummary[]`,
`requests: RequestSummary[]`, `pending_attention: AttentionSummary[]`, `queue_depth:
integer`, `degraded: Failure[]`, and `configuration: ResolvedConfigValue[]`.

### `browser_list`

**Input**

- `include_ineligible`: optional boolean; default false.

**Result**

`candidate_revision: integer`, `expires_at: Timestamp`, and
`candidates: BrowserCandidate[]`. The array contains at most 100 items.

### `session_open`

**Input**

- All `MutationContext` fields.
- `selection`: exactly one of:
  - `candidate` with `candidate_id: Id`, current `candidate_revision`, and current
    `expected_document_generation`.
  - `new_tab` with `browser_id: Id`, opaque `profile_ref`, opaque `window_ref`, current
    `candidate_revision`, and optional `initial_url` of at most 4,096 characters. The
    default URL is `about:blank`.
- `close_created_tab_on_release`: optional boolean. It defaults to `false` for an adopted
  candidate and `true` for a new tab.

**Result**

`session: SessionSummary`. For `new_tab`, `created_by_matinee` is true and the returned
opaque `tab_ref` identifies the created visible tab.

### `session_get`

**Input**

- `session_id: Id`.

**Result**

`session: SessionSummary` and optional `active_operation: OperationSummary`.

### `session_close`

**Input**

- All `MutationContext` fields.
- `session_id: Id`.
- `close_tab`: optional boolean; default false. It requires explicit authorization for
  an adopted tab.

**Result**

`session: SessionSummary` in `closed` or `failed` state and `tab_closed: boolean`.

### `page_observe`

**Input**

- `session_id: Id`.
- `max_depth`: optional integer 1 to 20; default 12.
- `max_nodes`: optional integer 1 to 5,000; default 1,000.
- `max_text_bytes`: optional integer 1 to 262,144; default 65,536.
- `roles`: optional array of 1 to 50 nonempty ARIA role strings.

**Result**

`session_id`, `document_generation`, `observed_at`, `root: SemanticNode`, `node_count`,
`text_bytes`, and optional `truncated` with `reason` and reached limit. Each
`SemanticNode` contains `element_ref`, role, redacted name, state map, and child array.

### `page_navigate`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `url: Url`.
- `wait_until`: optional enum `committed`, `dom_content_loaded`, or `load`; default
  `dom_content_loaded`.

**Result**

`session_id`, final redacted `url`, new `document_generation`, and reached
`navigation_state`.

### `element_click`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `element_ref: ElementRef`.
- `button`: optional enum `primary`, `middle`, or `secondary`; default `primary`.
- `click_count`: optional integer 1 or 2; default 1.
- `modifiers`: optional unique array containing `Alt`, `Control`, `Meta`, or `Shift`.

**Result**

`operation: OperationSummary`, resulting `document_generation`, and
`navigation_started: boolean`.

### `element_type`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `element_ref: ElementRef`.
- `text`: string from 0 to 1,048,576 bytes.
- `mode`: optional enum `replace` or `append`; default `replace`.
- `sensitivity: Sensitivity`.

**Result**

`operation: OperationSummary`, `inserted_bytes: integer`, and resulting
`document_generation`. Results never echo `text`.

### `keyboard_press`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `key`: one nonempty key name of at most 64 bytes.
- `modifiers`: optional unique modifier array from `element_click`.
- `element_ref`: optional `ElementRef`; omission targets the current document focus.

**Result**

`operation: OperationSummary` and resulting `document_generation`.

### `page_scroll`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `element_ref`: optional `ElementRef`; omission targets the viewport.
- `delta_x` and `delta_y`: integers from -100,000 to 100,000. At least one is nonzero.
- `behavior`: optional enum `instant` or `smooth`; default `instant`.

**Result**

`operation: OperationSummary`, integer `applied_x`, integer `applied_y`, and resulting
`document_generation`.

### `element_select`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `element_ref: ElementRef`.
- `values`: array of 1 to 100 strings, each at most 4,096 bytes.

**Result**

`operation: OperationSummary`, `selected_values: string[]`, and resulting
`document_generation`.

### `file_upload`

**Input**

- All `MutationContext` and `SessionContext` fields.
- `element_ref: ElementRef`.
- `file_request` with `count_min` and `count_max` from 1 to 20,
  `accept_media_types` containing at most 50 media types, `accept_extensions`
  containing at most 50 extensions, `max_file_bytes` at most 33,554,432, and
  `max_total_bytes` at most 134,217,728.

The user selects files in the trusted extension side panel. The MCP input carries only
selection constraints. It contains no file path or bytes. It contains no handle, name,
or digest.

**Result**

| Result field | Shape |
|---|---|
| `operation` | `OperationSummary` |
| `files` | Array of selected-file metadata |

Each `files` item has browser-reported name, media type, byte size, last-modified time,
and content digest.

| Approval scope | Bound value |
|---|---|
| Destination | Origin and element reference |
| Document | Generation |
| Use count | One upload |

The result omits local paths, file handles, and file content.

### `page_wait`

**Input**

- `session_id: Id`.
- `timeout_ms`: integer 1 to 300,000.
- `condition`: exactly one of:
  - `url_matches: { pattern: string }`.
  - `text_present: { text: string, exact: boolean }`.
  - `element_state: { element_ref: ElementRef, state: visible | hidden | enabled | disabled }`.
  - `document_generation_after: { generation: DocumentGeneration }`.

Patterns and text contain at most 4,096 bytes.

**Result**

`condition`, `satisfied_at`, `document_generation`, and optional `element_ref`.

### `page_screenshot`

**Input**

- All `MutationContext` fields.
- `session_id: Id` and current `expected_document_generation`.
- `scope`: enum `viewport`, `full_page`, or `element`.
- `element_ref`: required only for `element` scope.
- `format`: optional enum `png` or `jpeg`; default `png`.
- `quality`: integer 1 to 100, allowed only for `jpeg`.

**Result**

`artifact: ArtifactSummary`. Equivalent retries return the same artifact. If the
extension cannot confirm sensitive-field masking, the tool returns
`artifact.redaction_unsafe` and creates no artifact.

### `request_get`

**Input**

- `request_id: Id`.
- `include_operations`: optional boolean; default true.

**Result**

`request: RequestSummary` and `operations: OperationSummary[]` with at most 1,000 items.

### `request_cancel`

**Input**

- All `MutationContext` fields.
- `request_id: Id`.
- `reason`: optional string of at most 1,024 bytes.

**Result**

`request: RequestSummary`, `cancellation_recorded: boolean`, and optional
`reconciliation: OperationSummary`.

### `attention_list`

**Input**

- `request_id`: optional `Id` filter.
- `limit`: optional integer 1 to 100; default 20.

**Result**

`attention: AttentionSummary[]`. Each summary contains IDs, reason, redacted target and
value summaries, allowed decisions, trusted surface label, creation time, and expiry.
It contains no approval token or secret value.

### `artifact_get`

**Input**

- `artifact_id: Id`.

**Result**

`artifact: ArtifactSummary`. Clients read bytes through the returned MCP resource URI.
The adapter authorizes each resource read against the same principal before streaming at
most 32 MiB.

### `diagnostic_export`

**Input**

- All `MutationContext` fields.
- `request_id: Id`.
- `include_artifacts`: optional boolean; default true.

**Result**

`artifact: ArtifactSummary` for a ZIP bundle containing redacted request state, operation
summaries, failures, audit events, resolved non-secret configuration, and allowed
artifacts. The bundle excludes reusable credentials and raw browser-profile data.

## MCP resources

The adapter exposes an artifact as `matinee://artifacts/<artifact-id>`. Resource reads
require the native principal that requested the resource, enforce retention and size
limits, and return the recorded media type and digest. A deleted, expired, unauthorized,
or unsafe artifact returns the common failure envelope without revealing its prior path.
