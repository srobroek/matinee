# Data Model: Runtime Foundation

## Configuration Source

One value from the ordered set:

1. `default`
2. `user_file`
3. `project_file`
4. `environment`
5. `command_line`

The order is also the precedence order. A higher source replaces a lower source only
when the key permits both sources.

## Configuration Key Descriptor

Defines one accepted key.

| Field | Rule |
|---|---|
| `name` | Unique dotted key name |
| `value_kind` | Exact scalar or structured value type |
| `default` | Optional non-secret default |
| `allowed_sources` | Non-empty set of configuration sources |
| `material_class` | Exactly one of `non_secret`, `opaque_secret_reference`, or `secret_material` |
| `sensitive` | Whether diagnostics omit the normalized value |
| `normalizer` | Value-specific normalization rule |

### Invariants

- Two descriptors cannot use the same name.
- A protected setting permits only `user_file` and `command_line`.
- A sensitive value never appears in provenance output.
- An unknown key has no implicit descriptor.
- Spec 005's production registry accepts only `non_secret` descriptors. A fixture or
  future registry entry classified as `opaque_secret_reference` or `secret_material`
  fails with `config.secret_forbidden` before merge.
- Material class comes from the descriptor; resolution never guesses from arbitrary raw
  text or key-name patterns.
- A key name has at most four dotted segments.
- The registry contains at most 100 descriptors in this feature.

## Configuration Value

| Field | Rule |
|---|---|
| `key` | References one descriptor |
| `value` | Matches the descriptor's value kind |
| `source` | One configuration source |
| `origin` | Raw local origin; diagnostics receive only its redacted projection |

A layer cannot contain the same key twice. Parsing rejects duplicates before merge.

## Resolved Setting

| Field | Rule |
|---|---|
| `key` | Known configuration key |
| `value` | Normalized winning value; absent from diagnostics when sensitive |
| `source` | Winning source |
| `origin` | Redacted source location |

## Project Root

| Field | Rule |
|---|---|
| `input_path` | Explicit working-directory path |
| `identity` | Normalized absolute path after existing-link resolution |

Matinee does not search parent directories for a project root.

## Resolved Path

| Field | Rule |
|---|---|
| `kind` | `config`, `state`, `runtime`, `cache`, or `log` |
| `input_path` | Path before normalization |
| `absolute_path` | Absolute, lexically normalized path |
| `existing_anchor_id` | Platform file identity for the longest existing ancestor |
| `comparison_tail` | Remaining path interpreted with that filesystem's semantics |
| `identity` | Existing anchor identity plus normalized comparison tail |
| `source` | Source that selected the path |

### Invariants

- Resolution creates no file or directory.
- The platform adapter supplies file identity, case behavior, and Unicode behavior.
- A project configuration identity must remain under the project-root identity before
  Matinee opens the file.
- Equivalent state-root representations have one root identity and one lock identity.
- A lock identity contains the exact canonical root identity without hashing or
  truncation. Distinct root identities therefore cannot share a lock identity.
- A missing final path uses the identity and comparison behavior of its existing
  ancestor.

## Resolved Environment

| Field | Rule |
|---|---|
| `project_root` | One project root |
| `user_config` | Optional user configuration path |
| `project_config` | Optional project configuration path |
| `paths` | Exactly one resolved path for each required kind |
| `settings` | One resolved setting per known key with a value |
| `state_root_identity` | Identity derived from the resolved state path |
| `lock_identity` | Exact canonical `state_root_identity`, wrapped as a distinct type without hashing or truncation |

## Configuration File Snapshot

| Field | Rule |
|---|---|
| `path_identity` | Resolved path identity captured before open |
| `file_identity` | Platform file identity captured from the opened file |
| `file_type` | Regular file; implicit project files cannot be symbolic links |
| `byte_length` | At most 1 MiB |
| `modified_marker` | Best available platform change marker |

Matinee captures the snapshot before parsing and checks file identity, type, length, and
the change marker after reading. A mismatch rejects the resolution. An active same-user
attacker who can replace files during the checks remains outside Matinee's local threat
model.

## Bounded TOML Preflight

Before typed deserialization, a single-pass lexical preflight consumes at most the 1 MiB
file bound and maintains bounded counters and TOML lexical state. It recognizes comments,
quoted and multiline strings, escapes, table headers, arrays, inline tables, and dotted
keys so that syntax inside strings or comments does not affect structural counts.

The preflight returns only when the document has at most 100 assignments, each key has at
most four dotted segments, each text value has at most 4,096 Unicode scalar values, and no
key is duplicated. It rejects immediately when a counter would exceed its limit. A
preflight-rejected document cannot reach typed TOML deserialization. A passing document
may produce `config.syntax_invalid` during typed TOML parsing, but no failure reaches
merge.

## Configuration Failure

| Field | Rule |
|---|---|
| `code` | Closed `config.*` value from the configuration contract |
| `summary` | Static template selected solely by `code` |
| `source` | Closed failure-source projection: a redacted file origin or fixed layer class; for `config.key_unknown`, never the unaccepted key |
| `next_action` | Static template selected solely by `code` |

Raw operating-system errors are retained only long enough to choose a stable code, then
discarded. Raw paths, input values, rejected secret material, parser excerpts, and dynamic
error strings cannot enter the failure value. The `config.key_unknown` failure uses only a
redacted file origin or fixed layer class and never includes the unaccepted key.

### Resolution state machine

```text
unresolved -> locating -> loading -> validating -> resolved
             |          |          |
             +--------> rejected <-+
```

### Transition rules

1. `unresolved -> locating`: capture one immutable resolution input.
2. `locating -> loading`: resolve and validate project-root containment, path identity,
   environment-name identity, and pre-read file snapshots without mutation.
3. `locating -> rejected`: stop before reading on an unsafe path or environment-name
   collision.
4. `loading -> validating`: read each file through its validated path, enforce the byte
   limit, confirm its post-read snapshot, and run the bounded lexical preflight. Only a
   passing preflight reaches typed TOML deserialization.
5. `loading -> rejected`: stop on unreadable, oversized, changed, duplicate, or
   structurally excessive input. A preflight rejection remains before typed
   deserialization.
6. `validating -> rejected`: look up the descriptor first. A missing descriptor, including
   an unregistered reserved key, returns `config.key_unknown`. For a registered descriptor,
   validate material class, then source permission, then value type and normalization. Stop
   at the first failure with `config.secret_forbidden`, `config.source_forbidden`, or
   `config.value_invalid`.
7. `validating -> resolved`: normalize every value and path, then freeze the result.
8. `resolved` and `rejected` are terminal for one resolution attempt.

### Terminal invariants

- A resolved environment contains no unknown key and only `non_secret` descriptors.
- A rejected environment exposes exactly one closed configuration failure.
- Neither terminal outcome creates product state.
- Diagnostic provenance and every failure field use only the closed redacted projection.
- No failure reaches merge.
- Raw operating-system errors, raw paths, raw values, and rejected secret material are
  absent from both terminal outcomes.
