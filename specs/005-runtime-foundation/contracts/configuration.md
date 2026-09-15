# Configuration Contract

This contract narrows the configuration rules from spec 001 for runtime foundation
work. Later specifications add keys without changing source precedence.

## Locations

| Platform | User file | State directory |
|---|---|---|
| macOS | `~/Library/Application Support/Matinee/config.toml` | `~/Library/Application Support/Matinee/state/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/matinee/config.toml` | `${XDG_STATE_HOME:-~/.local/state}/matinee/` |
| Windows | `%APPDATA%\Matinee\config.toml` | `%LOCALAPPDATA%\Matinee\state\` |

The implicit project file is `matinee.toml` in the selected project root. Matinee does
not search parent directories. It validates containment and captures file identity
before reading the file. It rejects an implicit project file that is a symbolic link or
changes identity while being read.

The resolver models explicit `--config` and `--state-dir` inputs, but spec 005 does not
expose those flags. A later owning specification can bind them to the public CLI.

Environment keys use the `MATINEE_` prefix and double underscores for nesting. Matinee
applies native environment-name comparison before mapping names to dotted keys. Two
source names that map to one key fail as a duplicate.

## Source policy

| Source | Ordinary key | Protected key |
|---|---:|---:|
| Built-in default | Allowed | Allowed only for a non-selecting default |
| User file | Allowed | Allowed |
| Project file | Allowed | Rejected |
| Environment | Allowed | Rejected |
| Command line | Allowed | Allowed |

Protected keys are:

- `state_dir`, owned by spec 005
- `daemon.endpoint`, reserved for spec 007
- `principal.native`, reserved for spec 006
- `extension.development_identity`, reserved for spec 008

The resolver accepts `state_dir` in the user or command-line layer. It rejects each
reserved key as unknown until its owning specification defines the type and default.
Every source rejects unknown and duplicate keys.

The source-policy table applies only after descriptor lookup succeeds. Classification
order is descriptor presence, material class, source permission, then value validity. A
missing descriptor returns `config.key_unknown`, including for a reserved key whose owner
has not registered it. Only a registered protected descriptor can return
`config.source_forbidden`. Only a registered secret-class descriptor can return
`config.secret_forbidden`.

The descriptor registry is closed. Every descriptor declares exactly one material
class:

- `non_secret`;
- `opaque_secret_reference`;
- `secret_material`.

Spec 005's production registry contains only `non_secret` descriptors. Resolution rejects
either other class as `config.secret_forbidden`, including in fixture registries. It never
classifies arbitrary raw text by name or value pattern. Spec 005 rejects opaque secret
references and secret material. A later owning specification must define any opaque
reference before Matinee accepts it.

## Merge result

For each accepted non-secret key, the result exposes:

- normalized value;
- winning source;
- redacted origin: user paths relative to `~`, project paths relative to the project
  root, environment and argument origins by accepted key name, or `built-in`.

Successful provenance may name accepted keys. Failure `source` uses a separate closed
projection: either a redacted file origin (a user path relative to `~` or a project path
relative to the project root) or one fixed layer class (`built-in`, `user-file`,
`project-file`, `environment`, or `command-line`). It never contains an unaccepted key
token, raw absolute path, raw value, or operating-system error text. In particular,
`config.key_unknown` reports only the redacted file origin or fixed layer class.

Raw absolute paths and raw values remain internal and never enter a diagnostic field.

The resolver returns the complete result or one structured failure. It does not return a
partial environment and does not create files or directories.

## Resource limits

| Input | Limit |
|---|---:|
| One configuration file | 1 MiB |
| Accepted keys | 100 |
| Dotted-key segments | 4 |
| One text value | 4,096 Unicode scalar values |

Matinee enforces the file-byte limit before TOML parsing. It then performs one bounded,
TOML-aware lexical preflight over at most those bytes before typed deserialization.

The preflight tracks these TOML forms:

- quoted and multiline strings;
- escapes and comments;
- arrays and inline tables;
- table headers and dotted keys.

The preflight counts assignments and Unicode scalar values without treating string or
comment contents as syntax. It rejects a duplicate key, more than 100 assignments, more
than four dotted-key segments, or a text value longer than 4,096 Unicode scalar values.

Contract cases cover exact limits, one-over limits, and syntactically pathological 1 MiB
inputs. Preflight-rejected documents cannot reach typed deserialization. A document may
produce `config.syntax_invalid` during typed TOML parsing. No failure reaches merge.

## Failure codes

| Code | Condition |
|---|---|
| `config.file_unreadable` | A selected file cannot be read |
| `config.file_changed` | A selected file changes identity while being read |
| `config.file_too_large` | A selected file exceeds 1 MiB |
| `config.syntax_invalid` | TOML parsing fails |
| `config.key_duplicate` | One layer or normalized environment source repeats a key |
| `config.key_unknown` | Any layer defines a key with no registered descriptor, including a reserved key before its owning specification registers it; its source contains only a redacted file origin or fixed layer class and never the key |
| `config.source_forbidden` | A source sets a registered protected descriptor that it cannot set |
| `config.value_invalid` | A registered value has the wrong type or fails normalization after source authorization |
| `config.secret_forbidden` | A registered descriptor class is `opaque_secret_reference` or `secret_material` in spec 005 |
| `config.limit_exceeded` | Key count, nesting, or text length exceeds its limit |
| `config.project_escape` | The selected project file resolves outside the project root |
| `config.path_unavailable` | A required platform base path cannot be determined |

Every failure has exactly four public fields:

1. `code`: one value from the closed table above;
2. `summary`: one static template selected by `code`;
3. `source`: one value from the closed failure-source projection: a redacted file origin
   or fixed layer class, never an unaccepted key token; and
4. `next_action`: one static remediation template selected by `code`.

Renderers discard raw operating-system error text after mapping it to a code. Raw paths,
raw configuration values, rejected secret material, parser excerpts, and dynamically
constructed strings cannot enter `summary`, `source`, or `next_action`. Contract cases
cover unreadable, changed, escaped, oversized, malformed, duplicate, unknown,
source-forbidden, secret-forbidden, limit-exceeded, and invalid-value failures.
