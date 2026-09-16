# Research: Runtime Foundation

## Staged workspace shape

**Decision**: Convert the repository to a virtual Cargo workspace with two implemented
members: the published `matinee` CLI package under `crates/matinee-cli/` and a private
`matinee-runtime` library under `crates/matinee-runtime/`. Later specifications add
`matinee-domain`, `matinee-protocol`, `matinee-store`, and `matinee-daemon` only when
those crates contain complete behavior.

`matinee-runtime` owns one deep interface for resolving the local runtime environment.
It hides configuration parsing, source policy, platform directories, path identity,
and host access. The CLI preserves browser checks and delegates host operations through
runtime interfaces.

**Rationale**: This shape gives the CLI and future daemon one environment resolver
without creating empty crates or exposing future process modes. It refines the five-crate
outline in spec 001's plan; spec 001's product contracts remain unchanged.

**Alternatives considered**:

- Create every final crate in this slice. Empty protocol, store, and daemon crates would
  be placeholder implementations.
- Keep one crate until daemon work begins. Configuration and platform behavior would
  remain entangled with command dispatch and require a larger later move.
- Put environment resolution in the domain crate. Filesystem and operating-system access
  would violate the domain crate's pure dependency rule.

## Configuration parser and merge policy

**Decision**: Parse user and project files as TOML with `toml` 1.1.x and derived
`serde` 1.x types. Implement the five-layer merge in `matinee-runtime` rather than
adopting a general configuration framework. Each known key has one descriptor that
records its parser, default, permitted sources, and sensitivity. Reject duplicate and
unknown keys before merging.

**Rationale**: Matinee has a small, security-sensitive key set. A local resolver can
preserve exact provenance and enforce source permissions before values enter product
state. `toml` 1.1.6 declares Rust 1.85 compatibility.

The resolver reads no more than 1 MiB from one file. It accepts at most 100 known keys,
four dotted-key segments, and 4,096 Unicode scalar values in one text value. On
Windows, it normalizes environment-name case before mapping names to keys.

**Alternatives considered**:

- A general configuration framework reduces merge code but exposes more source behavior
  than Matinee permits and makes exact provenance harder to audit.
- Ignoring unknown keys improves forward compatibility but hides typos and unsupported
  security settings.
- JSON lacks the existing `config.toml` and `matinee.toml` contract from spec 001.

## Platform directory discovery

**Decision**: Use `directories` 6.x `BaseDirs` only to discover operating-system base
locations. Append Matinee-specific paths in one policy module so results match spec
001's CLI contract. Do not use `ProjectDirs`, because its macOS and Windows naming
rules do not produce the contracted paths.

Derived locations are:

| Platform | Config | State | Runtime | Cache | Logs |
|---|---|---|---|---|---|
| macOS | `~/Library/Application Support/Matinee` | config directory plus `state` | state plus `run` | `~/Library/Caches/Matinee` | `~/Library/Logs/Matinee` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/matinee` | `${XDG_STATE_HOME:-~/.local/state}/matinee` | `${XDG_RUNTIME_DIR}/matinee` or state plus `run` | `${XDG_CACHE_HOME:-~/.cache}/matinee` | state plus `logs` |
| Windows | `%APPDATA%\Matinee` | `%LOCALAPPDATA%\Matinee\state` | state plus `run` | `%LOCALAPPDATA%\Matinee\cache` | state plus `logs` |

**Rationale**: The library uses the platform APIs and XDG rules needed to locate base
directories. Matinee retains control of its stable path contract.

**Alternatives considered**:

- `ProjectDirs` adds qualifier and organization naming on macOS and Windows that differs
  from spec 001.
- Reading only environment variables fails to use Windows Known Folder APIs.
- Hand-written platform discovery duplicates mature operating-system integration.

## Minimum Rust compatibility

**Decision**: Pin the selected dependency versions in `Cargo.lock` and compile the full
workspace with Rust 1.85 before accepting them. `toml` 1.1.6 declares Rust 1.85.
`directories` 6.0.0 does not declare a Rust version in its packaged manifest, so its
compatibility requires an executable gate rather than an assumption.

**Rationale**: The constitution fixes the minimum compiler. Dependency metadata alone
does not prove that every transitive dependency supports it.

## Root identity and path safety

**Decision**: Resolve each path against an explicit base and normalize lexical `.` and
`..` segments. Identify the longest existing ancestor with the platform's stable file
identity. Interpret the missing tail with that filesystem's case and Unicode semantics.

Before Matinee reads an implicit project file, it verifies root containment and records
the file identity, type, length, and change marker. It rejects symbolic links for the
implicit file and rechecks the snapshot after reading. An active same-user attacker who
can replace files during these checks remains outside the local threat model.

**Rationale**: `std::fs::canonicalize` fails for a state root that does not exist yet.
Text normalization also mishandles aliases and platform case rules. The anchor identity
and comparison tail represent existing and future path segments without creating them.

**Alternatives considered**:

- Canonicalize the complete path. A first-run state root does not exist.
- Normalize only text segments. Existing symbolic links can escape a project root or
  create two identities for one state root.
- Create paths during resolution. Invalid configuration would mutate the filesystem.

## CLI preservation

**Decision**: Move the current parser and browser checks while preserving usage, help,
doctor text, output streams, and exit behavior. Version output retains its format and
uses the current package version. Do not introduce a command framework in this slice.
The CLI calls a small dispatch function for later complete modes.

**Rationale**: A command framework can change generated help and parse errors. Spec 005
requires the released contract and does not yet need a larger public surface.

**Alternatives considered**:

- Adopt `clap` now. Its generated output would require a public CLI contract change owned
  by a later specification.
- Register future commands as stubs. The constitution prohibits placeholder surfaces.

## Verification strategy

**Decision**: Use table-driven Rust tests for precedence, source permissions, path
fixtures, and released CLI cases. Test host-independent directory rules through an
injected platform description. Run the same library contract against the production
host adapter and a deterministic test adapter.

**Rationale**: The risky behavior is a finite policy matrix. Table-driven cases make
missing sources and protected keys visible without a property-test dependency.

**Alternatives considered**:

- Snapshot every structure. Snapshots would pin representation instead of behavior.
- Test only the host platform. Linux CI would not exercise macOS or Windows policy.
