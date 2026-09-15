# Implementation Plan: Runtime Foundation

**Branch**: `005-runtime-foundation` | **Date**: 2026-09-11 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/005-runtime-foundation/spec.md`

## Summary

Preserve Matinee 0.0.2 CLI behavior while introducing one private runtime library that
resolves configuration, platform directories, and canonical state-root identity. Move
the published binary into a virtual Cargo workspace without adding unfinished daemon,
MCP, extension, or workflow surfaces.

## Technical Context

**Language/Version**: Rust 2024 edition with minimum Rust 1.85

**Primary Dependencies**: `serde` 1.x with derive, `toml` 1.1.x, and `directories` 6.x;
`tempfile` 3.x for tests

**Storage**: TOML user and project configuration files; no product-state writes in this
feature

**Testing**: Rust unit and integration tests, table-driven configuration matrices,
bounded lexical-preflight attack cases, closed diagnostic-schema cases, platform
directory fixtures, lock-identity collision fixtures, filesystem isolation tests, and
retained CLI behavior tests

**Target Platform**: macOS, Linux desktop, and Windows desktop

**Project Type**: Cargo workspace with one published CLI crate and one private runtime
library crate

**Performance Goals**: Record 30 interleaved pairs of 0.0.2 and feature-branch cold and
warm CLI startup measurements plus 30 cold and warm environment-resolution measurements.
`validation.md` records the commands, platform/toolchain fingerprint, raw durations,
median, p95, and coefficient of variation. The spec 005 acceptance owner sets a numeric
regression threshold only after reviewing that variance; absent a defensible threshold,
any observed regression blocks publication and triggers rollback review.

**Constraints**:

- Rust 1.85 compatibility
- no product-state mutation during environment resolution
- no public Rust library stability commitment
- 0.0.2-compatible CLI text, streams, and exit classes, except for the current
  package-version value
- no placeholder commands or crates

**Scale/Scope**: Five configuration layers, up to 100 registered keys, one user file,
one project file, and one state-root identity per resolution attempt

## Constitution Check

### Pre-Design Gate

- **I. Human Authority -- PASS**: Project and environment sources cannot select protected
  settings or weaken approval policy.
- **II. Visible Browser Ownership -- PASS**: The plan preserves existing browser checks
  but introduces no browser-control surface.
- **III. Durable Local State -- PASS**: Environment resolution performs no writes and
  produces one canonical identity for future single-writer state.
- **IV. Least Privilege -- PASS**: The resolver rejects unsafe project paths, protected
  lower-trust values, unknown keys, and sensitive diagnostic output.
- **V. Observable Contracts -- PASS**: Configuration sources, failure codes, paths,
  output streams, and exit behavior have explicit contracts.
- **Delivery Gates -- PASS**: Tests cover source policy, path escapes, host failures,
  platform fixtures, and the released CLI baseline. The plan creates no placeholder
  surface.

### Post-Design Gate

- [data-model.md](data-model.md) defines configuration provenance and the resolution
  state machine.
- [contracts/configuration.md](contracts/configuration.md) defines paths, source policy,
  merge results, and failures.
- [quickstart.md](quickstart.md) provides CLI, configuration, isolation, and architecture
  acceptance commands.
- No constitution exception is required.

## Project Structure

### Documentation

```text
specs/005-runtime-foundation/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── checklists/
│   ├── requirements.md
│   └── foundation.md
├── validation.md                # generated acceptance evidence
└── contracts/
    └── configuration.md
```

### Source Code

```text
Cargo.toml
crates/
├── matinee-cli/
│   ├── Cargo.toml
│   ├── src/
│   │   ├── doctor.rs
│   │   ├── dispatch.rs
│   │   └── main.rs
│   └── tests/
│       └── released_cli.rs
└── matinee-runtime/
    ├── Cargo.toml
    ├── src/
    │   ├── config.rs
    │   ├── environment.rs
    │   ├── error.rs
    │   ├── path_identity.rs
    │   ├── platform.rs
    │   └── lib.rs
    └── tests/
        ├── configuration_contract.rs
        └── environment_contract.rs
```

**Structure Decision**: The workspace contains only crates with complete behavior in
this feature. `matinee-runtime` is private and owns environment resolution behind one
interface. `matinee-cli` remains the published `matinee` package and preserves the
released binary surface.

This plan supersedes only the five-crate repository layout proposed in spec 001's plan.
Spec 001's product behavior, state machines, and external contracts remain normative.
When specs 006-015 deliver their assigned behavior, they add the domain, protocol,
store, daemon, and extension implementations. Spec 016 owns packaging, installation,
release, and upgrade behavior and adds no product crate.

## Dependency Rules

1. `matinee-runtime` depends on `serde`, `toml`, and `directories`. It does not depend on
   CLI, daemon, storage, protocol, MCP, or browser code.
2. `matinee-cli` depends on `matinee-runtime`. Runtime code never depends on the CLI.
3. Host access enters runtime logic through one platform interface. Production and test
   adapters satisfy the same contract.
4. Configuration key descriptors are the only registry of accepted keys and permitted
   sources.
5. Command dispatch cannot register a mode until its owning specification implements the
   complete public behavior.

## Implementation Sequence

### Stage 1 - Preserve the baseline

- Move the published package to `crates/matinee-cli/` and create the virtual workspace.
- Split command dispatch and browser checks without changing public text or exit codes.
- Add behavior tests for help, version, doctor success, doctor failure, and invalid
  invocation.
- Exit condition: every 0.0.2 CLI acceptance case passes on Rust 1.85.

### Stage 2 - Resolve configuration

- Implement typed key descriptors and the closed descriptor material-class policy.
- Enforce the 1 MiB byte bound, then run the bounded TOML-aware lexical preflight before
  typed deserialization; reject duplicate, excessive, and pathological input there.
- After preflight, parse typed TOML and look up each descriptor before merge.
- For each parsed assignment, validate descriptor presence, material class, source
  permission, then value type and normalization. Reject the first failure.
- Normalize environment names with platform semantics before duplicate checks.
- Render every failure through the closed four-field redacted schema.
- Add the complete configuration contract matrix, including exact-limit, one-over-limit,
  pathological 1 MiB, secret-class, and raw-disclosure negative cases.
- Exit condition: every source, precedence pair, input limit, and protected setting has
  one passing or rejected case.

### Stage 3 - Resolve platform paths

- Implement host base-directory discovery and deterministic platform fixtures.
- Define path identity from a platform file identity and the comparison semantics of
  its existing ancestor.
- Define lock identity as the exact canonical root identity, without hashing or
  truncation; prove alias convergence and pairwise distinction for distinct roots.
- Validate project containment before read. Snapshot implicit project files before
  opening and recheck identity after reading.
- Prove resolution does not create files or directories.
- Exit condition: platform, case, alias, lock non-collision, escape, replacement,
  missing-directory, and isolation cases pass.

### Stage 4 - Integrate and gate

- Route CLI host access through the runtime interface while preserving its public
  behavior.
- Add Ubuntu, macOS, and Windows CI jobs for the platform contract fixtures.
- Add a Rust 1.85 job that compiles every selected direct and transitive dependency and
  records the `Cargo.lock` checksum, locked dependency tree, declared licenses, and
  advisory scan result in `validation.md`.
- Record the specified interleaved CLI and resolver baselines, repeat counts, variance,
  and threshold decision in `validation.md`.
- Run workspace formatting, linting, tests, and the quickstart.
- Map every functional requirement, success criterion, and security task to an exact
  command or scenario and observed outcome.
- Confirm help exposes no command owned by specs 006-016.
- Preserve the 0.0.2 comparison artifact. If the workspace or package move regresses the
  released contract or lacks an accepted performance threshold, the release owner blocks
  publication and reverts the package/workspace move before retrying.
- Exit condition: every success criterion has recorded evidence and no constitution
  exception remains.

## Complexity Tracking

No constitution violation requires an exception.
