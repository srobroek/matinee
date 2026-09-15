# Quickstart: Validate Runtime Foundation

## Prerequisites

- Rust 1.85 toolchain with `rustfmt` and `clippy`
- One supported desktop platform or platform fixtures from the repository

## Validate the released CLI baseline

```sh
cargo run -p matinee -- --help
cargo run -p matinee -- --version
cargo run -p matinee -- doctor
```

Expected results:

- Help lists only `doctor` and `help`.
- Version prints `matinee` followed by the package version.
- Doctor prints detection-only Firefox and Google Chrome rows; this feature exposes no Firefox automation or control.
- Doctor exits successfully when at least one browser exists.
- Doctor exits with code 1 when neither browser exists.
- Invalid invocation exits with code 2 and writes its diagnostic to standard error.

## Validate configuration policy

```sh
cargo test -p matinee-runtime --test configuration_contract
```

The matrix covers precedence, protected sources, duplicate and unknown keys, Windows
environment-name collisions, descriptor material classes, and malformed values. It
exercises exact and one-over limits plus syntactically pathological 1 MiB inputs before
typed deserialization. Every failure asserts the closed code, static summary, redacted
source, and static next action and proves that raw operating-system errors, paths, input
values, and rejected secret material are absent. Each rejected case leaves its temporary
root empty.

## Validate platform paths and isolation

```sh
cargo test -p matinee-runtime --test environment_contract
```

The test exercises macOS, Linux, and Windows directory fixtures. It covers one hundred
distinct roots, platform-equivalent paths, supported symbolic links, project escapes,
and project-file replacement during a read. Equivalent roots must produce the same exact
lock identity; every pair of distinct canonical roots must produce distinct lock
identities without hashing or truncation.

## Validate the architecture gate

```sh
cargo +1.85.0 test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

The CI workflow repeats the platform contract fixtures on Ubuntu, macOS, and Windows.
The Rust 1.85 job proves direct and transitive dependency compatibility.

The acceptance record also preserves the `Cargo.lock` checksum, locked dependency tree,
declared licenses, advisory scan result, and 30-run cold/warm CLI and resolver measurement
sets with raw durations, median, p95, coefficient of variation, and the release owner's
threshold decision.

The workspace contains only implemented crates. No user-visible command assigned to
specs 006-016 appears in help output.
