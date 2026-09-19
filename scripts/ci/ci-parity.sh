#!/usr/bin/env bash
# Reproduce the runnable CI gates locally, plus the all-features surface.
set -u

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_root" || exit 1

if ! command -v cargo >/dev/null 2>&1 || ! command -v rustup >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: cargo and rustup are required.' >&2
    exit 1
fi

if ! rustup toolchain list | awk '$1 ~ /^1[.]85[.]0([-.]|$)/ { found = 1 } END { exit !found }'; then
    printf '%s\n' 'ERROR: Rust 1.85.0 is not installed. Install it with:' >&2
    printf '%s\n' '  rustup toolchain install 1.85.0 --component clippy --component rustfmt' >&2
    exit 1
fi

if ! rustup component list --toolchain 1.85.0 --installed | awk '$1 ~ /^clippy([-.]|$)/ { clippy = 1 } $1 ~ /^rustfmt([-.]|$)/ { rustfmt = 1 } END { exit !(clippy && rustfmt) }'; then
    printf '%s\n' 'ERROR: Rust 1.85.0 must include clippy and rustfmt. Install them with:' >&2
    printf '%s\n' '  rustup toolchain install 1.85.0 --component clippy --component rustfmt' >&2
    exit 1
fi

if ! command -v mise >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: mise is required for the pinned cargo-deny command.' >&2
    exit 1
fi

# Do not reuse Cargo output from the worktree hook or another checkout.
target_dir=${CARGO_TARGET_DIR:-"$repo_root/.ci-target-$$"}
if [ -e "$target_dir" ]; then
    printf 'ERROR: refusing existing CARGO_TARGET_DIR: %s\n' "$target_dir" >&2
    exit 1
fi
mkdir -p "$target_dir" || exit 1
trap 'rm -rf "$target_dir"' EXIT HUP INT TERM
export CARGO_TARGET_DIR="$target_dir"

failures=0
step=0

run_step() {
    step=$((step + 1))
    label=$1
    shift
    printf '\n[%d] %s\n' "$step" "$label"
    printf '    $'
    printf ' %q' "$@"
    printf '\n'
    log="$target_dir/step-$step.log"
    if "$@" >"$log" 2>&1; then
        cat "$log"
        printf 'PASS: %s\n' "$label"
    else
        status=$?
        cat "$log"
        printf 'FAIL: %s (exit %d)\n' "$label" "$status"
        failures=$((failures + 1))
    fi
    awk '/test result:/ { print "    observed: " $0 }' "$log"
    awk '/test result:/ { passed += $4; failed += $6; seen = 1 } END { if (seen) printf "    aggregate: %d passed; %d failed\n", passed, failed }' "$log"
}

touch_security_lib() {
    touch crates/matinee-security/src/lib.rs
}

printf '%s\n' '=== Local CI gate reproduction ==='
printf '%s\n' 'Host: macOS; Linux and Windows matrix legs are not runnable here.'
printf '%s\n' "CARGO_TARGET_DIR: $CARGO_TARGET_DIR (fresh directory)"
printf '%s\n' 'CI command transcription: lint (fmt, clippy); test matrix (workspace all-targets); dependency-provenance (cargo-deny install, locked build/test, deny version/check).'

run_step 'CI lint: pinned fmt' cargo +1.85.0 fmt --all -- --check
touch_security_lib
run_step 'CI lint: pinned clippy' cargo +1.85.0 clippy --all-targets -- -D warnings

touch_security_lib
run_step 'CI test: pinned workspace all-targets' cargo +1.85.0 test --workspace --all-targets

touch_security_lib
run_step 'CI dependency-provenance: locked workspace build' cargo +1.85.0 build --locked --workspace --all-targets

touch_security_lib
run_step 'CI dependency-provenance: locked workspace test' cargo +1.85.0 test --workspace --all-targets --locked
# CI installs cargo-deny 0.20.2 for the 1.88.0 toolchain, then runs
# `cargo +1.88.0 deny --version` and `cargo +1.88.0 deny check`. cargo-deny is a
# PATH-provided cargo subcommand rather than a toolchain component, so mise
# supplies the pinned 0.20.2 plugin while the invocation itself uses CI's exact
# toolchain selector.
run_step 'CI dependency-provenance: cargo-deny version' mise x cargo:cargo-deny@0.20.2 -- cargo +1.88.0 deny --version
run_step 'CI dependency-provenance: cargo-deny check' mise x cargo:cargo-deny@0.20.2 -- cargo +1.88.0 deny check

printf '\n%s\n' '=== Beyond-CI all-features surface (not part of CI parity) ==='
touch_security_lib
run_step 'Beyond-CI: all-features workspace build' cargo build --workspace --all-targets --all-features

touch_security_lib
run_step 'Beyond-CI: all-features workspace test' cargo test --workspace --all-targets --all-features --no-fail-fast

touch_security_lib
run_step 'Beyond-CI: enrollment lifecycle example' cargo run -p matinee-runtime --features test-support --example enrollment_lifecycle

printf '\n=== Coverage limitations ===\n'
printf '%s\n' 'NOT VERIFIED on this macOS host:'
printf '%s\n' '  - CI test matrix ubuntu-latest leg'
printf '%s\n' '  - CI test matrix windows-latest leg'
printf '%s\n' '  - libdbus-1-dev provisioning in all Ubuntu jobs'
printf '%s\n' 'A green run therefore does not imply full CI parity.'

if [ "$failures" -ne 0 ]; then
    printf '\nFAIL: %d command(s) failed.\n' "$failures" >&2
    exit 1
fi
printf '\nPASS: all runnable CI and beyond-CI commands completed.\n'
