# CI gate findings, 2026-09-19

Recorded during the Spec 006 landing because the tracker was unavailable. The Dolt
server behind `bd` returned `begin write tx: context canceled` and then
`i/o timeout ... invalid connection` on `127.0.0.1:3308`, so these two findings are
written here to survive the session. File them as beads when the tracker recovers.

## Finding 1: CI never exercises `--all-features`

`.github/workflows/ci.yml` runs three cargo surfaces and none of them enables a
feature:

- `lint` runs `cargo clippy --all-targets -- -D warnings`
- the platform matrix runs `cargo test --workspace --all-targets`
- `dependency-provenance` runs `cargo +1.85.0 build --locked --workspace --all-targets`
  and `cargo +1.85.0 test --workspace --all-targets --locked`

No job passes `--all-features` or `--features test-support`.

This already caused a silent break in this repository. The `matinee-runtime`
test-support targets, `examples/enrollment_lifecycle.rs`,
`tests/enrollment_boundary.rs` and `tests/enrollment_host_budget.rs`, stopped
compiling when `EnrollmentCreation` gained `supported_versions` and
`EnrollmentBinding` gained `version`. At that point
`cargo build --workspace --all-targets --features test-support` exited 101 with 11
errors while CI stayed green. A local gate found it; CI could not.

Proposed fix: add one job, or extend the matrix, to run
`cargo build --workspace --all-targets --all-features` and
`cargo test --workspace --all-targets --all-features --no-fail-fast`, on Linux at
minimum. This change belongs in its own reviewed diff, so the Spec 006 pull request
leaves the workflow's feature coverage as it stands.

Related: `matinee-33l` records that `crates/matinee-runtime/tests/*.rs` are never
`include!`d, so they compile without executing. That is why a compile break was the
only available signal.

## Finding 2: the local verification recipe did not match CI's gate set

Four surfaces sat outside the local gate set. Two of them produced CI failures, Linux
provisioning and the clippy lint gate, and two were caught locally before CI reached
them. The list below marks which is which:

1. Linux. `keyring`'s `linux-native-sync-persistent` feature pulls `libdbus-sys`,
   which needs `libdbus-1-dev`. Every local gate ran on macOS, so all three Ubuntu
   jobs failed at dependency resolution on the first CI run.
2. Pinned toolchain with a locked graph. CI runs
   `cargo +1.85.0 build --locked` and `cargo +1.85.0 test --locked`; the local gates
   used the default toolchain without `--locked` until this was noticed and closed.
3. `--all-features`, as described in finding 1.
4. Clippy. CI runs `cargo clippy --all-targets -- -D warnings`. The local gate set was
   fmt, build, test, the lifecycle example, `cargo deny`, and a symbol-absence check.
   It never ran clippy, so 100-plus dead-code errors on the deliberate platform seams
   were invisible locally.

The clippy error count also differs by toolchain: the default toolchain reported a
different count than pinned 1.85.0 on the same tree, so the pinned run is the
authoritative one.

Proposed practice, extending the retro's IMP-005: enumerate every command CI runs and
run all of them locally before claiming a head is verified, and state the unverified
surfaces explicitly in each handoff rather than listing only what passed.
