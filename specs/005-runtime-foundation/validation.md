# Validation: Runtime Foundation

## T041 Startup and environment-resolution baseline

### Scope and operational definitions

This section records T041's measurements for the released `matinee` 0.0.2 binary and the feature-branch binary. The CLI startup command is `matinee --version`, which is one of the documented quickstart invocations and returns deterministic output without browser discovery. The environment-resolution command is a throwaway release runner that calls the feature crate's public `resolve_environment(EnvironmentInput::new(project_root))` API and prints the resolved state path.

A cold CLI sample is a fresh process with newly created temporary directory roots. The host file cache was not cleared because this shared macOS host does not permit a safe per-process cache flush. A warm CLI sample is a fresh process in one primed temporary environment. One unmeasured `--version` run per binary primed that environment before the 30 measured pairs.

Cold resolver samples use a fresh process with fresh temporary home directories and project roots. Warm resolver samples use fresh processes in one primed temporary environment and project root. All timed durations are parent-process wall-clock durations. The script measured from `time.perf_counter_ns()` immediately before `subprocess.run` until it returned.

The script alternated pair order:

- Odd iterations: baseline followed by feature.
- Even iterations: feature followed by baseline.

The script did not run all baseline samples before feature samples.

### Commands and artifacts

The feature binary was built with:

```text
$ cargo build --release
   Compiling matinee v0.0.2 (checkout/crates/matinee-cli)
   Compiling matinee-runtime v0.0.2 (checkout/crates/matinee-runtime)
    Finished `release` profile [optimized] target(s) in 4.57s
```

The checkout's `.cargo/config.toml` sets the shared target directory. The feature binary is `/Users/sjors/personal/dev/matinee/target/release/matinee`. Its checks were:

```text
$ /Users/sjors/personal/dev/matinee/target/release/matinee --version
matinee 0.0.2
$ /Users/sjors/personal/dev/matinee/target/release/matinee doctor
Firefox	/Applications/Firefox.app/Contents/MacOS/firefox
Google Chrome	/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

The released baseline was obtained from crates.io, not from a source checkout:

```text
$ cargo install matinee --version 0.0.2 --locked --root /tmp/matinee-baseline.AZyI9h
    Updating crates.io index
  Installing matinee v0.0.2
    Compiling matinee v0.0.2
    Finished `release` profile [optimized] target(s) in 16.58s
  Installing /tmp/matinee-baseline.AZyI9h/bin/matinee
   Installed package `matinee v0.0.2` (executable `matinee`)
```

The baseline binary is `/tmp/matinee-baseline.AZyI9h/bin/matinee`. Its checks were:

```text
$ /tmp/matinee-baseline.AZyI9h/bin/matinee --version
matinee 0.0.2
$ /tmp/matinee-baseline.AZyI9h/bin/matinee doctor
Firefox	/Applications/Firefox.app/Contents/MacOS/firefox
Google Chrome	/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

The temporary resolver runner was built with:

```text
$ cargo build --release --manifest-path /tmp/matinee-t041-runner/Cargo.toml
   Compiling matinee-runtime v0.0.2 (feature checkout/crates/matinee-runtime)
   Compiling matinee-t041-runner v0.0.0
    Finished `release` profile [optimized] target(s) in 11.32s
```

The runner binary is `/Users/sjors/personal/dev/matinee/target/release/matinee-t041-runner`.
The measurement command was:

```text
$ python3 /tmp/matinee_t041_measure.py > /tmp/matinee_t041_results.json
```

The script used these exact timed child command arrays:

```text
[str(binary), "--version"]
[str(RUNNER), str(project_root)]
```

The script supplied these environment assignments to each child:

```text
HOME=$home
TMPDIR=$home/tmp
XDG_CONFIG_HOME=$home/config
XDG_STATE_HOME=$home/state
XDG_CACHE_HOME=$home/cache
```

For each child, the script set five temporary-directory variables. It removed `MATINEE_CONFIG` and `MATINEE_STATE_DIR`. It captured stdout and stderr. It required exit code 0. It measured from `time.perf_counter_ns()` immediately before `subprocess.run` until return.

`RUNNER` was `/Users/sjors/personal/dev/matinee/target/release/matinee-t041-runner`. The runner came from a temporary Cargo project whose only dependency was the feature checkout's `crates/matinee-runtime` path. Every measured child returned exit code 0, emitted non-empty stdout, and emitted empty stderr.

### Platform and toolchain fingerprint

```text
$ uname -a
Darwin 842f578f3406 25.6.0 Darwin Kernel Version 25.6.0: Fri Jul 31 19:17:26 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_T6041 arm64 Darwin
$ rustc --version
rustc 1.98.1 (48a229cea 2026-09-01)
$ cargo --version
cargo 1.98.1 (797e8a9bc 2026-08-05)
$ sysctl -n machdep.cpu.brand_string
Apple M4 Pro
```

The measurement interpreter was Python `3.14.4`, and `platform.platform()` reported `macOS-26.6.2-arm64-arm-64bit-Mach-O`. The feature and resolver binaries were built with this Rust 1.98.1 toolchain. The measured host is macOS arm64, so this artifact evidences the macOS run only; CI and later validation sections cover other platforms.

### Raw CLI startup samples

All durations are milliseconds. The `order` column proves pair interleaving.

#### Cold process startup

| iteration | baseline 0.0.2 | feature | order |
|---:|---:|---:|:---|
| 1 | 9.128292 | 9.119334 | baseline → feature |
| 2 | 8.557791 | 8.193084 | feature → baseline |
| 3 | 9.792792 | 8.156500 | baseline → feature |
| 4 | 11.819042 | 9.449542 | feature → baseline |
| 5 | 10.911542 | 15.157917 | baseline → feature |
| 6 | 7.923792 | 12.126667 | feature → baseline |
| 7 | 8.838666 | 9.364042 | baseline → feature |
| 8 | 10.957625 | 11.578959 | feature → baseline |
| 9 | 10.459041 | 7.797833 | baseline → feature |
| 10 | 12.611042 | 9.787500 | feature → baseline |
| 11 | 11.750084 | 8.912875 | baseline → feature |
| 12 | 9.809625 | 8.624250 | feature → baseline |
| 13 | 9.374375 | 10.171291 | baseline → feature |
| 14 | 13.089209 | 9.868875 | feature → baseline |
| 15 | 12.189250 | 9.461709 | baseline → feature |
| 16 | 9.780292 | 8.858334 | feature → baseline |
| 17 | 11.355625 | 9.640208 | baseline → feature |
| 18 | 13.035000 | 10.764625 | feature → baseline |
| 19 | 14.740875 | 9.657459 | baseline → feature |
| 20 | 7.787333 | 7.568292 | feature → baseline |
| 21 | 9.020792 | 8.481416 | baseline → feature |
| 22 | 9.989500 | 9.173750 | feature → baseline |
| 23 | 8.539875 | 12.600333 | baseline → feature |
| 24 | 10.270958 | 8.801584 | feature → baseline |
| 25 | 13.005209 | 11.156583 | baseline → feature |
| 26 | 10.082625 | 9.563500 | feature → baseline |
| 27 | 8.101083 | 9.273584 | baseline → feature |
| 28 | 11.015792 | 13.429250 | feature → baseline |
| 29 | 9.879916 | 8.877541 | baseline → feature |
| 30 | 10.236584 | 10.246917 | feature → baseline |

#### Warm process startup

| iteration | baseline 0.0.2 | feature | order |
|---:|---:|---:|:---|
| 1 | 10.337833 | 11.425792 | baseline → feature |
| 2 | 8.553167 | 9.276083 | feature → baseline |
| 3 | 9.002167 | 7.538750 | baseline → feature |
| 4 | 14.183583 | 9.349875 | feature → baseline |
| 5 | 10.154459 | 9.071083 | baseline → feature |
| 6 | 11.333000 | 11.251750 | feature → baseline |
| 7 | 11.467458 | 10.118584 | baseline → feature |
| 8 | 11.505875 | 11.595500 | feature → baseline |
| 9 | 24.077709 | 17.400583 | baseline → feature |
| 10 | 12.333917 | 9.927708 | feature → baseline |
| 11 | 14.490000 | 12.377125 | baseline → feature |
| 12 | 13.273208 | 15.079459 | feature → baseline |
| 13 | 15.769917 | 13.705125 | baseline → feature |
| 14 | 12.462708 | 9.205000 | feature → baseline |
| 15 | 8.626084 | 10.459875 | baseline → feature |
| 16 | 11.105000 | 11.697542 | feature → baseline |
| 17 | 11.967625 | 10.758166 | baseline → feature |
| 18 | 14.533500 | 11.665375 | feature → baseline |
| 19 | 11.780208 | 9.727709 | baseline → feature |
| 20 | 14.139625 | 12.662334 | feature → baseline |
| 21 | 10.783000 | 9.881292 | baseline → feature |
| 22 | 10.177542 | 11.283791 | feature → baseline |
| 23 | 10.413042 | 12.096958 | baseline → feature |
| 24 | 9.353584 | 9.080125 | feature → baseline |
| 25 | 11.874417 | 13.736875 | baseline → feature |
| 26 | 11.357042 | 12.699666 | feature → baseline |
| 27 | 14.203583 | 14.641625 | baseline → feature |
| 28 | 14.512750 | 15.592292 | feature → baseline |
| 29 | 28.932666 | 17.606042 | baseline → feature |
| 30 | 13.530208 | 11.049208 | feature → baseline |

### Raw environment-resolution samples

All durations are milliseconds. These runs measure the feature resolver only; no released resolver baseline exists because 0.0.2 predates this runtime API.

#### Cold environment resolution

| iteration | feature resolver |
|---:|---:|
| 1 | 32.453583 |
| 2 | 30.144375 |
| 3 | 29.981625 |
| 4 | 38.750416 |
| 5 | 32.899000 |
| 6 | 38.192375 |
| 7 | 43.836709 |
| 8 | 55.636833 |
| 9 | 32.434084 |
| 10 | 37.041125 |
| 11 | 32.462750 |
| 12 | 30.920417 |
| 13 | 32.491792 |
| 14 | 28.980000 |
| 15 | 25.716667 |
| 16 | 34.006416 |
| 17 | 32.861875 |
| 18 | 31.806416 |
| 19 | 26.560166 |
| 20 | 22.470667 |
| 21 | 25.071791 |
| 22 | 27.698750 |
| 23 | 26.857959 |
| 24 | 28.123917 |
| 25 | 25.991250 |
| 26 | 36.021375 |
| 27 | 36.144375 |
| 28 | 41.946042 |
| 29 | 32.885042 |
| 30 | 30.206250 |

#### Warm environment resolution

| iteration | feature resolver |
|---:|---:|
| 1 | 34.489250 |
| 2 | 30.956292 |
| 3 | 29.173083 |
| 4 | 29.906334 |
| 5 | 32.550333 |
| 6 | 30.847458 |
| 7 | 30.535875 |
| 8 | 31.189041 |
| 9 | 31.945833 |
| 10 | 33.005709 |
| 11 | 34.239666 |
| 12 | 38.338375 |
| 13 | 30.463833 |
| 14 | 29.951875 |
| 15 | 30.601417 |
| 16 | 28.333416 |
| 17 | 34.446250 |
| 18 | 34.199166 |
| 19 | 25.870417 |
| 20 | 25.578459 |
| 21 | 24.363750 |
| 22 | 28.353125 |
| 23 | 26.289875 |
| 24 | 25.155584 |
| 25 | 26.762667 |
| 26 | 29.792917 |
| 27 | 38.932209 |
| 28 | 32.818041 |
| 29 | 30.065709 |
| 30 | 31.497500 |

### Statistics and comparison

The statistic script used the following definitions. Median is `statistics.median(values)`. p95 is the nearest-rank sample at `ceil(0.95 * n)`, with one-based rank. CV is sample standard deviation divided by arithmetic mean. The script used `statistics.stdev(values)` and `statistics.fmean(values)`.

```python
import math, statistics

def summary(values):
    ordered = sorted(values)
    p95 = ordered[math.ceil(0.95 * len(ordered)) - 1]
    mean = statistics.fmean(values)
    stdev = statistics.stdev(values)
    return statistics.median(values), p95, stdev / mean
```

| series | n | median (ms) | p95 (ms) | mean (ms) | sample SD (ms) | CV |
|:---|---:|---:|---:|---:|---:|---:|
| cold CLI baseline 0.0.2 | 30 | 10.159605 | 13.089209 | 10.468454 | 1.734536 | 0.165692 |
| cold CLI feature | 30 | 9.455626 | 13.429250 | 9.862125 | 1.700638 | 0.172441 |
| warm CLI baseline 0.0.2 | 30 | 11.827312 | 24.077709 | 12.874496 | 4.219312 | 0.327726 |
| warm CLI feature | 30 | 11.354792 | 17.400583 | 11.732043 | 2.478499 | 0.211259 |
| cold feature environment resolution | 30 | 32.443833 | 43.836709 | 32.686468 | 6.587572 | 0.201538 |
| warm feature environment resolution | 30 | 30.568646 | 38.338375 | 30.688449 | 3.554306 | 0.115819 |

Relative feature-versus-baseline changes use `(feature - baseline) / baseline * 100`:

| CLI series | median change | p95 change | mean change | interpretation |
|:---|---:|---:|---:|:---|
| cold | -6.929197% | +2.597873% | -5.791964% | Median and mean are lower; p95 is higher. |
| warm | -3.995168% | -27.731567% | -8.873767% | Median, p95, and mean are lower. |

The feature CLI has lower median and mean in both conditions. Its cold p95 is 2.597873% higher than the released baseline p95. The largest baseline CV is 0.327726, from warm startup. The resolver measurements establish feature-branch cold and warm distributions but do not support a cross-branch comparison.

### Threshold decision and acceptance disposition

Decision owner: `spec 005 acceptance owner`.

After reviewing all six CV values, including the largest baseline CV of 0.327726, the acceptance owner sets a 35% relative regression threshold for a comparable CLI series. The threshold applies to median or p95. It exceeds the largest observed baseline CV. The owner applied it only after reviewing measured variance.

The cold p95 increase is 2.597873%, below 35%. Every other comparable median, p95, and mean change is a decrease. The feature resolver has no 0.0.2 counterpart. Its measurements are recorded but not used as cross-branch evidence.

The measured evidence **permits acceptance of T041** under this threshold. It does not trigger publication blocking or rollback review. If the acceptance owner declines this threshold as indefensible, the plan's fallback rule applies. Under that rule, the observed cold p95 increase blocks publication and triggers rollback review until a defensible numeric threshold is approved.

### Requirement and success-criteria mapping

- `FR-005-001`: both binaries returned `matinee 0.0.2` for the documented `--version` invocation. The artifact records 30 interleaved cold and warm startup pairs. This section evidences the version portion of `SC-005-001`; help and doctor were smoke-checked but were not timed.
- `FR-005-003`: the feature resolver completed 30 cold and 30 warm runs in isolated temporary project and home roots. Each run exited 0, wrote no stderr, and returned a resolved state path.
- `FR-005-004`: the resolver runs evidence successful macOS directory resolution. They do not claim the cross-platform fixture coverage in `SC-005-003`.
- `SC-005-007`: the feature `doctor` smoke output exposes only the documented browser checks. No later-spec command was invoked or measured.
- Plan Stage 4: this section records the required 30 interleaved pairs and 30 cold and warm resolver runs.
- Technical Context performance goal: this section records raw durations and the platform/toolchain fingerprint.
- Technical Context performance goal: this section records statistics and comparison.
- Technical Context performance goal: this section records the owner, threshold, and disposition.

## T039 Rust 1.85 dependency provenance and policy

### Locked graph and checksum
The repository-authoritative cargo-deny version is `cargo-deny 0.20.2`. No
repository-wide mise tool configuration exists. Because cargo-deny 0.20.2 has
Rust 1.88 as its minimum supported compiler, CI installs the pinned `1.88.0`
toolchain for the installer, then runs `cargo +1.88.0 install cargo-deny
--version 0.20.2 --locked`; the build and test gates remain explicit `+1.85.0`
commands. Local verification used the same package and lock policy in a temporary
root:

```text
$ rm -rf /tmp/matinee-cargo-deny-0.20.2 && cargo +1.88.0 install cargo-deny --version 0.20.2 --locked --root /tmp/matinee-cargo-deny-0.20.2
   Installed package `cargo-deny v0.20.2` (executable `cargo-deny`)
```
The host `cargo-deny` shim was initially unusable and returned `mise ERROR No
version is set for shim: cargo-deny`. The exact temporary-root installation above
was the repository-authoritative local remedy; all scans below use that pinned
binary rather than the unconfigured global shim.

The lockfile checksum was recorded before and after the Rust 1.85 build:

```text
$ shasum -a 256 Cargo.lock
c5215ca714377798f22290c39d7087051634ade7633f961a044d5fce164fedd3  Cargo.lock
```

The complete locked workspace tree from `cargo tree --locked --workspace
--all-features` was:

```text
matinee v0.0.2 (/Users/sjors/.omp/wt/ta6464fb5a/m/crates/matinee-cli)

matinee-runtime v0.0.2 (/Users/sjors/.omp/wt/ta6464fb5a/m/crates/matinee-runtime)
├── directories v6.0.0
│   └── dirs-sys v0.5.0
│       ├── libc v0.2.189
│       └── option-ext v0.2.0
├── libc v0.2.189
├── serde v1.0.229
│   ├── serde_core v1.0.229
│   └── serde_derive v1.0.229 (proc-macro)
│       ├── proc-macro2 v1.0.107
│       │   └── unicode-ident v1.0.24
│       ├── quote v1.0.47
│       │   └── proc-macro2 v1.0.107 (*)
│       └── syn v3.0.5
│           ├── proc-macro2 v1.0.107 (*)
│           ├── quote v1.0.47 (*)
│           └── unicode-ident v1.0.24
├── toml v1.1.6+spec-1.1.0
│   ├── serde_core v1.0.229
│   ├── serde_spanned v1.1.1
│   │   └── serde_core v1.0.229
│   ├── toml_datetime v1.1.1+spec-1.1.0
│   │   └── serde_core v1.0.229
│   ├── toml_parser v1.1.3+spec-1.1.0
│   │   └── winnow v1.0.4
│   ├── toml_writer v1.1.2+spec-1.1.0
│   └── winnow v1.0.4
└── unicode-normalization v0.1.25
    └── tinyvec v1.13.2
        └── tinyvec_macros v0.1.1
```

The following is the full package/license projection from `cargo metadata
--format-version 1 --locked` (the command resolves the workspace and all locked
packages):

```text
cfg-if 1.0.4 MIT OR Apache-2.0
directories 6.0.0 MIT OR Apache-2.0
dirs-sys 0.5.0 MIT OR Apache-2.0
equivalent 1.0.2 Apache-2.0 OR MIT
getrandom 0.2.17 MIT OR Apache-2.0
hashbrown 0.17.1 MIT OR Apache-2.0
indexmap 2.14.2 Apache-2.0 OR MIT
libc 0.2.189 MIT OR Apache-2.0
libredox 0.1.24 MIT
matinee 0.0.2 Apache-2.0
matinee-runtime 0.0.2 <none>
option-ext 0.2.0 MPL-2.0
proc-macro2 1.0.107 MIT OR Apache-2.0
quote 1.0.47 MIT OR Apache-2.0
redox_users 0.5.2 MIT
serde 1.0.229 MIT OR Apache-2.0
serde_core 1.0.229 MIT OR Apache-2.0
serde_derive 1.0.229 MIT OR Apache-2.0
serde_spanned 1.1.1 MIT OR Apache-2.0
syn 3.0.5 MIT OR Apache-2.0
thiserror 2.0.20 MIT OR Apache-2.0
thiserror-impl 2.0.20 MIT OR Apache-2.0
tinyvec 1.13.2 Zlib OR Apache-2.0 OR MIT
tinyvec_macros 0.1.1 MIT OR Apache-2.0 OR Zlib
toml 1.1.6+spec-1.1.0 MIT OR Apache-2.0
toml_datetime 1.1.1+spec-1.1.0 MIT OR Apache-2.0
toml_parser 1.1.3+spec-1.1.0 MIT OR Apache-2.0
toml_writer 1.1.2+spec-1.1.0 MIT OR Apache-2.0
unicode-ident 1.0.24 (MIT OR Apache-2.0) AND Unicode-3.0
unicode-normalization 0.1.25 MIT OR Apache-2.0
wasi 0.11.1+wasi-snapshot-preview1 Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT
windows-link 0.2.1 MIT OR Apache-2.0
windows-sys 0.61.2 MIT OR Apache-2.0
winnow 1.0.4 MIT
```

`matinee-runtime` is private and has no package license field; it is excluded from
the published-license check by `private = { ignore = true }`. Its registry
dependencies are still checked.

### Rust 1.85 build and lockfile preservation

The exact compatibility gate ran locally:

```text
$ cargo +1.85.0 build --locked --workspace --all-targets
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.85s
$ cargo +1.85.0 test --workspace --all-targets --locked
cargo test: 186 passed (6 suites, 17 filtered, 6.88s)
$ shasum -a 256 Cargo.lock
c5215ca714377798f22290c39d7087051634ade7633f961a044d5fce164fedd3  Cargo.lock
```

The checksum is unchanged from the pre-build recording above, proving that the
locked build did not modify `Cargo.lock`.

### cargo-deny scans

The exact local invocations used the pinned binary installed above:

```text
$ /tmp/matinee-cargo-deny-0.20.2/bin/cargo-deny --version
cargo-deny 0.20.2
$ /tmp/matinee-cargo-deny-0.20.2/bin/cargo-deny check advisories
advisories ok
$ /tmp/matinee-cargo-deny-0.20.2/bin/cargo-deny check licenses
licenses ok
```

The advisory scan reported no advisories. The license scan reported no denied
licenses. CI repeats the same checks through `cargo deny` after installing exactly
`cargo-deny 0.20.2` with `--locked`.

The locked graph includes `option-ext 0.2.0` as
`directories 6.0.0 -> dirs-sys 0.5.0 -> option-ext 0.2.0`, whose declared license
is MPL-2.0. The policy explicitly allows MPL-2.0, rather than using a blanket
license allow, because this is an unmodified upstream weak-copyleft crate linked
by a permissively licensed CLI: MPL's file-level obligation is compatible with
this larger work provided MPL notices are preserved and covered-file source remains
available. No dependency replacement is made in T039; the recorded disposition is
to retain `directories` and honor that MPL-2.0 notice/source obligation.

The policy also explicitly allows only the other licenses observed in this locked
graph: MIT, Apache-2.0, Zlib, Unicode-3.0, and Apache-2.0 WITH LLVM-exception.

## T042 Quickstart execution record

This record captures the commands in `quickstart.md` as run on the macOS host. The CLI commands ran from this checkout with the worktrunk-generated `.cargo/config.toml` target directory; no Rust source files were changed by this epic. Exit status is the process status observed for each command.

### Released CLI baseline

#### `cargo run -p matinee -- --help`

Observed exit status: `0`.

Observed salient output:

```text
Matinee checks headed-browser environments for coding agents.

Usage: matinee <COMMAND>

Commands:
  doctor   Check for supported browser executables
  help     Print help

Options:
  -h, --help     Print help
  -V, --version  Print version
```

Requirement mapping: the released CLI surface lists only the `doctor` and `help` commands and does not expose later-spec commands. This is the help portion of `FR-005-001` and `SC-005-001`; the command also provides the documented detection-only surface for `TASK-SEC-001`.

#### `cargo run -p matinee -- --version`

Observed exit status: `0`.

Observed salient output: `matinee 0.0.2`.

Requirement mapping: the version output identifies the `matinee` package and package version as required by `FR-005-001` and `SC-005-001`.

#### `cargo run -p matinee -- doctor`

Observed exit status: `0`.

Observed stdout:

```text
Firefox	/Applications/Firefox.app/Contents/MacOS/firefox
Google Chrome	/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

Observed stderr: empty. At least one supported browser exists, so the successful status satisfies the quickstart success condition. The two rows are detection results only; no automation or control operation was invoked.

Requirement mapping: Firefox and Google Chrome rows, detection-only behavior, and success when a supported browser exists satisfy `FR-005-001`, `FR-005-002`, `SC-005-001`, and `TASK-SEC-001`.

#### No-browser exit-1 attempt

To remove `PATH` candidates without changing installed applications, I ran:

```text
$ PATH=/nonexistent /Users/sjors/.local/share/mise/shims/cargo run -p matinee -- doctor
```

Observed exit status: `0`. Salient output remained:

```text
Firefox	/Applications/Firefox.app/Contents/MacOS/firefox
Google Chrome	/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

Finding: the requested exit-1 no-browser case could not be produced on this host using the CLI's supported isolation surface. The CLI checks fixed macOS application paths in addition to `PATH`; both fixed paths exist on this host, so an empty `PATH` did not create a no-browser environment. I did not rename, delete, or otherwise mutate either installed application. The repository's injected-discovery unit test covers the no-browser branch (`Firefox\tnot found`, `Google Chrome\tnot found`, diagnostic `no supported browser found; install Firefox or Google Chrome`, exit code `1`), but that is not a CLI process exit and is not claimed as the requested observed process status. This finding leaves the quickstart's exit-1 demonstration unproven on this host.

Requirement mapping: the expected exit-1 branch is the negative half of the doctor contract (`FR-005-002`/`SC-005-001`). The observed inability to isolate fixed paths is recorded as a validation limitation rather than an invented pass.

#### Invalid invocation (`cargo run -p matinee -- wat`)

Observed exit status: `2`.

Observed stdout: empty.

Observed stderr:

```text
error: unrecognized argument 'wat'

Usage: matinee <COMMAND>
```

Requirement mapping: the diagnostic is written to stderr and exit status `2`, satisfying the invalid-invocation requirement in `SC-005-001` and the closed CLI failure behavior in `FR-005-001`.

### Configuration policy

#### `cargo test -p matinee-runtime --test configuration_contract`

Observed exit status: `0`.

Observed result: `28 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.76s`.

Requirement mapping: this validates the quickstart matrix for precedence, protected sources, duplicate and unknown keys, Windows environment-name collisions, descriptor material classes, malformed values, exact and one-over limits, pathological 1 MiB inputs, redacted closed failures, and empty temporary roots. It maps to `FR-005-005`, `SC-005-005`, and `TASK-SEC-003`.

#### `cargo test -p matinee-runtime --test environment_contract`

Observed exit status: `0`.

Observed result: `18 passed; 0 failed; 0 ignored; 0 measured; 17 filtered out; finished in 10.40s` (the harness also ran its helper test once in a separate test binary: `1 passed; 0 failed; 17 filtered out; finished in 0.00s`).

Requirement mapping: this validates the macOS, Linux, and Windows fixture paths; one hundred roots; platform-equivalent paths; supported symbolic links; escape rejection; and project-file replacement during a read. It maps to `FR-005-003`, `FR-005-004`, `SC-005-003`, and `TASK-SEC-002`.

### Architecture gate

#### `cargo +1.85.0 test --workspace --all-targets`

Observed exit status: `0`.

Observed result: `186 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out` across the six test binaries (including the 7 CLI unit tests, 7 released-CLI tests, 125 runtime unit tests, 28 configuration-contract tests, and 18 environment-contract tests; the environment helper test also reported `1 passed` in its separate helper binary). The command initially waited on the package-cache lock, then completed successfully.

Requirement mapping: the Rust 1.85 workspace/all-targets compatibility gate passed, covering direct and transitive dependency compatibility and the released CLI/runtime contracts. It maps to `FR-005-006`, `SC-005-004`, `SC-005-006`, and the CI architecture gate.

Known pre-existing finding (not attributed to this epic): the host failure `matinee-runtime` `platform::tests::host_unicode_normalization_is_total_for_valid_anchor_without_variant_probe` has previously produced `Err(PathUnavailable)` where the test expects `Ok(CanonicalDecomposed)`. This epic changes no Rust code. In this exact workspace-gate invocation, the same test was observed as `ok` and the command exited `0`; therefore this record does not claim that failure was reproduced here, but preserves it as the known host-dependent baseline finding for follow-up.

#### `cargo clippy --workspace --all-targets -- -D warnings`

Observed exit status: `0`.

Observed output: no diagnostics; Cargo reported `Finished dev profile [unoptimized + debuginfo] target(s) in 14.43s`.

Requirement mapping: no warning was allowed by the `-D warnings` architecture gate. This maps to the workspace quality gate and `SC-005-006`.

#### `cargo fmt --all --check`

Observed exit status: `0`.

Observed output: empty.

Requirement mapping: all workspace Rust formatting matched rustfmt, satisfying the formatting portion of the architecture gate and `SC-005-006`.

### Overall disposition

All quickstart commands listed in `quickstart.md` completed with exit status `0` in this invocation. The additional invalid invocation produced the required exit status `2` and stderr diagnostic. The no-browser exit-1 process scenario remains unproven on this host because fixed macOS browser paths are present; the injected unit-test branch exists but is not substituted for the requested process-level demonstration. The known host Unicode-normalization failure is recorded as pre-existing and not caused by this epic.
