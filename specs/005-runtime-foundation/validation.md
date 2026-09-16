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
Google Chrome	/Applications/Google Chrome.app/Contents/MacOS/google-chrome
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
Google Chrome	/Applications/Google Chrome.app/Contents/MacOS/google-chrome
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
