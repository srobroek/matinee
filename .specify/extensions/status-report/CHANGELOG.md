# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.4.2] - 2026-09-10

### Fixed

- **Forwarding `--all` or `--verbose` to the script broke the command.** Both are documented
  user-facing flags that the agent is meant to interpret itself, but nothing said so and each
  runtime failed differently: bash read them as a feature name and reported "Feature not found",
  python exited 2 on an unrecognized argument, and PowerShell accepted `-Verbose` while
  rejecting `--all`. Since the command spec tells the agent to stop and report when the script
  fails, a forwarded flag turned a status query into an error. All three now ignore
  unrecognized flags, and the command spec says explicitly not to pass them through.
- **PowerShell read a wildcard as a valid feature name.** `Test-Path` and `-like` treat `*`, `?`
  and `[ ]` as patterns, so `-Feature '*'` resolved to an arbitrary feature instead of being
  rejected. Now uses `-LiteralPath` and `Contains()`. Bash and Python were already literal.

### Changed

- Command body no longer carries the stale "if that placeholder was not substituted" fallback.
  `{SCRIPT}` substitution is verified working against Spec Kit 1.0.5, and the leftover sentence
  described a placeholder that is not there by the time an agent reads it.

## [1.4.1] - 2026-09-10

### Fixed

- **Branch read as `HEADunknown` in a repo with no commits.** `git rev-parse --abbrev-ref HEAD`
  prints `HEAD` to stdout *and* exits non-zero before the first commit, so the fallback
  concatenated onto it. All three runtimes now try `git symbolic-ref --short HEAD` first, which
  reports the real branch pre-commit, and keep `rev-parse` for detached HEAD. Found by
  installing the v1.4.0 release into a real Spec Kit 1.0.5 project.

## [1.4.0] - 2026-09-10

Compatibility pass against Spec Kit 1.0.5.

### Fixed

- **Current feature detection ignored `.specify/feature.json`** — Spec Kit 1.0.x resolves the
  active feature via `SPECIFY_FEATURE_DIRECTORY`, then `.specify/feature.json`, then
  `SPECIFY_FEATURE`, and only then the git branch. Both scripts checked the branch alone, so
  projects that do not use a branch per feature always reported no current feature. The scripts
  now mirror Spec Kit's own precedence.
- **Timestamp and four-digit features were invisible** — `create-new-feature.sh --timestamp`
  produces `YYYYMMDD-HHMMSS-slug`, and Spec Kit matches sequential prefixes of three digits or
  more. The discovery glob required exactly three digits followed by a hyphen and silently
  skipped both shapes.
- **PowerShell never received the v1.2.0 cache removal** — the Windows script still served
  unchanged features from `spec-status.md` via git staleness detection and emitted a
  `from_cache` field that Bash had dropped, so Windows users got different data and a different
  JSON shape. The cache path is gone; both scripts now do a fresh scan.
- **README install command was not runnable** — it read
  `specify extension add --from <url> EXTENSION` with the literal placeholder in the argument
  position. The extension id comes first.
- **Bash wrote a misaligned status table** — `printf`'s `%-Ns` pads by bytes, and the status
  symbols are three-byte UTF-8, so every column holding one came out two characters short in
  `spec-status.md`. Padding is now character-based. PowerShell and Python were already correct;
  the test asserts all three render the file identically.

### Added

- `current_feature` and `feature_source` fields in JSON output — the resolved feature and how it
  was found (`env`, `feature.json`, or `branch`)
- `category` and `effect` in `extension.yml`, matching the bundled extensions. `effect` is
  `read-write`: the command writes `specs/spec-status.md` on every run.
- **Python runtime** (`scripts/python/get_project_status.py`), declared as `py` in the command
  frontmatter alongside `sh` and `ps`. Spec Kit 1.0.x ships all three runtimes and selects the
  one a project was initialized with; previously a python-variant project fell back to bash or
  powershell.
- `tests/test-status.sh` — runnable self-check covering feature discovery, every branch of the
  resolution precedence, and cross-runtime parity. Runs the full suite against each installed
  runtime and asserts they agree on both JSON output and the rendered status file.

### Changed

- **Command frontmatter restored.** v1.2.6 removed it on the premise that skills do not support
  the `scripts:` key. They do: `_register_extension_skills` runs frontmatter through the same
  path adjuster as commands, and extension-local `scripts/...` is rewritten to
  `.specify/extensions/status-report/scripts/...`. Dropping the block also dropped
  `description:`, which is the text a skills-based agent reads when deciding whether to trigger
  the command — Spec Kit had been substituting a generic fallback. The body now uses `{SCRIPT}`,
  which resolves to the right script for the platform, with the explicit paths kept as a
  fallback line.
- **Command references are now `__SPECKIT_COMMAND_*__` tokens** rather than literal `/speckit.*`
  text. Spec Kit renders each token in the active agent's invocation style, so the literals were
  correct only for slash-and-dot agents and wrong for Codex, Kimi and the rest.
- `__SPECKIT_COMMAND_CHECKLIST__` and `__SPECKIT_COMMAND_CONVERGE__` added to the next-action
  recommendations — both are core commands that postdate the original table.
- **`requires.speckit_version` raised to `>=1.0.0`.** The extension was declaring `>=0.1.0`
  while everything it targets is verified only against 1.0.5. Spec Kit now refuses the install
  on 0.x rather than silently serving degraded feature detection.
- `target_feature` now falls back to the current feature when no explicit `--feature` or
  positional argument is given. It was previously null in that case, leaving the command spec's
  step 4 with nothing to reference.
- `commands/show.md` step 4 drives the detail section from `target_feature` and forbids
  inferring the current feature from the branch name

## [1.3.4] - 2026-04-18

### Changed

- Added explicit instruction prohibiting manual directory scanning or file inference — agent must use script JSON or stop with an error

## [1.3.3] - 2026-04-18

### Changed

- Sections 3, 4, and 5 now driven entirely from script JSON — agent no longer scans directories, checks file existence, or reads files manually

## [1.3.2] - 2026-04-18

### Changed

- Constitution status now derived from script JSON (`constitution.exists`) — no manual file reading

## [1.3.1] - 2026-04-18

### Changed

- Removed remaining YAML/frontmatter terminology from command body — constitution version lookup now described in plain terms (look for `## Version` heading or `version:` field)

## [1.3.0] - 2026-04-18

### Changed

- Removed last "frontmatter" wording from command body — constitution version extraction now described as reading YAML at top of file, avoiding confusion with the `scripts:` key that was removed in v1.2.6

## [1.2.6] - 2026-04-18

### Changed

- Removed `scripts:` frontmatter from `commands/show.md` — speckit now wraps commands as skills, which don't support the `scripts:` key
- Inlined explicit script paths directly in the command body so the execution instruction is self-contained and works in both skill and command contexts

## [1.2.5] - 2026-04-08

### Changed

- Trimmed description to ≤100 chars to meet spec-kit catalog publishing requirements
- Dropped `visibility` tag from `extension.yml` (it's the README category, not a tag per the guide's tag taxonomy)
- Renamed `commands/status.md` → `commands/show.md` to match the final segment of the `speckit.status-report.show` command

## [1.2.4] - 2026-04-04

### Fixed

- PowerShell `PadRight()` error — cast `[char]` symbols to `[string]` so string methods work

## [1.2.3] - 2026-04-04

### Fixed

- PowerShell script fails on Windows due to UTF-8 encoding — replaced Unicode literals with `[char]` escape sequences

## [1.2.2] - 2026-04-04

### Changed

- Renamed command to `speckit.status-report.show` to match required `speckit.{extension}.{command}` pattern

## [1.2.1] - 2026-04-04

### Changed

- Attempted namespace fix (invalid — missing `speckit.` prefix)

## [1.2.0] - 2026-04-03

### Changed

- Removed cache logic — always performs a fresh scan and writes a new status file on every run

## [1.1.5] - 2026-03-25

### Changed

- Compacted command spec from ~320 to ~150 lines for better LLM processing
- Front-loaded script execution requirement to prevent Claude from skipping it

## [1.1.4] - 2026-03-20

### Changed

- Renamed extension ID from `status` to `status-report` to avoid collision with existing community extension
- Renamed extension from "Project Status" to "Status Report"
- Updated script paths in command spec to match new extension ID

## [1.1.3] - 2026-03-16

### Fixed

- Fix specs directory lookup order to prefer `specs/` over `.specify/specs/`

## [1.1.2] - 2026-03-15

### Fixed

- Removed incorrect "Read-Only Operation" claim from command spec — the command writes/updates `spec-status.md` as designed

## [1.1.1] - 2026-03-15

### Fixed

- Bash script compatibility with macOS bash 3.2 — replaced `declare -A` associative arrays with indexed arrays
- Replaced `grep -oP` (Perl regex) with portable `sed` for cache field extraction
- Fixed `grep -c` exit code 1 on zero matches causing doubled output in task counting
- Script path resolution after extension installation — frontmatter now uses full `.specify/extensions/status/scripts/...` paths
- Replaced `{SCRIPT}` placeholder in command body with reference to frontmatter scripts

## [1.1.0] - 2026-03-03

### Added

- Cache file (`{SPECS_DIR}/spec-status.md`) — human-readable markdown summary written by the scripts after each run and committed to git
- Git-based staleness detection — only feature folders changed since the cache was last committed are rescanned; unchanged features are served from cache
- Task counting in scripts — `tasks_total` and `tasks_completed` are now computed by the scripts and included in JSON output, eliminating the need for the AI to read individual `tasks.md` files
- `from_cache` field in JSON output per feature — indicates whether data came from cache or a fresh scan
- `cache_file` field in JSON output — path to the written cache file

### Changed

- `commands/status.md` — updated to use pre-computed task counts from script JSON output instead of counting lines from `tasks.md`

## [1.0.0] - 2026-02-27

### Added

- `/speckit.status-report.show` command — display project status, feature progress, and recommended next actions
- Support for `--all`, `--verbose`, `--json`, and `--feature` flags
- Bash discovery script (`scripts/bash/get-project-status.sh`)
- PowerShell discovery script (`scripts/powershell/Get-ProjectStatus.ps1`)
- Pipeline view showing all features with workflow stages (Specify → Plan → Tasks → Implement)
- Artifact status for the current/selected feature
- Task completion tracking for features in implementation
- Next action recommendations based on current state
- JSON output format for machine-readable integration

[1.4.2]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.4.2
[1.4.1]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.4.1
[1.4.0]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.4.0
[1.3.4]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.3.4
[1.3.3]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.3.3
[1.3.2]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.3.2
[1.3.1]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.3.1
[1.3.0]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.3.0
[1.2.6]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.6
[1.2.5]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.5
[1.2.4]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.4
[1.2.3]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.3
[1.2.2]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.2
[1.2.1]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.1
[1.2.0]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.2.0
[1.1.5]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.1.5
[1.1.4]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.1.4
[1.1.3]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.1.3
[1.1.2]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.1.2
[1.1.1]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.1.1
[1.1.0]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.1.0
[1.0.0]: https://github.com/Open-Agent-Tools/spec-kit-status/releases/tag/v1.0.0
