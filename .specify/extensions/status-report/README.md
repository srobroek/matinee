# Status Report — Spec Kit Extension

A [Spec Kit](https://github.com/github/spec-kit) extension that adds the `/speckit.status-report.show` command, giving you an at-a-glance view of project and feature progress across the spec-driven development workflow.

## Features

- **Pipeline view** — all features with their workflow stage (Specify → Plan → Tasks → Implement)
- **Artifact status** — which documents exist for the current feature
- **Task progress** — completion counts and percentages for features in implementation
- **Checklist tracking** — progress on any quality checklists
- **Next action** — recommends the exact command to run next
- **JSON output** — machine-readable format for tooling integration
- Cross-platform: Bash, PowerShell, and Python runtimes, matching the variant your project was initialized with

## Installation

Install directly from a GitHub release:

```bash
specify extension add status-report --from https://github.com/Open-Agent-Tools/spec-kit-status/archive/refs/tags/v1.4.2.zip
```

The extension id comes first; `--from` points at the release archive.

## Usage

```
/speckit.status-report.show [feature] [flags]
```

### Flags

| Flag | Description |
|------|-------------|
| *(none)* | Show overview + current branch's feature detail |
| `--all` | Overview only, no feature detail |
| `--verbose` | Add task phase breakdown and checklist details |
| `--feature <name>` | Target a specific feature by name, number, or path |
| `--json` | Machine-readable JSON output |

### Examples

```
/speckit.status-report.show
/speckit.status-report.show --all
/speckit.status-report.show --verbose
/speckit.status-report.show 002
/speckit.status-report.show 002-dashboard
/speckit.status-report.show --feature 002-dashboard --json
```

### Output

**Default view:**

```
Spec-Driven Development Status

Project: my-app
Branch: 002-dashboard
Constitution: ✓ Defined (v1.0.0)

Features
+-----------------+---------+------+-------+------------------+
| Feature         | Specify | Plan | Tasks | Implement        |
+-----------------+---------+------+-------+------------------+
| 001-onboarding  |    ✓    |  ✓   |   ✓   | ✓ Complete       |
| 002-dashboard < |    ✓    |  ✓   |   ✓   | ● 12/18 (67%)    |
+-----------------+---------+------+-------+------------------+

Legend: ✓ complete  ● in progress  ○ ready  - not started

002-dashboard

Artifacts:
  ✓ spec.md        ✓ plan.md        ✓ tasks.md
  ✓ research.md    - data-model.md  - quickstart.md
  - contracts/     - checklists/

Next: /speckit.implement
  Continue implementation (12/18 tasks complete)
```

## Requirements

- Spec Kit `>=1.0.0`
- Bash, PowerShell, or Python 3 — Spec Kit picks the variant your project uses
- Git (optional — used to resolve the current feature when `.specify/feature.json` is absent)

## License

MIT — see [LICENSE](LICENSE)

## Changelog

See [CHANGELOG.md](CHANGELOG.md)
