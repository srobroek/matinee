# Critique Report: Runtime Foundation, Post-Remediation

**Date**: 2026-09-11

**Feature**: [spec.md](../spec.md)

**Plan**: [plan.md](../plan.md)

**Verdict**: PROCEED

## Executive summary

This review applies the complete product and engineering critique to the amended
artifacts. The feature now preserves the released CLI, defines bounded configuration
behavior, and creates no unfinished public surface. The implementation plan owns one
runtime interface, resolves its architecture precedence, and defines cross-platform and
minimum-Rust gates. No finding blocks task generation.

## Product lens

### Problem validation

The feature addresses two prerequisites for later Matinee work: preserving 0.0.2 while
code moves, and resolving one safe local environment before stateful processes exist.
Spec 001 and roadmap specs 006-016 establish the downstream need. The feature does not
claim installation, upgrades, browser control, or daemon behavior.

### User value

The P1 stories preserve the released CLI and reject unsafe configuration. The P2 story
prevents state and lock collisions between local instances. Each story has an
independent observable test. No story depends on an unfinished command.

### Alternatives

`research.md` compares a staged workspace with empty final crates and a retained
monolith. It also compares a local configuration resolver with a general framework.
The selected design minimizes public surface and avoids placeholder implementations.

### Edge cases and experience

The specification covers missing platform directories, path aliases, project escapes,
file replacement, malformed or excessive input, source collisions, and premature
command registration. Failures identify a safe source without exposing absolute paths
or secrets.

### Success measurement

Seven success criteria cover released behavior, source policy, three-platform paths,
state isolation, path equivalence, failure containment, and absent future commands. The
plan records performance baselines before setting a threshold.

## Engineering lens

### Architecture soundness

The workspace adds only the published CLI and one implemented private runtime crate.
The plan explicitly supersedes spec 001's repository layout while preserving its
product contracts. Dependency direction and ownership are unambiguous.

### Failure modes

The data model rejects unsafe paths before reads, checks file identity after reads, and
returns terminal outcomes without product-state mutation. Input limits bound parsing
and merge work.

### Security and privacy

Protected settings reject lower-trust sources. Unknown and duplicate keys fail closed.
Configuration cannot contain credentials or browser-profile secrets. Provenance removes
raw user and project prefixes.

### Performance and scale

The design bounds files to 1 MiB, keys to 100, key depth to four segments, and text to
4,096 Unicode scalar values. The plan requires comparative cold and warm measurements
instead of an unsupported latency promise.

### Testing

The plan covers released CLI behavior, the complete configuration policy matrix,
platform fixtures, path replacement, state isolation, and security boundaries. CI runs
on Ubuntu, macOS, Windows, and Rust 1.85.

### Operational readiness

This slice writes no product state and needs no migration or rollback protocol. A
reversion restores the previous package layout. Later daemon and diagnostic specs own
long-running operations and support bundles.

### Dependencies and integration

The plan selects three runtime dependencies. The Rust 1.85 gate covers direct and
transitive compatibility because `directories` 6.0.0 declares no MSRV.

## Cross-lens result

The smallest safe slice preserves the released surface while making configuration and
path behavior reusable by later processes. The same scope choice reduces user-visible
risk and prevents premature architecture commitments.

## Findings summary

| Metric | Count |
|---|---:|
| Must-address findings | 0 |
| Recommendations | 0 |
| Questions | 0 |

## Recommended action

Generate implementation tasks from the amended artifacts and the security task table.
