<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-3 -->
---
number: 3
title: "Inject browser discovery inputs and unit-test the deterministic matrix in doctor.rs"
status: accepted
date: 2026-09-12
bead: adr-3
spec: 005-runtime-foundation
---

# Inject browser discovery inputs and unit-test the deterministic matrix in doctor.rs

## Considered Options

A new environment variable that overrides the fixed-path list, rejected: it is observable product surface, and spec.md:9-11 forbids exposing unfinished surfaces for this slice. Adding a lib target that exports discovery so tests/ can call it, rejected: it publishes an interface the spec wants kept private and would outlive the test need. Asserting only what the host happens to have, rejected: the expected value would have to be recomputed by the test from the same rules, which is a tautological test that passes regardless of the behavior it claims to pin. Deferring both nodes until a later spec adds a platform adapter, rejected: the nodes are ready now, their acceptance names deterministic fixtures, and the graph's later environment work is about configuration directories, not browser discovery.

## Decision Outcome

Browser discovery in crates/matinee-cli/src/doctor.rs gains one internal injected discovery environment, and the deterministic Firefox/Chrome fixtures for matinee-mol-hyr.1.4 and matinee-mol-hyr.1.5 live in that module's #[cfg(test)] unit tests, while crates/matinee-cli/tests/released_cli.rs keeps only host-independent end-to-end assertions.

### Rationale

The two nodes are scoped to the integration test file alone, but nothing in that file can make discovery deterministic on this platform. Measured at head 9f02193: doctor consults hard-coded absolute fixed paths first (/Applications/Firefox.app/Contents/MacOS/firefox and /Applications/Google Chrome.app/Contents/MacOS/Google Chrome, doctor.rs:89-125) and only then scans PATH (doctor.rs:55-63). A test process can set PATH but cannot alter /Applications, and on this host both fixed paths exist, so the PATH branch is unreachable and the no-browser case is impossible; the T010 implementer already reported exactly that. matinee-cli is a bin-only crate, so an integration test can only execute the binary and cannot reach a private seam. The spec's own research decision is to run one library contract against a production host adapter and a deterministic test adapter (research.md:126-139), and the Windows branch already derives its fixed paths from environment variables (doctor.rs:127-135), so injecting the discovery inputs is consistent with the existing structure rather than a new idea. Production call sites pass exactly today's values, so released behavior is unchanged, which is what Stage 1 requires.

### Consequences

Two nodes whose beads name only the integration test file will also modify crates/matinee-cli/src/doctor.rs, so their scope metadata is widened by the owning architect and their reviewers must check that the production path still yields the original fixed paths. Unit tests inside the binary crate cannot exercise the shipped executable, so end-to-end coverage of doctor stays limited to the row-shape and exit-class assertions that hold on any host; a genuinely host-free end-to-end doctor test remains impossible until a platform adapter exists.

### Confirmation

matinee-mol-hyr.1.4 and matinee-mol-hyr.1.5 carry this decision in their scope metadata and comments, and each node's independent review verifies both the deterministic matrix and unchanged production discovery values.
