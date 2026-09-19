<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show matinee-a0n -->
---
number: 5
title: "Keep T022 scoped to config.rs and route deep-interface wiring to T025 and T037"
status: accepted
date: 2026-09-12
bead: matinee-a0n
---

# Keep T022 scoped to config.rs and route deep-interface wiring to T025 and T037

## Decision Outcome

Node matinee-mol-hyr.3.13 (T022) keeps its declared scope, crates/matinee-runtime/src/config.rs, and is accepted on in-module behavioral proof of merge order, provenance, ties, empty layers and origin failure. Round-1 finding 1 -- wire merge_layers into the shipped resolution path and add an end-to-end contract scenario -- is not a T022 defect and is routed as an inherited acceptance requirement to matinee-mol-hyr.3.16 (T025, crates/matinee-runtime/src/environment.rs, assembles the all-or-failure configuration result) and matinee-mol-hyr.3.28 (T037, crates/matinee-runtime/src/lib.rs, integrates configuration resolution). The end-to-end contract scenario belongs to the contract-case beads that own the test files, starting with matinee-mol-hyr.3.5 (crates/matinee-runtime/tests/configuration_contract.rs).

### Rationale

Scopes on this epic are disjoint by construction and the ready front is serial. T022 owns config.rs only; environment.rs belongs to T025 and lib.rs to T037, both still open. Widening T022 to wire and export the resolution path would take territory those nodes exist to implement, duplicate their work, and produce exactly the overlapping-scope conflicts the decomposition avoids. crates/matinee-runtime/tests/configuration_contract.rs does not exist yet at 2f70ab1: T014 (matinee-mol-hyr.3.5) creates it, so an end-to-end scenario cannot land inside T022 without pre-empting that node too. The reviewer was correct that a merge function with no shipped consumer is unproven end to end; the fix is to make that a named, verified acceptance requirement on the two nodes that own the seam rather than to dissolve the scope boundary. Findings 2 through 6 are genuine T022 defects inside config.rs and go back to the implementer queue as one captured fix round.

### Consequences

Reviewers of T022 round 2 and later must not re-raise finding 1 against T022; it is tracked on T025 and T037. T025 and T037 cannot be accepted unless the deep environment-resolution interface actually reaches merge_layers and a contract scenario exercises layered resolution end to end. If T025 and T037 both land without that wiring, T022 remains formally accepted but the epic is incomplete, and the gap surfaces as a feature-level finding on matinee-mol-hyr.3 rather than as silent coverage debt.
