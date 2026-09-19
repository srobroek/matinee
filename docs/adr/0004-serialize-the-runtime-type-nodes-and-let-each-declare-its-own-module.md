<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-4 -->
---
number: 4
title: "Serialize the runtime type nodes and let each declare its own module"
status: accepted
date: 2026-09-12
bead: adr-4
spec: 005-runtime-foundation
---

# Serialize the runtime type nodes and let each declare its own module

## Considered Options

Run all three concurrently with per-file rustc typechecks, rejected: cross-module references break a detached typecheck, and the first node to need another's type would either stub it or block. Run them concurrently and let each add its own mod line, rejected: three workers editing crates/matinee-runtime/src/lib.rs concurrently is a guaranteed integration conflict on a file none of them owns. Give lib.rs to matinee-mol-hyr.3.4 alone and defer all wiring, rejected: it defers all compilation and all test execution to one node and hides which node introduced a defect. Reorder as platform, error, environment, rejected: the failure type is referenced by both of the others, so it must land first.

## Decision Outcome

The three ready runtime type nodes are serialized as error.rs, then platform.rs, then environment.rs, and each one's scope is widened to include crates/matinee-runtime/src/lib.rs so it declares its own module.

### Rationale

The nodes look concurrent because their file scopes are disjoint, but their content is not: matinee-mol-hyr.3.2 defines the closed failure type that matinee-mol-hyr.1.2's result and provenance types must produce, and matinee-mol-hyr.3.3's platform adapter is what environment resolution consults, so writing environment.rs first would mean inventing the very types the other two nodes own. Their acceptance criteria also demand observable behavior, and in a library crate no module compiles or is testable until the crate root declares it, so a node that cannot touch lib.rs can only be typechecked as a detached file — and that stops working the moment one module refers to another. Serializing costs one wave of parallelism and buys a crate that builds, with unit tests that actually run, at every node boundary. The alternative of leaving all three undeclared until matinee-mol-hyr.3.4 wires them would push every compile error and every test to that node, which is exactly the accumulation the earlier CLI stage avoided.

### Consequences

Three nodes that could have run in one wave now take three, which is slower in wall-clock terms and costs three review rounds instead of possibly one. Each node also touches a file outside its bead's original scope, so reviewers must check that a node added only its own module declaration to lib.rs and nothing else.

### Confirmation

Dependency edges make the order explicit in the graph rather than in prose, each node's scope metadata names lib.rs, and each node's review verifies both a warning-free workspace build and that lib.rs gained only that node's declaration.
