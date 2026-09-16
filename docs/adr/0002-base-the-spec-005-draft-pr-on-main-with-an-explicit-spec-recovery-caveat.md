<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-2 -->
---
number: 2
title: "Base the Spec 005 draft PR on main with an explicit spec-recovery caveat"
status: accepted
date: 2026-09-12
bead: adr-2
spec: 005-runtime-foundation
---

# Base the Spec 005 draft PR on main with an explicit spec-recovery caveat

## Considered Options

Pushing spec-recovery-main to origin and basing the PR on it, rejected: that branch belongs to the spec-recovery run, and publishing another owner's lineage from inside this epic crosses an ownership boundary this architect does not hold. Waiting for spec-recovery-main to land before opening any PR, rejected: it would block the run's review and CI feedback behind an external run with no dependency edge in this graph. Rebasing 005 onto origin/main, rejected: it would drop the approved spec capture c028459 that every task bead cites as spec_capture_sha.

## Decision Outcome

Draft PR #5 for orc/005-runtime-foundation targets main, and records the unlanded spec-recovery-main fork point as an explicit caveat rather than pushing another run's branch.

### Rationale

The feature branch forks from spec-recovery-main at c028459228ed7e6fc62579cebe9c0e51cd39e5a0, which exists only locally (git ls-remote origin lists main, renovate/configure and __dolt_remote_info__ only). A PR needs a base that exists on the remote, and origin/main is an ancestor of the fork point, so main is the only correct base available to this run. The eight intervening commits are spec-recovery documentation history and disappear from the diff once that lineage lands, so the caveat is cheap and reversible: a PR base can be re-targeted before the PR is made ready.

### Consequences

Until spec-recovery-main lands, PR #5's diff and CI cover more than this run authored, so reviewers and any diff-based automation must read c028459..HEAD rather than the full PR range, and a shepherd must re-check the base before making the PR ready.

### Confirmation

PR #5's body states the fork point, the reviewable range and the re-targeting instruction; the epic and merge bead carry base_ref and base_sha.
