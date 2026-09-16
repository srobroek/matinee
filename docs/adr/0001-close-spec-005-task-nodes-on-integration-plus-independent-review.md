<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-1 -->
---
number: 1
title: "Close Spec 005 task nodes on integration plus independent review"
status: accepted
date: 2026-09-12
bead: adr-1
spec: 005-runtime-foundation
---

# Close Spec 005 task nodes on integration plus independent review

## Considered Options

One PR per task node, rejected: 47 stacked PRs against an unlanded base multiply review and CI cost and would still serialise on merges, and the spec's stage boundaries are not independently shippable. Closing nodes on integration alone without review, rejected: it removes the independent verdict the run's contract requires and puts the architect in the position of approving its own integration. Holding every node open until the PR merges and unblocking dependents by deleting dependency edges, rejected: it destroys the authored DAG, which is the run's only record of ordering.

## Decision Outcome

Integrated Spec 005 task nodes close on architect integration plus an independent reviewer approval at the integrated commit; the single unparented pr:merge bead routed role=shepherd is the only landing unit that waits on PR #5 merging.

### Rationale

The epic's 47 implementer nodes form an almost fully serial dependency chain (bd dep edges: T001 -> T010/T011 -> T012 -> T007 -> T008 -> T009 -> T013 -> T002 -> ...), and a dependent only becomes ready when its dependency closes. One shared feature branch carries all of them behind one PR, so a policy of "no task node closes until its git work is merged" would deadlock the graph: PR #5 cannot merge until the last node is done, and no node after T001 can start until earlier nodes close. Closing on integration plus independent review keeps every node's git evidence real (a commit on orc/005-runtime-foundation, verified in the feature checkout, pushed to origin) and keeps exactly one shepherd-owned landing transaction.

### Consequences

Task nodes read closed while their code is still unmerged, so a reader who equates closed with shipped will be wrong until PR #5 lands; the merge bead is the only place that truth lives. If the PR is ultimately rejected, closed nodes must be reopened rather than simply re-run.

### Confirmation

Each closed node carries its integrated commit sha and an independent reviewer verdict in its comments, and the merge bead carries the PR and its head at landing.
