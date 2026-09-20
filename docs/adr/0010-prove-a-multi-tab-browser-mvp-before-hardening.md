<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-9 -->
---
number: 10
title: "Prove a multi-tab browser MVP before hardening"
status: accepted
date: 2026-09-20
bead: adr-9
spec: 006.5-demonstrable-browser-mvp
---

# Prove a multi-tab browser MVP before hardening

## Considered Options

Completing the full Spec 007 daemon and store architecture first was rejected because it commits to operational complexity before proving browser control. Creating a disposable browser prototype without durable operation identity was rejected because a restart could replay an effect whose result is unknown, so the demonstration would be unsafe or misleading. Collapsing Specs 007 through 011 into one specification was rejected because it removes the deep-module ownership seams needed for later hardening.

## Decision Outcome

Insert Spec 006.5 as a demonstrable vertical MVP that controls multiple visible browser tabs through one paired extension and one MCP client. Keep durable pre-dispatch operation records and unknown-outcome reservation. Defer the broader Spec 007 lifecycle and storage hardening contract until the MVP works end to end.

### Rationale

The released baseline and completed foundations do not yet prove that MCP requests can control visible browser tabs through the extension. A vertical slice tests product value and the highest-risk integration before Matinee commits to relocation, multi-client multiplexing, automatic storage recovery, idle lifecycle policy, or general migration machinery. Durable pre-dispatch records remain necessary because navigate, click, and type cross an external effect boundary: after a lost response or crash, replay could duplicate a submission, purchase, message, or navigation side effect.

### Consequences

Spec 006.5 may use intentionally narrow implementations behind stable seams. It must prove multiple visible tabs, secure pairing, MCP communication, pre-dispatch durability, restart behavior, and no automatic replay of unknown effects. Specs 007 through 011 deepen those seams after the demonstration. Relocation and other optional administration remain post-MVP.

### Confirmation

The MVP demonstration must drive at least two visible browser tabs independently, survive daemon restart without replaying an unknown effect, and expose a reconciliation-required result when outcome evidence is missing.
