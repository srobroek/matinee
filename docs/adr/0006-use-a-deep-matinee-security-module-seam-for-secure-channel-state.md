<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-5 -->
---
number: 6
title: "Use a deep matinee-security module seam for secure-channel state"
status: accepted
date: 2026-09-16
bead: adr-5
spec: 006-identity-authorization-secure-channels
---

# Use a deep matinee-security module seam for secure-channel state

## Considered Options

Separate protocol, domain, daemon, and extension crates were rejected because later specifications own those integrations and the split exposes security ordering across shallow interfaces. Adding the behavior to matinee-runtime was rejected because runtime identity and security policy would lose locality. Public authenticate, authorize, encode, and decode primitives were rejected because callers could sequence them incorrectly.

## Decision Outcome

Implement Spec 006 in one new crates/matinee-security deep module. Its stateful ChannelSession and closed SecurityCommand interfaces own authentication, framing, epoch checks, authorization ordering, and lifecycle transitions. Raw frame operations remain private. Only credential-store and inherited operating-system pipe platform variations are adapter seams. Later specifications own daemon, extension, clock, audit, and product-flow integration.

### Rationale

Roadmap constraint C-09 requires one deep module per specification. The implemented Spec 005 workspace contains matinee-cli and matinee-runtime; one security crate adds an executable ownership seam without reviving Spec 001 proposed package split. A stateful interface prevents callers from reordering authentication and authorization or duplicating object-existence policy. The evidence is recorded in `.specify/memory/roadmap.md` (C-09 and Spec 006 ownership), `specs/006-identity-authorization-secure-channels/plan.md` (the one-crate file map and downstream ownership table), and `specs/006-identity-authorization-secure-channels/spec.md` (the in-scope security boundary).

### Consequences

The new crate adds a workspace member and package seam. Downstream specifications must integrate through its typed interfaces. Internal framing and policy cannot be bypassed for convenience.

### Confirmation

The Spec 006 plan file map contains only crates/matinee-security as new implementation ownership. Architecture review must confirm raw framing stays private and later-spec integrations remain downstream before task generation. The plan and task graph keep workspace, manifest, and implementation work behind the accepted ADR prerequisite.
