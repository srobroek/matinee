<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-7 -->
---
number: 8
title: "Permit native principals to stop the daemon"
status: accepted
date: 2026-09-20
bead: adr-7
spec: 007-daemon-lifecycle-durable-store
---

# Permit native principals to stop the daemon

## Considered Options

Reserving shutdown for the native administrator role was rejected because it adds an administration dependency to routine local process lifecycle control. Allowing any same-user process to stop the daemon without principal authentication was rejected because local process identity does not prove authorization to the selected Matinee state directory.

## Decision Outcome

Permit any authenticated native principal, including an MCP client, to request graceful shutdown of the shared local daemon.

### Rationale

Matinee is a single-user local tool. Shutdown is a reversible lifecycle request that preserves durable state, drains all work, and reports blockers instead of forcing exit. Requiring the administrator role would prevent an authenticated local MCP client from stopping an idle or malfunctioning daemon that it caused to start.

### Consequences

One native principal can disrupt other connected principals by initiating a global drain. The daemon must notify every client, preserve durable sessions, reject new mutations, and remain draining when it cannot stop safely. This decision supersedes the Spec 006 global-administration rule only for graceful shutdown.

### Confirmation

Spec 007 acceptance tests must prove that authenticated native principals may request stop, while extension and unauthenticated callers are denied before lifecycle state changes.
