<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-8 -->
---
number: 9
title: "Multiplex principal sessions over one extension channel"
status: accepted
date: 2026-09-20
bead: adr-8
spec: 008-extension-secure-connection
---

# Multiplex principal sessions over one extension channel

## Considered Options

Opening one extension channel per MCP principal was rejected because one extension profile would have concurrent authorities and duplicated reconnect state. Sharing one daemon-wide browser session and tab group was rejected because one principal could observe or mutate another principal's browser work. Ending sessions and closing tabs on disconnect was rejected because connection loss is not authorization to destroy durable work or user-visible browser state.

## Decision Outcome

Use one active authenticated control-channel generation per paired browser profile to multiplex explicitly granted sessions. Give each MCP principal at most one visible tab group per paired profile. Preserve durable sessions and tabs when an MCP or extension connection drops, while dissolving or disconnecting the visible control group until authenticated rebind.

### Rationale

A browser extension represents one paired browser profile, while MCP principals own independent durable work. Multiplexing preserves this authority split without opening one competing extension channel per client or binding durable ownership to transient connections.

### Consequences

Specs 008 and 011 must define message routing, grant revocation, reconnect generations, group recreation, and visible ownership. Spec 007 provides only generic durable ownership and grant records and does not implement channel or tab behavior.

### Confirmation

Spec 008 must prove one active authenticated channel generation per paired profile. Spec 011 must prove principal/profile group isolation and preservation across connection loss.
