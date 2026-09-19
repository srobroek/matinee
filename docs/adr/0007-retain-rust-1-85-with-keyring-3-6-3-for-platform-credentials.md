<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-6 -->
---
number: 7
title: "Retain Rust 1.85 with keyring 3.6.3 for platform credentials"
status: accepted
date: 2026-09-16
bead: adr-6
spec: 006-identity-authorization-secure-channels
---

# Retain Rust 1.85 with keyring 3.6.3 for platform credentials

## Considered Options

Raise the workspace minimum to Rust 1.88 and use keyring 4.0.0 was rejected because the toolchain migration exceeds Spec 006 scope. Custom per-platform credential stores were rejected because they duplicate platform policy and enlarge the security surface.

## Decision Outcome

Retain the workspace Rust 1.85 minimum and pin keyring 3.6.3 with apple-native, windows-native, linux-native-sync-persistent, and crypto-rust features behind the private credential-store seam.

### Rationale

Package metadata records keyring 3.6.3 with Rust 1.75 support, so it satisfies the workspace Rust 1.85 minimum and provides the required macOS, Windows, and Linux credential backends. keyring 4.0.0 requires Rust 1.88 and would force an unrelated cross-specification toolchain migration. The evidence is recorded in `specs/006-identity-authorization-secure-channels/plan.md` (the dependency table and architecture decision), `specs/006-identity-authorization-secure-channels/research.md` (MSRV and rejected-alternative evidence), and `specs/006-identity-authorization-secure-channels/quickstart.md` (the required feature configuration).

### Consequences

Spec 006 does not receive keyring 4 features. The private credential-store seam must preserve replacement locality, and dependency review must track security advisories for the pinned release.

### Confirmation

The crate manifest must constrain keyring to 3.6.3 with no default features and the four named backend features. The generated lockfile and platform credential tests must confirm the resolved version and backend behavior under Rust 1.85. Until those implementation checks run, these paths remain planning evidence rather than implementation evidence.
