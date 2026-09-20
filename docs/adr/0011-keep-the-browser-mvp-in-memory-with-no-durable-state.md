<!-- Generated from a beads decision bead. Edit the bead, not this file:
     bd show adr-10 -->
---
number: 11
title: "Keep the browser MVP in memory with no durable state"
status: accepted
date: 2026-09-20
bead: adr-10
spec: 006.5-demonstrable-browser-mvp
supersedes: adr-9 (in part)
---

# Keep the browser MVP in memory with no durable state

## Considered Options

- Keep the SQLite journal already built for this MVP. Rejected: it protects a
  fixture counter, and it costs a schema, recovery paths, and a bundled C
  dependency.
- Persist one crash flag per in-flight operation. A restart would then refuse the
  reused idempotency key. Rejected for the MVP, and recorded as the cheapest
  option for Spec 007, because it needs no database.
- Keep `uncertain` and `reconciliation_required` as in-memory states. Rejected:
  within one run the daemon can always name the lost boundary, so a `failed`
  state carrying that boundary says the same thing with fewer states.

## Decision Outcome

Spec 006.5 keeps no durable state. The daemon holds every Request, Operation,
Session, idempotency record, and artifact in memory for one run. It makes no
crash-safety claim.

This supersedes the part of `adr-9` that kept a durable pre-dispatch record and an
unknown-outcome reservation inside the MVP.

In place of recovery, the daemon reports only what it observed:

- It never claims an outcome it did not observe.
- It never retries an operation whose result it lost.
- It generates one instance identity per start, and every response carries it.
- It assigns a monotonic action sequence per session.
- It rejects a client holding a prior instance identity with `daemon.restarted`,
  naming that client's last action sequence.

### Rationale

`FR-018` confines the MVP to one deterministic local fixture origin. Repeating an
action there changes a counter the user can see.

A durable journal prevents duplicate consequential effects on real sites. This MVP
cannot reach a real site, and Spec 007 already owns that store.

Durability was never what told a client that an outcome was unknown. A client
detects daemon loss from its dropped connection and a changed instance identity.
Durability would only separate never-sent from maybe-sent, which is an
optimization. The MVP always gives the conservative answer instead.

### Consequences

This is a scoped exception to Constitution III, for Spec 006.5 only:

- Scope: the fixture-only MVP.
- Expiry: the first specification that automates any non-fixture origin.
- Replacement: the Spec 007 durable store.

No release that reaches a real site may inherit this exception.

One risk remains. A client that retries after a restart can duplicate an effect,
because no record survives to refuse the reused key. The fixture-only restriction
bounds that risk, which MUST be closed before real-site automation.

`FR-031` through `FR-044` define the in-run effect boundary. `SC-006`, `SC-007`, `SC-009`, `SC-012`, and `SC-014` measure instance detection, honest failure, sequence monotonicity, and absent state.

### Confirmation

- An extension disconnect ends an operation as `failed`, naming that boundary.
- A restarted daemon rejects a stale instance identity with `daemon.restarted`.
- A restarted daemon holds zero sessions.
- Every browser tab stays open.
