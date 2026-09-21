<!-- Written directly, not generated from a beads decision bead: the project's
embedded Beads store was unreachable when this was recorded (config.yaml sets
dolt.shared-server, nothing listens on 127.0.0.1:3308, auto-start is disabled,
and starting a Dolt server manually is forbidden). No `adr-11` bead exists.
Create one from this file if the store returns. -->

---
number: 12
title: "Shelve Matinee in favour of the omp browser relay"
status: accepted
date: 2026-09-21
bead: none
spec: 006.5-demonstrable-browser-mvp
supersedes: adr-9 (in part), adr-10 (in part)
---

# Shelve Matinee in favour of the omp browser relay

## Decision

Stop building Matinee. The repository is archived read-only. Browser control
for agent work uses the omp browser relay, which is already installed and
already drives real logged-in tabs.

Specs 001 and 005 through 016 are not withdrawn or disproven. They are shelved
unbuilt.

## Context

The owner observed late in implementation that omp ships a browser relay. It
was read end to end before this decision.

The relay is a CDP facade. Its MV3 extension forwards `chrome.debugger`
commands over a loopback WebSocket, and its daemon half impersonates Chrome's
discovery endpoint, synthesises the `Target.*` hierarchy that `chrome.debugger`
does not expose, and multiplexes several puppeteer connections over the single
debugger attachment Chrome permits per tab. Driven tabs are gathered into a
tab group so ownership is visible, and the group is dissolved on disconnect.

Two properties of the relay decided this:

- It requires `debugger`, `tabs`, `tabGroups`, `storage` and `alarms`, and no
  host permissions, because `debugger` already grants everything. Its own
  README states that anything able to reach its loopback port can drive
  logged-in tabs.
- It carries no effect accounting. A search of its extension for idempotency,
  ledger, operation, request-identity or retry vocabulary returns nothing. A
  dropped CDP reply is a dropped reply and nothing records it.

Matinee was therefore not redundant in intent. Its two defensible claims were
provable non-duplication of a real effect across a crash or lost response, and
browser control that never requests `debugger`.

Neither claim was true of the code as scoped. `adr-10` removed all durable
state, so nothing could prove non-duplication. `FR-018` confined the MVP to a
deterministic local fixture, so no real effect was ever at stake. The scope
cuts that made the MVP affordable also removed the reasons to prefer it, and
what remained was a slower, less capable relay with a better error envelope.

Performance was considered and rejected as a differentiator. CDP input
dispatch is cheaper than the content-script event synthesis Matinee uses
without `debugger`; Matinee adds two process hops and per-operation
bookkeeping; and a restored durability barrier would write before every
effect by design. Two narrow advantages were plausible -- less serialisation
across many tabs, and more compact typed results for a model -- but both were
unmeasured, because no `session_open` ever completed against a browser.

## What was proven, and what was not

Verified by running real binaries:

- an in-memory daemon that spawns a real child process and binds two loopback
  listeners
- a control channel authenticated by the Spec 006 handshake against registered
  principals
- an extension channel authenticated by an ECDSA P-256 signature over the
  pairing transcript, gated on an active `PairingRecord` so a revoked pairing
  cannot authorise
- one-time-key extension enrollment
- a ten-tool stdio MCP adapter and a CLI
- a deterministic two-route fixture with stall injection
- an unpacked MV3 extension with a pinned key that a real Chrome profile loads
  and pairs

Gates green at every commit: `cargo fmt`, `cargo clippy -D warnings`, 450 tests.

Not proven: a browser operation. `session_open` returns
`operation.extension_disconnected` while the daemon's own evidence report
shows the channel authenticated at an unchanged generation before, during and
after the dispatch, and the session record created. The frame reaches a live,
authenticated extension that neither replies nor throws.

The leading hypothesis, unconfirmed, is a race at
`extension/service-worker.js:264-276`: a tab is created and its document
generation requested immediately, and a freshly created tab may have no
committed main frame, so no `documentId` is found. This was never instrumented
to a conclusion, and `bindSession` does catch generation errors and reply with
a failure, which argues against it. `SC-001` through `SC-019` and `FR-058`
remain unproven.

Seven defects were found only by driving a real browser, none reachable by unit
test:

- a missing `storage` permission
- an extension comparing the daemon's channel generation against its own counter
- a hello sent before any generation existed
- a permanently expired invitation returned by `setup pair-extension`
- silent aborts in the pairing handlers
- success reported on socket setup rather than on enrollment
- an MV3 worker terminating mid-operation

## Consequences

- The repository is archived. Its history, specs, ADRs 0001-0012 and research
  notes stay readable.
- Branch `omp/agent/matinee-2im` holds the 20 unmerged implementation commits
  and stays on `origin` for reference.
- Agent browser work uses the relay, and accepts that a dropped reply is
  unaccounted and that the relay's port grants whole-browser control.
- If effect accounting is wanted later, the finding that matters is that it
  does not require a bespoke extension. A ledger can sit on CDP, whether via
  the relay or a direct connection, which reaches real origins immediately and
  avoids the transport, handshake and enrollment layers that consumed most of
  this effort. The specs, the state machine, the failure-code taxonomy and the
  fixture are the reusable parts.
- The Chrome findings stay useful independently: Chrome 137 removed
  `--load-extension` and 139 removed `--disable-extensions-except`, so branded
  Chrome cannot load an unpacked extension from the command line, and Chrome
  refuses unpacked extensions headlessly. Chrome for Testing from the
  Playwright cache still honours the flag.

## Alternatives rejected

**Finish 006.5 as specified.** Rejected: an in-memory, fixture-only MVP is
dominated by an installed relay that drives real sites. Completing it would
have proved a demonstration, not a product.

**Restore durability and lift the fixture restriction.** Rejected here, but on
cost and sequencing rather than on merit. This is the option that would have
made Matinee defensible, and it remains the shape of any revival.

**Keep the daemon and ledger, and drive CDP through the relay.** Rejected for
now as it still requires the relay's `debugger` grant, which contradicts the
least-privilege claim. Recorded because it is the cheapest revival path if
effect accounting matters more than least privilege.
