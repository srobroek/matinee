# Contract: Daemon Protocol

**Feature**: [spec.md](../spec.md)

Two local transports reach the daemon. Both bind loopback only and authenticate
every peer.

## Bootstrap channel

The launcher starts the daemon with an inherited operating-system handle and
passes a `BootstrapEnvelope` carrying the state directory UUID and endpoint
descriptor. `matinee_security::adapters::os_pipe` already parses the daemon side;
the MVP adds the launcher side (`FR-005`).

Only the native administrator uses this channel, and only for:

| Command | Effect |
|---|---|
| `register_principal` | Registers the one MVP MCP principal |
| `create_enrollment` | Issues an extension pairing with a one-time key |
| `rotate` | Rotates a principal's custody |
| `revoke` | Terminally revokes a principal |

Client-supplied owners, capabilities, clocks, and epochs are rejected: the daemon
derives them from authenticated records (`FR-011`, `FR-012`).

## Control channel

The MCP adapter connects over a loopback stream and authenticates with its
registered MCP principal using the Spec 006 `ClientHandshake` and
`ServerHandshake` pair. The daemon rejects an unknown principal, a stale epoch,
or a revoked credential before any state change.

Messages carry the protocol version. A mismatch rejects the peer rather than
negotiating down (`FR-014`, Constitution V).

## Lifecycle states

`starting`, `ready`, `draining`, `failed`.

| Transition | Trigger |
|---|---|
| `starting` to `ready` | Ownership acquired, instance identity generated, endpoints bound |
| `starting` to `failed` | State-directory ownership unavailable or lost |
| `ready` to `draining` | Authorized stop crosses the dispatch-admission boundary |
| `draining` to exit | New operations rejected, in-memory state abandoned, extension disconnected, tabs left open |
| `draining` to `ready` | Never |
| `ready` to `failed` | State-directory ownership lost |

## Dispatch admission

One serialized boundary admits both a stop request and a `preflight` to
`dispatching` transition, so exactly one wins (`FR-054`, `SC-016`). Entering
`draining` closes admission before the daemon evaluates outstanding work.

## Exclusive ownership

Startup acquires an advisory lock inside the state directory before binding any
endpoint. Every loser returns `daemon.start_conflict` and mutates nothing
(`FR-001`, `SC-005`). The operating system releases the lock when the owning
process exits, so a crashed owner leaves no lock behind.

## Stop authority

Any authenticated native principal may request stop, including the MCP principal.
Extension and unauthenticated principals are denied before lifecycle mutation,
as recorded by `adr-7` (`FR-053`).
