# Authorization contract

Authorization runs inside `ChannelSession::receive`, which is stateful. The frame
validator is private and decrypts one payload first. That validator checks:

- The connection
- The counter
- The epoch
- The lifecycle

The session evaluates:

- The principal
- The negotiated contract
- The requested action
- The owner
- The capability ceiling
- The extension grant

The session returns only an `AuthorizedInput` typed for that permitted scope. A caller
cannot invoke an independent public `authorize` function. A caller cannot inspect
plaintext before this gate.

## Principal ceilings

The session applies these ceilings:

- **Native administrator**:
  - Global setup
  - Principal management
  - Rotation
  - Revocation
  - Every session retained under the local-state directory
  - Every request retained under the local-state directory
  - Every attention summary retained under the local-state directory
  - Every artifact retained under the local-state directory
  - Every diagnostic retained under the local-state directory
  - Every event retained under the local-state directory
- **MCP client**, limited to what it owns:
  - Its requests
  - Its sessions
  - Its resources
  - Its non-administrative actions
- **Browser extension**, limited to its own browser identity:
  - Its granted sessions
  - Its granted actions
  - No policy administration and no trusted decision

## Gate order and denial shape

The gate runs first. Object lookup serialization and mutation follow it. These object
reads return the indistinguishable `object.not_found` envelope:

- An unknown object
- A cross-owner object
- A filtered object
- An unauthorized object

An authorization failure contains only a stable boundary and code, a safe next action,
and an optional safe principal or connection ID. Such a failure never discloses:

- That a protected object exists
- Object counts
- Object titles
- Origins
- Payload
- Sensitive identifiers

## Filtering and epoch binding

Before `ChannelSession::send` receives a value, the session filters that
`AuthorizedOutput`. Filtering covers:

- Status
- Events
- Artifacts
- Bounded stream chunks

An extension grant is a subset of the principal ceiling and binds to the current
authentication epoch. Rotation, revocation, and a stale epoch each invalidate old grants
and old channels at the transition boundary.

## Inherited typed inputs

Spec 007 defines the typed transition outcomes. The security module receives them.
Spec 009 defines typed expiry and deadline results, and the module receives them too.
The module defines no persistence trait and no clock trait. Three downstream
specifications must not duplicate this gate: the daemon specification, the MCP
specification, and the extension specification.
