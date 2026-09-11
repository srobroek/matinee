# Daemon Control Protocol

## Endpoint

The daemon listens on a configured loopback address. The default is
`http://127.0.0.1:3210`. Binding a non-loopback address is invalid configuration.

## Native Authentication

CLI and MCP adapter requests send `Authorization: Bearer <credential>`. The daemon
hashes the credential, loads a non-revoked principal, applies its capability ceiling,
and records only the credential fingerprint. Missing, malformed, unknown, expired, or
revoked credentials receive the same unauthenticated response shape.

## Routes

| Route | Method | Authentication | Purpose |
|---|---|---|---|
| `/v1/health` | GET | none | Process liveness only; returns no state |
| `/v1/status` | GET | native bearer | Read readiness and redacted runtime state |
| `/v1/commands` | POST | native bearer | Submit one command envelope |
| `/v1/requests/{id}` | GET | native bearer | Read authoritative request state |
| `/v1/requests/{id}/cancel` | POST | native bearer | Persist cancellation intent |
| `/v1/events` | WebSocket | native bearer | Stream events visible to the principal |
| `/v1/artifacts/{id}` | GET | native bearer | Read an authorized redacted artifact |
| `/v1/pair` | WebSocket | pairing code and extension origin | Consume a pairing code |
| `/v1/extension` | WebSocket | extension bearer and origin | Serve extension commands and events |

## Command Envelope

```json
{
  "contract": "matinee.daemon.v1",
  "command_id": "0199...",
  "idempotency_key": "client-generated-key",
  "method": "session.open",
  "params": {},
  "deadline": "2026-09-11T12:00:00.000000Z"
}
```

`command_id` deduplicates transport delivery. `idempotency_key` deduplicates the
product mutation. A request deadline can shorten but not extend daemon security or
attention deadlines.

## Response Envelope

```json
{
  "contract": "matinee.daemon.v1",
  "command_id": "0199...",
  "ok": true,
  "result": {},
  "revision": 14
}
```

Failures use the common envelope. HTTP acceptance means the corresponding durable
transition committed. A browser operation result means its completion transition
committed.

## Native Event Envelope

```json
{
  "contract": "matinee.daemon.v1",
  "event_id": "0199...",
  "sequence": 42,
  "kind": "request.state_changed",
  "occurred_at": "2026-09-11T11:00:00.000000Z",
  "request_id": "0199...",
  "revision": 14,
  "payload": {}
}
```

A reconnect supplies the last observed sequence. If retained events no longer cover
that sequence, the daemon sends `resync_required`; the client reads current state.
Events are hints. Reads return authoritative state.

## Limits

- Native HTTP body: 1 MiB.
- WebSocket frame: 1 MiB.
- WebSocket message: 4 MiB.
- Connected native clients: 16 by default.
- Connected extensions: one live connection per paired browser identity.
- Commands per native connection: 32 in flight.
- Request deadline: at most 30 minutes unless the request is awaiting attention.

Limits return `resource-limit` failures before allocating an unbounded body or queue.

## Configuration Precedence

```text
defaults < user file < project file < environment < CLI
```

Each resolved value records its source. A higher layer changes only keys it defines.
The following floors cannot be weakened: loopback binding, authenticated mutation,
extension-origin checks, sensitive-effect attention, secret redaction, and bounded
messages.

User and state locations follow `contracts/cli.md`. Project configuration is
`matinee.toml` in the invocation's working directory; parent directories are not
searched. Environment keys use `MATINEE_` and double underscores for nesting.
