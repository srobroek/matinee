# Daemon Control Protocol

## Endpoint

The daemon listens on a configured loopback address. The default is
`http://127.0.0.1:3210`. Binding a non-loopback address is invalid configuration. HTTP
serves liveness and WebSocket upgrades only. Every state-bearing message uses an
authenticated encrypted WebSocket channel.

## Identity material

The daemon has one ECDSA P-256 identity keypair. Its private key lives in the platform
credential store. SQLite holds only its public key fingerprint. Every native or extension
principal has a separate ECDSA P-256 keypair. The principal stores its private key and
pinned daemon public key in the platform credential store or `chrome.storage.local`.
The daemon stores only each principal's public key, fingerprint, authentication epoch,
and revocation state in SQLite. Private keys never enter SQLite or a network message.

## Secure channel

The handshake protocol is the fixed context string `matinee.secure-channel.v1`; its only
cipher suite is P-256 ECDH, ECDSA-SHA-256, HKDF-SHA-256, and AES-256-GCM. A registered
principal and daemon establish a channel as follows:

1. The client sends a principal ID or registered key fingerprint, authentication epoch,
   supported contract range, random nonce, and ephemeral P-256 public key. It sends no
   private key or product payload.
2. The daemon selects one application contract in that range. It returns the selected
   contract, daemon ID, random nonce, ephemeral P-256 public key, and ECDSA-SHA-256
   signature over the fixed channel context plus the complete transcript. It rejects a
   disjoint range before channel creation.
3. The client verifies the pinned daemon public key, expected daemon ID, selection, and
   signature. It returns its ECDSA-SHA-256 signature over the fixed context and transcript.
4. The daemon verifies the registered principal public key and signature.
5. Both peers derive directional AES-256-GCM keys through P-256 ECDH and
   HKDF-SHA-256. HKDF binds the fixed channel context, both nonces, identities,
   authentication epoch, selected application contract, endpoint, and direction.
6. Each encrypted frame uses a strictly increasing 64-bit counter as authenticated
   associated data and nonce input. A repeated, skipped, wrapped, or wrong-direction
   counter closes the channel.

This exchange authenticates both peers and hides every product payload from a process
that squats on or observes the loopback port. A relay sees only authenticated ciphertext
and cannot alter it. The implementation uses reviewed cryptographic-library primitives
and fixed test vectors; it does not implement a cipher primitive.

## First native principal

The clean-install bootstrap uses two inherited operating-system pipes, not a network
route:

1. Setup creates a bootstrap ID and native ECDSA P-256 keypair. It stores the private
   key as `pending` in the platform credential store.
2. Setup starts the daemon with only the inheritable pipe handles. It sends the bootstrap
   ID, a random nonce, and its public key.
3. A daemon with no native principals creates or reuses its daemon identity. It returns
   a `prepared` record containing the nonce, daemon ID, daemon public key, and endpoint.
4. Setup pins that identity and returns a signature over the prepared record.
5. The daemon verifies the signature, commits the first principal with the bootstrap ID,
   and returns `committed`. Setup marks its credential active.

After a crash before commit, setup resumes with the same bootstrap ID and public key.
After a crash following commit, setup authenticates at `/v1/native` by key fingerprint
and recovers the principal ID. A matching committed bootstrap may return its existing
record through the inherited pipes. Any different bootstrap against an initialized state
fails. The daemon reuses credential-store identity material after a database or process
restart. The CLI never writes daemon state directly.

## Extension enrollment principal

Setup asks the authenticated daemon to create a pending extension enrollment. The daemon
generates a one-time ECDSA P-256 keypair. It stores only the public key with the expected
extension origin and expiry. It returns the PKCS#8 private key through the encrypted native
channel. The displayed enrollment bundle contains the endpoint, daemon identity, public
key, enrollment ID, one-time private key, and expiry.

The extension uses that one-time key as its `/v1/pair` identity and pins the daemon public
key. After it establishes the secure channel, it generates a fresh long-term ECDSA P-256
keypair and sends only the public key. The daemon consumes the enrollment and creates the
extension principal in one transaction. The extension then discards the one-time private
key. The bundle contains 256 random secret bits, expires after ten minutes, and works once.

## Routes

| Route | Method | Authentication | Purpose |
|---|---|---|---|
| `/v1/health` | GET | none | Process liveness only; returns no identity or state |
| `/v1/native` | WebSocket | native secure channel | CLI and MCP commands, authorized events, and bounded artifact streams |
| `/v1/pair` | WebSocket | pending-enrollment secure channel | Consume one extension enrollment |
| `/v1/extension` | WebSocket | extension secure channel | Authorized browser commands, events, and attention decisions |

## Object authorization

| Principal | Permitted scope |
|---|---|
| Native administrator | Global status, setup, doctor, stop, principal rotation and revocation, plus every retained local session, request, attention summary, artifact, diagnostic, and event |
| MCP client | Browser candidates from granted extension identities; sessions and requests it created; operations, attention summaries, artifacts, diagnostics, cancellation, and events owned by those requests |
| Browser extension | Its own browser candidates; sessions bound to its browser identity; commands for those sessions; operation events for those commands; decisions for attention requests designating that extension principal |

Authorization evaluates principal kind, capability ceiling, authentication epoch,
object owner, extension grant, and requested action. An unauthorized object identifier
returns the same `object.not_found` envelope as an unknown identifier. Status and event
streams filter objects before serialization. The daemon cannot delegate administrative
actions to an MCP client or approval decisions to a native principal.

## Encrypted frame

The WebSocket carries binary frames with this outer header:

```json
{
  "connection_id": "0199...",
  "counter": 42,
  "ciphertext": "base64url-aes-gcm"
}
```

`connection_id`, counter, direction, `matinee.secure-channel.v1`, selected application
contract, and authentication epoch form the authenticated associated data. The decrypted
payload is one command, response, event, or bounded stream chunk. Frames cannot exceed
1 MiB and decrypted messages cannot exceed 4 MiB.


## Command envelope

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

`command_id` deduplicates channel delivery. `idempotency_key` deduplicates the product
mutation. A request deadline can shorten but not extend daemon security or attention
deadlines.

## Response envelope

```json
{
  "contract": "matinee.daemon.v1",
  "command_id": "0199...",
  "ok": true,
  "result": {},
  "revision": 14
}
```

Failures use the common envelope. A success response means the corresponding durable
transition committed. A browser operation result means its completion transition
committed.

## Event envelope

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
that sequence, the daemon sends `resync_required`; the client reads authorized current
state. Events are hints. Reads return authoritative state.

## Limits

- WebSocket frame: 1 MiB.
- Decrypted message: 4 MiB.
- Artifact stream: 32 MiB per authorized artifact.
- Connected native clients: 16 by default.
- Connected extensions: one live connection per paired browser identity.
- Commands per native connection: 32 in flight.
- Request deadline: at most 30 minutes unless the request awaits attention.

Limits return `resource-limit` failures before allocating an unbounded body or queue.

## Configuration precedence

Ordinary configuration uses this precedence for keys allowed at each layer:

```text
defaults < user file < project file < environment < CLI
```

The state directory, daemon endpoint, principal selection, credential references,
trusted production extension identities, and development-extension allowance are
security-sensitive. Only the user file or an explicit CLI argument can set them. Project
files and environment variables containing those keys fail validation. No layer can
weaken loopback binding, mutual authentication, encryption, object authorization, origin
checks, sensitive-effect attention, secret redaction, or bounded messages.

User and state locations follow [cli.md](cli.md). Project configuration is `matinee.toml`
in the invocation's working directory; parent directories are not searched. Environment
keys use `MATINEE_` and double underscores for nesting.
