# Daemon Control Protocol

## Endpoint

The daemon listens on a configured loopback address. The default is
`http://127.0.0.1:3210`. Binding a non-loopback address is invalid configuration. HTTP
serves liveness and WebSocket upgrades only. Every state-bearing message uses an
authenticated encrypted WebSocket channel.

## Identity material

The daemon has one ECDSA P-256 identity keypair. Its private key lives in the platform
credential store. SQLite holds only its public key fingerprint. Every native or extension
principal has a separate ECDSA P-256 keypair. A key fingerprint is lowercase hexadecimal
SHA-256 over the exact 65-byte uncompressed SEC1 public key, with no prefix or separators.

The principal stores its private key and pinned daemon public key in the platform
credential store or `chrome.storage.local`. The daemon stores only each principal's
public key, fingerprint, authentication epoch, and revocation state in SQLite. Private
keys never enter SQLite or a network message.

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

## Wire encoding

All integers use unsigned big-endian encoding. `LP(x)` is a four-byte big-endian length
followed by the exact bytes of `x`. Protocol strings use UTF-8 without a terminator.
Identifiers use their 16 raw UUID bytes. A P-256 public key uses the 65-byte uncompressed
SEC1 form `0x04 || X || Y`. An ECDSA signature uses the fixed 64-byte IEEE P1363 form
`r || s`, with each integer left-padded to 32 bytes. DER signatures are invalid.

The client hello is the following concatenation, in order:

1. `LP("matinee.secure-channel.v1")` and `LP("client-hello")`.
2. `LP(endpoint)`, using the exact endpoint bytes stored during setup.
3. `LP(principal_selector)`, encoded as `id:<uuid>` or `fingerprint:<sha256-hex>`.
4. The eight-byte authentication epoch.
5. `LP(application_min)` and `LP(application_max)`.
6. `LP(client_nonce)` with exactly 32 random bytes.
7. `LP(client_ephemeral_key)` with exactly 65 SEC1 bytes.

The daemon signs `LP("server-proof") || client_hello` followed by these fields:

1. `LP(selected_application_contract)`.
2. `LP(daemon_id)` with 16 UUID bytes.
3. `LP(server_nonce)` with exactly 32 random bytes.
4. `LP(server_ephemeral_key)` with exactly 65 SEC1 bytes.
5. `LP(connection_id)` with 16 UUID bytes.

The client verifies the 64-byte server signature. It then signs
`LP("client-proof") || SHA256(server_proof_input) || LP(server_signature)`. The daemon
verifies that 64-byte client signature with the registered principal public key.

P-256 ECDH produces the 32-byte input key material. HKDF-Extract uses
`SHA256(client_proof_input || client_signature)` as salt. HKDF-Expand uses
`LP("matinee.secure-channel.v1") || LP(selected_application_contract) || LP(direction)`
as info and returns one 32-byte AES key for each direction. `direction` is exactly
`client-to-daemon` or `daemon-to-client`. Contract fixtures include valid bytes and one
mutation at every field boundary for Rust and WebCrypto.

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

The WebSocket carries binary frames with this layout:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | Frame version `0x01` |
| 1 | 16 | Raw connection UUID |
| 17 | 8 | Counter, unsigned big-endian |
| 25 | remaining | AES-GCM ciphertext followed by its 16-byte tag |

The counter starts at zero and increases by one per direction. The 12-byte AES-GCM nonce
is a four-byte direction value followed by the counter. The direction value is
`0x00000000` for client-to-daemon and `0x00000001` for daemon-to-client.

Authenticated associated data is the first 25 frame bytes followed by
`LP("matinee.secure-channel.v1")`, `LP(selected_application_contract)`, the eight-byte
authentication epoch, and `LP(direction)`. The decrypted payload is one command,
response, event, or bounded stream chunk. A frame cannot exceed 1 MiB. A decrypted
message cannot exceed 4 MiB.

Every decrypted frame starts with a one-byte payload kind. `0x01` contains one UTF-8 JSON
command, response, or event envelope. `0x02` contains an artifact chunk with this binary
layout: 16-byte stream UUID, four-byte sequence, eight-byte offset, four-byte content
length, then that many content bytes. Chunk integers are unsigned big-endian. Content is
at most 1,000,000 bytes and its declared length must consume the frame exactly.

An authorized artifact read starts with a JSON `stream.open` response containing:

- stream ID and artifact ID;
- media type and total byte count;
- content digest and chunk limit.

Chunk sequence starts at zero, and offset starts at zero. Neither value can skip or
repeat. A JSON `stream.complete` event contains stream ID, final chunk count, and digest.
A JSON `stream.abort` event contains stream ID and a safe failure.

The receiver exposes bytes only after it verifies the final byte count and digest. A
disconnect abandons the stream. A later authorized read creates a new stream. The daemon
permits at most four streams and 32 MiB in flight for each principal.


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
