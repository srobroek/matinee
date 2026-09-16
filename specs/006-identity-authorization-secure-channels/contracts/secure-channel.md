# Secure channel contract

The fixed context is `matinee.secure-channel.v1`. A state-bearing WebSocket route uses the
configured loopback endpoint, the expected route, and the versioned subprotocol. Health
may remain unauthenticated, and it carries no identity and no state.

In this contract, the channel client is the protocol peer for handshake messages. A `ChannelSession` caller is the module consumer that invokes the typed session operations after the handshake. The `mcp-client` principal kind identifies the authorization principal. It is not a name for the protocol peer or the module consumer.

## Handshake

1. The client sends the exact Spec 001 client hello. That hello carries these fields in
   order:
   - `LP("matinee.secure-channel.v1")`
   - `LP("client-hello")`
   - The exact configured endpoint bytes
   - `LP(principal_selector)`
   - The eight-byte authentication epoch
   - `LP(application_min)`
   - `LP(application_max)`
   - A 32-byte client nonce
   - A 65-byte ephemeral P-256 SEC1 public key
2. The daemon selects exactly the highest contract in the range intersection. It returns
   these fields:
   - The selected contract
   - The daemon ID
   - A 32-byte server nonce
   - A 65-byte ephemeral key
   - The connection ID

   The daemon signs `LP("server-proof") || client_hello` plus those returned fields. Any
   of these selections fails before key derivation:
   - A disjoint selection
   - A malformed selection
   - A substituted selection
   - A downgraded selection
3. The client verifies:
   - The pinned daemon public key
   - The expected identity
   - The selection
   - The 64-byte P1363 signature

   The client signs `LP("client-proof") || SHA256(server_proof_input) ||
   LP(server_signature)`.
4. The daemon verifies that client signature with the registered principal public key.
   Neither side sends a product payload until the transcript completes.
5. P-256 ECDH produces 32 bytes of input key material. HKDF-Extract uses
   `SHA256(client_proof_input || client_signature)` as salt. HKDF-Expand uses
   `LP("matinee.secure-channel.v1") || LP(selected_application_contract) ||
   LP(direction)` as info. For each direction, it produces one independent AES key of 32
   bytes.

Every integer uses unsigned big-endian encoding. `LP(x)` is a big-endian length of four
bytes followed by exact bytes. A string is exact UTF-8 without a terminator. A UUID is 16
raw bytes. A public key is exactly a 65-byte uncompressed SEC1 point. A signature is
exactly a 64-byte IEEE P1363 `(r || s)` value. These encodings are invalid:

- DER
- Compressed keys
- Alternate lengths
- Any other alternate encoding

## Stateful session boundary

After the handshake, `matinee-security` creates a stateful `ChannelSession`. Callers use
only two typed operations.

`receive(frame, typed_context)` validates the exact v1 frame. It performs these steps
in order:

- It checks the direction and the counter.
- It decrypts and authenticates the frame.
- It checks the current epoch and the lifecycle.
- It evaluates authorization.
- It filters object fields.
- It returns only an `AuthorizedInput`.

`send(AuthorizedOutput)` accepts an output whose filtering has already run. The session
privately selects these values and returns one frame:

- The version
- The UUID
- The counter
- The nonce
- The AAD
- The tag

These parts of the module stay private:

- Raw frame decoding
- Raw plaintext
- Transcript assembly
- Authorization policy

Callers cannot invoke any of these functions independently:

- `authenticate`
- `authorize`
- `encode_frame`
- `decode_frame`

A failed check returns a bounded failure and dispatches no contained payload. This holds
for each of these checks:

- Validation
- Decryption
- Epoch
- Lifecycle
- Authorization

## Exact v1 encrypted frame

The binary frame carries no new header field:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 1 | frame version `0x01` |
| 1 | 16 | raw connection UUID |
| 17 | 8 | unsigned big-endian counter |
| 25 | remaining | AES-GCM ciphertext followed by its 16-byte tag |

The counter is directional and starts at zero. It must equal the next value the receiver
expects. Any of these counter values closes the channel:

- A duplicate value
- A skipped value
- A wrapped value
- A wrong-direction value

After `u64::MAX`, the sender refuses to encrypt. The receiver accepts `u64::MAX` once.
After that one acceptance, the receiver closes and accepts no later value. A stale
epoch, a malformed frame, or an invalid tag closes the channel before dispatch.

The 12-byte AES-GCM nonce is `direction_u32_be || counter_u64_be`:

- `0x00000000` identifies client-to-daemon.
- `0x00000001` identifies daemon-to-client.

AAD is the first 25 frame bytes followed by these fields in order:

- `LP("matinee.secure-channel.v1")`
- `LP(selected_application_contract)`
- The eight-byte authentication epoch
- `LP(direction)`

A caller never selects any of these four AAD inputs:

- The context
- The contract
- The epoch
- The direction

## Limits and the no-fragmentation rule

At the inherited protocol-family boundary, an encoded frame is at most 1 MiB. A decrypted
message is at most 4 MiB. v1 has no secure-channel fragmentation and no reassembly. One
decrypted payload occupies one frame. The effective v1 plaintext maximum is therefore
`1,048,535` bytes (`1 MiB - 25-byte header - 16-byte tag`). Before encryption or
allocation, the module rejects a larger payload.

An application artifact stream uses the bounded artifact-chunk payload of Spec 001. Each
chunk occupies its own frame and contains at most 1,000,000 content bytes. Set the
declared length to consume the frame exactly. A stream may carry more than one independent
chunk frame. The module never buffers a continuation fragment, and it never accepts a
fragment identifier.

Before allocation, the module checks length prefixes and declared ciphertext lengths. Any
of these inputs closes the channel:

- An oversize input
- A malformed input
- An invalid-AEAD input
- An aggregate-limit input

The module returns one bounded protocol failure or one bounded resource failure.

## Routes and origin binding

The downstream route owner selects the route and the WebSocket subprotocol. The security
session accepts only these values:

- A configured loopback IP literal, either `127.0.0.1` or `::1`
- The expected route
- The expected subprotocol
- A transcript-bound endpoint

Pairing in production requires these further values:

- The pinned `chrome-extension://<id>` Origin
- The store ID
- The normal install type
- The update URL
- A supported version

Origin parsing is private security logic. It is not a public adapter.

## Conformance evidence

The native peer and the WebCrypto peer consume identical deterministic vectors. Vectors
include the valid handshake bytes and the valid frame bytes. Vectors also include one
mutation at every field boundary, for each of these fields:

- Endpoint
- Selector
- Epoch
- Contract range
- Nonce
- Key
- Signature
- Connection ID
- Header
- Direction
- Counter
- Ciphertext
- Tag
- Payload kind
- Length

Nonce vectors and AAD vectors cover both directions at counters zero, one, `u64::MAX`, and
overflow. Every invalid vector must close the channel and dispatch zero payloads.
