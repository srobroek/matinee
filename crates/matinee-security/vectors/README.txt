SECURE-CHANNEL-V1 VECTOR AND EVIDENCE CONTRACT
==============================================

Status
------
This file is the normative contract for `secure-channel-v1.json` and the native and
WebCrypto readers. It specifies data and evidence; it is not product code. T014/T015
must implement this contract without adding fields or interpreting unspecified values.
The vector directory contains no secrets: fixtures use deterministic public bytes,
synthetic labels, and redacted evidence only.

1. Deterministic serialization
------------------------------
The corpus is UTF-8 JSON, parsed with duplicate-key rejection, no insignificant
semantic defaults, and deterministic object keys in the order shown below. Writers
use UTF-8, LF line endings, no BOM, and canonical JSON numbers (non-negative integers
are decimal JSON integers; no exponent, fraction, or leading zero). Readers compare
bytes, not decoded-language objects, for every field declared `bytes`.

Top-level shape:

    {
      "schema": "matinee.secure-channel.v1",
      "schema_version": 1,
      "vectors": [ Vector... ],
      "evidence_schema": "matinee.security.evidence.v1"
    }

A Vector has exactly: `id` (ASCII lower-case kebab case), `kind` (`handshake` or
`frame`), `valid` (boolean), `inputs` (object), and `expect` (object). Invalid vectors
also have `mutation` with `field`, `boundary`, and `operation`; valid vectors MUST NOT
have `mutation`. `inputs` contains only the fields needed by its kind. Byte fields are
lower-case hexadecimal with an exact expected byte length; text is exact UTF-8; UUIDs
are 32 hex characters; counters/epochs are unsigned decimal integers in [0, 2^64-1].
No base64, implicit encoding, platform endianness, random value, wall clock, or omitted
field is permitted.

The valid handshake and frame bytes are included as `frame_hex`/`transcript_hex` and
are independently derivable from the named inputs. Handshake field order is the
secure-channel contract order. A frame is exactly version (1), UUID (16), counter (8),
then ciphertext and tag (16-byte tag); no framing or fragmentation field may appear.
AAD is derived, never caller-supplied: header || LP(context) || LP(contract) || epoch
|| LP(direction). Nonces are direction_u32_be || counter_u64_be.

2. Required valid cases and mutations
--------------------------------------
Every field below has one valid vector and at least one *single-field* invalid vector.
A mutation changes exactly the named field while all other input bytes remain identical.
Each mutation records the boundary being exercised and the expected bounded failure.

Handshake fields: context, hello label, endpoint, principal selector, epoch, minimum
contract, maximum contract, client nonce, client key (exact 65-byte uncompressed SEC1),
selected contract, daemon ID, server nonce, server key, connection ID, daemon key,
client key, and signature (exact 64-byte IEEE P1363). Frame fields: version, connection
ID, direction, counter, ciphertext, tag, payload kind, declared length, and payload.
Field mutations include empty/short, exact-boundary, one-over/one-under where meaningful,
substitution, truncation, extension, malformed UTF-8, DER key, compressed key, invalid
UUID, bad length prefix, altered tag, and altered ciphertext. A vector that mutates
multiple fields is an additional case and never substitutes for the single-field case.

Required boundary IDs (stable prefixes):

    valid.handshake, valid.frame
    mutate.handshake.<field>.<boundary>
    mutate.frame.<field>.<boundary>

At minimum, the set includes endpoint, selector, epoch, contract range, nonce, key,
signature, connection ID, header/version, direction, counter, ciphertext, tag, payload
kind, and length mutations. Contract negotiation includes disjoint, substituted,
and downgraded selections. Every invalid vector has `expect.result = "reject"`,
`expect.channel_state = "closed"`, `expect.dispatch_count = 0`, one stable failure
code, and `expect.secret_scan = "pass"`.

3. Nonce, AAD, counters, and limits
------------------------------------
For each direction (`0` client-to-daemon, `1` daemon-to-client), vectors MUST cover
counter 0, 1, 18446744073709551615 (`u64::MAX`), and the overflow attempt
`18446744073709551616` represented as a rejected out-of-range input (never wrapped).
Include duplicate, skipped, wrong-direction, and wrapped counter mutations. The sender
rejects encryption after MAX; the receiver accepts MAX exactly once, then closes. Each
case records nonce hex and AAD hex so native and WebCrypto outputs are byte-identical.

Payload limits MUST include zero bytes, one byte, the exact plaintext maximum 1,048,535
bytes, one byte over that maximum, exact encoded-frame maximum 1,048,576 bytes, and one
byte over. A declared length is checked before allocation. Include a forged four-byte
length prefix that requests an oversize allocation and a truncated body. Both must
reject before allocation, close, dispatch zero, and report `resource_limit` or
`malformed.input` as specified by the mutation.

Evidence records distinguish `allocation = "none"` (rejected before allocation),
`allocation = "bounded"` (allocation does not exceed the declared limit), and
`allocation = "maximum"` (the exact permitted maximum only). A reader MUST fail closed
if it cannot establish the allocation assertion; it must not turn an unsupported
measurement into a pass.

4. Evidence-record schema
--------------------------
Each runner writes one JSON line per vector, with no secret-bearing input echo:

    {
      "evidence_schema": "matinee.security.evidence.v1",
      "vector_id": "valid.frame",
      "runtime": "native" | "webcrypto",
      "result": "pass" | "fail" | "unsupported",
      "expected": "accept" | "reject",
      "failure_code": null | "malformed.input" | "resource_limit" | ...,
      "channel_state": "open" | "closed",
      "dispatch_count": 0,
      "allocation": "none" | "bounded" | "maximum",
      "nonce_hex": "<redacted-or-derived-byte-count>",
      "aad_hex": "<redacted-or-derived-byte-count>",
      "event": {
        "boundary": "channel",
        "code": "malformed.input",
        "outcome": "rejected",
        "safe_next_action": "discard_and_reconnect",
        "principal": null,
        "connection_id": null,
        "metadata": {}
      },
      "secret_scan": "pass"
    }

`failure_code` is null only for an accepted valid vector. `unsupported` is allowed only
when the runtime explicitly cannot provide the required capability; it is never a pass
and must carry a bounded failure/event plus `channel_state = "closed"` and
`dispatch_count = 0` for security-sensitive operations. Every record has exactly one
result, expected outcome, channel state, dispatch count, allocation assertion, event,
and secret scan. `dispatch_count` is zero for every reject; accepted vectors record the
single expected dispatch (or explicitly `0` for handshake-only vectors).

Event fields are bounded and checked: stable boundary/code/outcome/safe action, optional
safe UUIDs, typed time (fixture value only; no wall-clock dependency), state-directory
identity label, and redacted metadata (at most 8 entries; keys <=32 UTF-8 bytes, values
<=128 bytes, aggregate <=512 bytes; event <=2,048 bytes). Sink outcomes are exactly
`accepted`, `aggregated`, or `unavailable`. An unavailable required sink MUST produce
`event_sink.unavailable`, no protected mutation, closed channel, and zero dispatch.
Aggregation evidence covers 64 buckets and saturation at count 255.

5. Secret scanning and redaction
--------------------------------
The scanner runs over vector source, generated evidence, stderr/stdout captures, and
serialized events. It MUST pass with zero occurrences of private keys, PKCS#8 bytes,
enrollment secrets, credentials, cookies, authorization headers, payload text, full
URLs, or protected object identifiers. Public synthetic bytes are permitted only when
labeled and never reused as secret material. Scan decoded JSON values as well as raw
bytes; fail closed on scanner error, missing scan, or redaction uncertainty. Evidence
contains IDs and bounded labels only, never plaintext input or full frame plaintext.

6. Focused conformance and mutation checks
-------------------------------------------
After T014/T015 land, run from the workspace root:

    cargo test -p matinee-security --test secure_channel_faults -- --exact vector_schema
    cargo test -p matinee-security --test secure_channel_faults -- --exact mutation_coverage
    node crates/matinee-security/fixtures/webcrypto/secure-channel-vectors.mjs \
      --vectors crates/matinee-security/vectors/secure-channel-v1.json

The schema check MUST reject duplicate keys, non-canonical numbers, unknown required
shape, wrong hex lengths, absent mutation metadata, and secret-bearing strings. The
mutation check MUST prove one single-field mutation for every required field and all
counter/allocation boundaries above; it fails if any mutation is unexecuted, accepted,
dispatches payload, allocates before rejection, or lacks a redacted event. The native
and WebCrypto runs must produce identical `vector_id`, expected result, failure code,
channel state, dispatch count, allocation, event fields, and secret-scan outcome.
A focused run is successful only when valid vectors pass, every invalid vector rejects,
and no unsupported or secret-bearing record is silently counted as pass.

7. Contract-to-evidence checklist
----------------------------------
- [ ] Deterministic UTF-8 JSON, exact bytes, no secrets, no implicit defaults.
- [ ] Valid handshake/frame plus one isolated mutation at every listed field boundary.
- [ ] Nonce/AAD both directions at 0, 1, MAX, and explicit overflow rejection.
- [ ] Pre-allocation oversize/truncation rejection and exact maximum allocation.
- [ ] Closed channel and zero dispatch for every invalid case.
- [ ] Channel state, dispatch count, bounded allocation, event fields, sink outcome recorded.
- [ ] Secret scan covers source, evidence, captures, and events and fails closed.
- [ ] Native/WebCrypto results agree; unsupported is explicit and never a pass.
