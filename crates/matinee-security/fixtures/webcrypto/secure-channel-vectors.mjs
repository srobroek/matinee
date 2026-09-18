#!/usr/bin/env node
// The extension-side peer for `vectors/secure-channel-v1.json`.
//
// Three modes, all deterministic and all free of wall-clock, randomness, and secrets:
//   --generate            rewrite the corpus from the fixed scalars below
//   (default)             classify every corpus vector, one evidence line per vector
//   --campaign            classify the seeded SC-003 handshake corpus, one line per case
//
// The classifier is an independent implementation of the v1 wire contract: it does not
// share code with the Rust peer, so agreement between the two is evidence rather than
// tautology.
import { createECDH, webcrypto } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const { subtle } = webcrypto;
const CONTEXT = "matinee.secure-channel.v1";
const EVIDENCE_SCHEMA = "matinee.security.evidence.v1";
const ENDPOINT = "127.0.0.1:7777";
const PRINCIPAL = "00000000000000000000000000000002";
const DAEMON = "00000000000000000000000000000003";
const EXTENSION = "00000000000000000000000000000004";
const CONNECTION = "0000abcdefabcdefabcdefabcdefabcd";
const CLIENT_IDENTITY_SCALAR = "1".padStart(64, "0");
const DAEMON_IDENTITY_SCALAR = "2".padStart(64, "0");
const CLIENT_EPHEMERAL_SCALAR = "3".padStart(64, "0");
const SERVER_EPHEMERAL_SCALAR = "4".padStart(64, "0");
const CLIENT_NONCE = Buffer.alloc(32, 0xaa);
const SERVER_NONCE = Buffer.alloc(32, 0xbb);
const EPOCH = 7n;
const SELECTED = 3;
const CLIENT_MIN = 1;
const CLIENT_MAX = 3;
const SERVER_MIN = 2;
const SERVER_MAX = 4;

const LENGTH_LEN = 4;
const HEADER_LEN = 25;
const TAG_LEN = 16;
const MAX_FRAME = 1_048_576;
const MAX_PLAINTEXT = 1_048_535;
const MAX_PAYLOAD = 1_048_534;
const MAX_HANDSHAKE = 4_096;
const NONCE_LEN = 32;
const KEY_LEN = 65;
const SIGNATURE_LEN = 64;
const U64_MAX = (1n << 64n) - 1n;
const COMMAND_KIND = 1;

const AUTH_FAILED = "authentication.failed";
const CRYPTO_FAILED = "authentication.cryptographic";
const MALFORMED = "malformed.input";
const RESOURCE_LIMIT = "resource_limit";
const STALE_EPOCH = "stale_epoch";
const DOWNGRADE = "compatibility.downgrade";
const UNSUPPORTED_CONTRACT = "compatibility.unsupported";
const REPLAY = "replay.detected";
const COUNTER = "replay.counter";

function fail(message) { throw new Error(message); }
function bytes(hex) { return Buffer.from(hex, "hex"); }
function hex(value) { return Buffer.from(value).toString("hex"); }
function concat(...parts) { return Buffer.concat(parts.map((part) => Buffer.from(part))); }
function u32(value) { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; }
function lp(value) { const body = Buffer.from(value); return concat(u32(body.length), body); }
function text(value) { return Buffer.from(value, "utf8"); }
function contract(value) { return lp(text(String(value))); }
function b64url(value) { return Buffer.from(value).toString("base64url"); }
function uuidText(hexId) {
  const h = hexId;
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
function selectorFor(hexId) { return `id:${uuidText(hexId)}`; }
function equal(name, actual, expected) {
  if (actual !== expected) fail(`${name} mismatch\nactual:   ${actual}\nexpected: ${expected}`);
}

// ---------------------------------------------------------------------------
// P-256 point validation, mirroring `PublicKey::from_uncompressed`: 65 SEC1
// bytes, an uncompressed 0x04 tag, and a point that satisfies the curve.
// ---------------------------------------------------------------------------
const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function onCurve(key) {
  if (key.length !== KEY_LEN || key[0] !== 0x04) return false;
  const x = BigInt(`0x${hex(key.subarray(1, 33))}`);
  const y = BigInt(`0x${hex(key.subarray(33, 65))}`);
  if (x >= P || y >= P) return false;
  if (x === 0n && y === 0n) return false;
  const left = (y * y) % P;
  const right = (((x * x % P) * x % P) + (P - 3n) * x % P + B) % P;
  return left === right;
}

function publicFromScalar(scalarHex) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(Buffer.from(scalarHex, "hex"));
  return ecdh.getPublicKey();
}

function jwk(scalarHex) {
  const point = publicFromScalar(scalarHex);
  return {
    kty: "EC",
    crv: "P-256",
    d: b64url(Buffer.from(scalarHex, "hex")),
    x: b64url(point.subarray(1, 33)),
    y: b64url(point.subarray(33, 65)),
  };
}

async function signingKey(scalarHex) {
  return subtle.importKey("jwk", { ...jwk(scalarHex), key_ops: ["sign"], ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
}

async function verifyKey(scalarHex) {
  const point = publicFromScalar(scalarHex);
  return subtle.importKey("jwk", {
    kty: "EC", crv: "P-256",
    x: b64url(point.subarray(1, 33)), y: b64url(point.subarray(33, 65)),
    key_ops: ["verify"], ext: true,
  }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
}

async function agreementKey(scalarHex, usages) {
  return subtle.importKey("jwk", { ...jwk(scalarHex), key_ops: usages, ext: true },
    { name: "ECDH", namedCurve: "P-256" }, false, usages);
}

async function agreementPublic(scalarHex) {
  const point = publicFromScalar(scalarHex);
  return subtle.importKey("jwk", {
    kty: "EC", crv: "P-256",
    x: b64url(point.subarray(1, 33)), y: b64url(point.subarray(33, 65)), ext: true,
  }, { name: "ECDH", namedCurve: "P-256" }, false, []);
}

async function sha256(value) {
  return Buffer.from(await subtle.digest("SHA-256", value));
}

async function deriveKey(shared, salt, direction) {
  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const info = concat(lp(text(CONTEXT)), contract(SELECTED), lp(text(direction)));
  return Buffer.from(await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info }, material, 256,
  ));
}

// ---------------------------------------------------------------------------
// Client hello as an ordered, named segment list. A mutation rewrites exactly
// one segment, so "all other input bytes remain identical" is structural
// rather than a byte-offset search.
// ---------------------------------------------------------------------------
function helloSegments(facts) {
  return [
    { field: "context", body: text(CONTEXT), max: CONTEXT.length },
    { field: "hello-label", body: text("client-hello"), max: 12 },
    { field: "endpoint", body: text(facts.endpoint), max: 256 },
    { field: "principal-selector", body: text(facts.selector), max: 128 },
    { field: "epoch", body: u64(facts.epoch), raw: true },
    { field: "minimum-contract", body: text(String(facts.min)), max: 5 },
    { field: "maximum-contract", body: text(String(facts.max)), max: 5 },
    { field: "client-nonce", body: facts.nonce, max: NONCE_LEN },
    { field: "client-ephemeral-key", body: facts.ephemeral, max: KEY_LEN },
    { field: "client-key", body: facts.identity, max: KEY_LEN },
  ];
}

function encodeHello(segments) {
  const parts = [];
  for (const segment of segments) {
    if (segment.dropped) continue;
    if (segment.raw) { parts.push(Buffer.from(segment.body)); continue; }
    const declared = segment.declared ?? segment.body.length;
    parts.push(concat(u32(declared), segment.body));
  }
  return concat(...parts);
}

/// Rewrite exactly one named segment. `change` is one of `body`, `declared`
/// (a prefix that disagrees with the body it introduces), or `dropped`.
function mutateHello(segments, field, change) {
  let seen = false;
  const out = segments.map((segment) => {
    if (segment.field !== field) return segment;
    seen = true;
    return { ...segment, ...change };
  });
  if (!seen) fail(`unknown hello field ${field}`);
  return out;
}

// ---------------------------------------------------------------------------
// The independent v1 reader. Every reject carries the stable failure code the
// contract fixes for that boundary.
// ---------------------------------------------------------------------------
class Reject extends Error {
  constructor(code) { super(code); this.code = code; }
}
function reject(code) { throw new Reject(code); }

class Reader {
  constructor(input) { this.input = input; this.offset = 0; }

  raw(length) {
    const end = this.offset + length;
    if (end > this.input.length) reject(MALFORMED);
    const value = this.input.subarray(this.offset, end);
    this.offset = end;
    return value;
  }

  u64() { return this.raw(8).readBigUInt64BE(0); }

  lp(maximum) {
    const declared = this.raw(LENGTH_LEN).readUInt32BE(0);
    if (declared > maximum) reject(RESOURCE_LIMIT);
    return this.raw(declared);
  }

  exactLp(length) {
    const value = this.lp(length);
    if (value.length !== length) reject(MALFORMED);
    return value;
  }

  validPublicKey() {
    const key = this.exactLp(KEY_LEN);
    if (!onCurve(key)) reject(MALFORMED);
    return key;
  }

  expectLp(expected, maximum) {
    if (!this.lp(maximum).equals(Buffer.from(expected))) reject(AUTH_FAILED);
  }

  finish() {
    if (this.offset !== this.input.length) reject(MALFORMED);
  }
}

function parseContract(value) {
  const body = value.toString("latin1");
  if (!/^[0-9]+$/.test(body)) reject(MALFORMED);
  if (body.length > 1 && body.startsWith("0")) reject(MALFORMED);
  if (!Buffer.from(body, "utf8").equals(value)) reject(MALFORMED);
  const parsed = Number(body);
  if (!Number.isInteger(parsed) || parsed > 0xffff) reject(MALFORMED);
  return parsed;
}

function utf8OrReject(value) {
  const decoded = new TextDecoder("utf-8", { fatal: true });
  try { return decoded.decode(value); } catch { return reject(MALFORMED); }
}

function parseClientHello(input) {
  if (input.length > MAX_HANDSHAKE) reject(RESOURCE_LIMIT);
  const reader = new Reader(input);
  reader.expectLp(text(CONTEXT), CONTEXT.length);
  reader.expectLp(text("client-hello"), 12);
  const endpoint = utf8OrReject(reader.lp(256));
  const selector = utf8OrReject(reader.lp(128));
  const epoch = reader.u64();
  const min = parseContract(reader.lp(5));
  const max = parseContract(reader.lp(5));
  reader.exactLp(NONCE_LEN);
  reader.validPublicKey();
  const identity = reader.validPublicKey();
  reader.finish();
  return { endpoint, selector, epoch, min, max, identity };
}

function negotiate(clientMin, clientMax, serverMin, serverMax) {
  if (clientMin === 0 || serverMin === 0 || clientMin > clientMax || serverMin > serverMax) {
    reject(DOWNGRADE);
  }
  const minimum = Math.max(clientMin, serverMin);
  const maximum = Math.min(clientMax, serverMax);
  if (minimum > maximum) reject(UNSUPPORTED_CONTRACT);
  return maximum;
}

/// The daemon's hello admission, in the order `ServerHandshake::accept` fixes.
function classifyHello(helloBytes, expected) {
  const hello = parseClientHello(helloBytes);
  if (hello.endpoint !== expected.endpoint
    || hello.selector !== expected.selector
    || hex(hello.identity) !== expected.identityHex) {
    reject(AUTH_FAILED);
  }
  if (hello.epoch !== BigInt(expected.epoch)) reject(STALE_EPOCH);
  return negotiate(hello.min, hello.max, expected.serverMin, expected.serverMax);
}

// ---------------------------------------------------------------------------
// Frames
// ---------------------------------------------------------------------------
function frameHeader(connectionHex, counter) {
  return concat(Buffer.from([1]), bytes(connectionHex), u64(counter));
}

function frameAad(header, direction) {
  return concat(header, lp(text(CONTEXT)), contract(SELECTED), u64(EPOCH), lp(text(direction)));
}

function frameNonce(direction, counter) {
  return concat(u32(direction === "client-to-daemon" ? 0 : 1), u64(counter));
}

async function aesKey(key) {
  return subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function sealFrame(key, spec) {
  const payload = materialize(spec);
  if (payload.length > MAX_PAYLOAD) reject(RESOURCE_LIMIT);
  const plaintext = concat(Buffer.from([spec.kind ?? COMMAND_KIND]), payload);
  if (plaintext.length > MAX_PLAINTEXT) reject(RESOURCE_LIMIT);
  const header = frameHeader(spec.connection ?? CONNECTION, spec.counter ?? 0n);
  const direction = spec.direction ?? "client-to-daemon";
  const aad = frameAad(header, direction);
  const nonce = frameNonce(direction, spec.counter ?? 0n);
  const sealed = Buffer.from(await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    await aesKey(key), plaintext,
  ));
  const body = concat(header, sealed);
  return { plaintext, payload, header, nonce, aad, sealed, framed: concat(u32(body.length), body) };
}

/// Open one frame exactly as `ChannelState::open` does: declared length before
/// any body allocation, then version and connection, then the counter, then AEAD.
async function classifyFrame(framed, state) {
  if (framed.length < LENGTH_LEN) reject(MALFORMED);
  const declared = framed.readUInt32BE(0);
  if (declared > MAX_FRAME) reject(RESOURCE_LIMIT);
  if (declared < HEADER_LEN + TAG_LEN || framed.length !== LENGTH_LEN + declared) reject(MALFORMED);
  const frame = framed.subarray(LENGTH_LEN);
  const header = frame.subarray(0, HEADER_LEN);
  if (header[0] !== 1 || !header.subarray(1, 17).equals(bytes(state.connection))) reject(MALFORMED);
  const counter = header.readBigUInt64BE(17);
  if (state.exhausted || counter !== state.receiveCounter) {
    reject(counter < state.receiveCounter ? REPLAY : COUNTER);
  }
  const aad = frameAad(header, state.direction);
  const nonce = frameNonce(state.direction, counter);
  let plaintext;
  try {
    plaintext = Buffer.from(await subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      await aesKey(state.key), frame.subarray(HEADER_LEN),
    ));
  } catch { return reject(CRYPTO_FAILED); }
  if (plaintext.length > MAX_PLAINTEXT) reject(RESOURCE_LIMIT);
  if (plaintext.length === 0 || plaintext[0] !== COMMAND_KIND) reject(MALFORMED);
  if (plaintext.length - 1 > MAX_PAYLOAD) reject(RESOURCE_LIMIT);
  return { nonce, aad, payload: plaintext.subarray(1) };
}

/// Size-boundary vectors carry a repeat rule instead of a megabyte of hex.
function materialize(spec) {
  if (spec.payload_hex !== undefined) return bytes(spec.payload_hex);
  if (spec.payload_len === undefined) fail("vector declares neither payload_hex nor payload_len");
  return Buffer.alloc(spec.payload_len, bytes(spec.payload_repeat_byte_hex)[0]);
}

// ---------------------------------------------------------------------------
// Deterministic transcripts
// ---------------------------------------------------------------------------
function baseFacts() {
  return {
    endpoint: ENDPOINT,
    selector: selectorFor(PRINCIPAL),
    epoch: EPOCH,
    min: CLIENT_MIN,
    max: CLIENT_MAX,
    nonce: CLIENT_NONCE,
    ephemeral: publicFromScalar(CLIENT_EPHEMERAL_SCALAR),
    identity: publicFromScalar(CLIENT_IDENTITY_SCALAR),
  };
}

function serverProofInput(hello, daemonIdentityPublic, serverEphemeralPublic) {
  return concat(
    lp(text("server-proof")), hello,
    contract(SELECTED), contract(SERVER_MIN), contract(SERVER_MAX),
    lp(bytes(DAEMON)), lp(daemonIdentityPublic), lp(SERVER_NONCE),
    lp(serverEphemeralPublic), lp(bytes(CONNECTION)),
  );
}

async function clientProofInput(serverProof, serverSignature) {
  return concat(lp(text("client-proof")), await sha256(serverProof), lp(serverSignature));
}

async function deterministicParts(serverSignature, clientSignature) {
  const facts = baseFacts();
  const daemonIdentityPublic = publicFromScalar(DAEMON_IDENTITY_SCALAR);
  const serverEphemeralPublic = publicFromScalar(SERVER_EPHEMERAL_SCALAR);
  const hello = encodeHello(helloSegments(facts));
  const serverProof = serverProofInput(hello, daemonIdentityPublic, serverEphemeralPublic);
  const clientProof = serverSignature ? await clientProofInput(serverProof, serverSignature) : null;
  const clientPrivate = await agreementKey(CLIENT_EPHEMERAL_SCALAR, ["deriveBits"]);
  const serverPublic = await agreementPublic(SERVER_EPHEMERAL_SCALAR);
  const serverPrivate = await agreementKey(SERVER_EPHEMERAL_SCALAR, ["deriveBits"]);
  const clientPublic = await agreementPublic(CLIENT_EPHEMERAL_SCALAR);
  const clientShared = Buffer.from(await subtle.deriveBits(
    { name: "ECDH", public: serverPublic }, clientPrivate, 256));
  const serverShared = Buffer.from(await subtle.deriveBits(
    { name: "ECDH", public: clientPublic }, serverPrivate, 256));
  equal("ECDH peers", hex(clientShared), hex(serverShared));
  const salt = clientProof && clientSignature
    ? await sha256(concat(clientProof, clientSignature)) : null;
  return {
    facts,
    clientIdentityPublic: facts.identity,
    daemonIdentityPublic,
    clientEphemeralPublic: facts.ephemeral,
    serverEphemeralPublic,
    hello,
    serverProof,
    clientProof,
    shared: clientShared,
    salt,
    clientToDaemon: salt ? await deriveKey(clientShared, salt, "client-to-daemon") : null,
    daemonToClient: salt ? await deriveKey(clientShared, salt, "daemon-to-client") : null,
  };
}

async function signFixedInputs() {
  const initial = await deterministicParts(null, null);
  const daemonSigning = await signingKey(DAEMON_IDENTITY_SCALAR);
  const serverSignature = Buffer.from(await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, daemonSigning, initial.serverProof));
  if (serverSignature.length !== SIGNATURE_LEN) fail("WebCrypto did not produce P1363");
  const clientProof = await clientProofInput(initial.serverProof, serverSignature);
  const clientSigning = await signingKey(CLIENT_IDENTITY_SCALAR);
  const clientSignature = Buffer.from(await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, clientSigning, clientProof));
  if (clientSignature.length !== SIGNATURE_LEN) fail("WebCrypto did not produce P1363");
  return { serverSignature, clientSignature };
}

// ---------------------------------------------------------------------------
// The mutation tables. Every protocol field the contract fixes appears with at
// least one single-field mutation and its expected bounded failure.
// ---------------------------------------------------------------------------
const OTHER_KEY_HEX = hex(publicFromScalar(DAEMON_IDENTITY_SCALAR));

function derKeyBytes() {
  // An SPKI/DER-prefixed key of the right length and the wrong encoding.
  const out = Buffer.alloc(KEY_LEN);
  Buffer.from("3059301306072a8648ce3d020106082a8648ce3d030107034200", "hex").copy(out);
  return out;
}

function compressed(key) {
  const out = Buffer.from(key);
  out[0] = 0x02;
  return out;
}

const HANDSHAKE_MUTATIONS = [
  ["context", "substitution", "replace-context-label", AUTH_FAILED,
    (s) => mutateHello(s, "context", { body: text("matinee.secure-channel.v2") })],
  ["context", "malformed-utf8", "insert-invalid-utf8-byte", AUTH_FAILED,
    (s) => mutateHello(s, "context", { body: concat(text(CONTEXT.slice(0, 24)), Buffer.from([0xff])) })],
  ["hello-label", "substitution", "replace-hello-label", AUTH_FAILED,
    (s) => mutateHello(s, "hello-label", { body: text("client-hell0") })],
  ["endpoint", "substitution", "replace-endpoint", AUTH_FAILED,
    (s) => mutateHello(s, "endpoint", { body: text("127.0.0.1:7778") })],
  ["endpoint", "malformed-utf8", "replace-endpoint-byte-with-0xff", MALFORMED,
    (s) => mutateHello(s, "endpoint", { body: concat(text("127.0.0.1:777"), Buffer.from([0xff])) })],
  ["endpoint", "empty", "drop-endpoint-body", AUTH_FAILED,
    (s) => mutateHello(s, "endpoint", { body: Buffer.alloc(0) })],
  ["endpoint", "extension", "declare-endpoint-past-its-bound", RESOURCE_LIMIT,
    (s) => mutateHello(s, "endpoint", { declared: 257 })],
  ["principal-selector", "substitution", "replace-selector-identity", AUTH_FAILED,
    (s) => mutateHello(s, "principal-selector", { body: text(selectorFor(EXTENSION)) })],
  ["principal-selector", "invalid-uuid", "replace-uuid-text-with-non-uuid", AUTH_FAILED,
    (s) => mutateHello(s, "principal-selector", { body: text("id:zzzzzzzz-0000-0000-0000-000000000002") })],
  ["epoch", "one-over", "increment-epoch", STALE_EPOCH,
    (s) => mutateHello(s, "epoch", { body: u64(EPOCH + 1n) })],
  ["epoch", "one-under", "decrement-epoch", STALE_EPOCH,
    (s) => mutateHello(s, "epoch", { body: u64(EPOCH - 1n) })],
  ["epoch", "truncation", "drop-one-epoch-byte", RESOURCE_LIMIT,
    (s) => mutateHello(s, "epoch", { body: u64(EPOCH).subarray(0, 7) })],
  ["minimum-contract", "disjoint", "raise-minimum-past-maximum", DOWNGRADE,
    (s) => mutateHello(s, "minimum-contract", { body: text("4") })],
  ["minimum-contract", "leading-zero", "non-canonical-contract-number", MALFORMED,
    (s) => mutateHello(s, "minimum-contract", { body: text("01") })],
  ["minimum-contract", "empty", "drop-minimum-body", MALFORMED,
    (s) => mutateHello(s, "minimum-contract", { body: Buffer.alloc(0) })],
  ["maximum-contract", "disjoint", "lower-maximum-below-server-minimum", UNSUPPORTED_CONTRACT,
    (s) => mutateHello(s, "maximum-contract", { body: text("1") })],
  ["maximum-contract", "one-over", "declare-contract-past-its-bound", RESOURCE_LIMIT,
    (s) => mutateHello(s, "maximum-contract", { declared: 6 })],
  ["client-nonce", "short", "thirty-one-byte-nonce", MALFORMED,
    (s) => mutateHello(s, "client-nonce", { body: CLIENT_NONCE.subarray(0, 31) })],
  ["client-nonce", "extension", "thirty-three-byte-nonce", RESOURCE_LIMIT,
    (s) => mutateHello(s, "client-nonce", { body: concat(CLIENT_NONCE, Buffer.from([0xaa])) })],
  ["client-nonce", "empty", "zero-length-nonce", MALFORMED,
    (s) => mutateHello(s, "client-nonce", { body: Buffer.alloc(0) })],
  ["client-ephemeral-key", "compressed-key", "set-compressed-sec1-tag", MALFORMED,
    (s) => mutateHello(s, "client-ephemeral-key", { body: compressed(baseFacts().ephemeral) })],
  ["client-ephemeral-key", "der-key", "replace-point-with-der-encoding", MALFORMED,
    (s) => mutateHello(s, "client-ephemeral-key", { body: derKeyBytes() })],
  ["client-ephemeral-key", "truncation", "sixty-four-byte-point", MALFORMED,
    (s) => mutateHello(s, "client-ephemeral-key", { body: baseFacts().ephemeral.subarray(0, 64) })],
  ["client-key", "substitution", "present-the-daemon-point", AUTH_FAILED,
    (s) => mutateHello(s, "client-key", { body: bytes(OTHER_KEY_HEX) })],
  ["client-key", "compressed-key", "set-compressed-sec1-tag", MALFORMED,
    (s) => mutateHello(s, "client-key", { body: compressed(baseFacts().identity) })],
  ["client-key", "bad-length-prefix", "declare-sixty-six-byte-point", RESOURCE_LIMIT,
    (s) => mutateHello(s, "client-key", { declared: KEY_LEN + 1 })],
  ["client-key", "empty", "drop-the-identity-point", MALFORMED,
    (s) => mutateHello(s, "client-key", { dropped: true })],
];

/// Whole-artifact handshake mutations: the field is the transcript envelope.
const HANDSHAKE_ENVELOPE_MUTATIONS = [
  ["transcript-length", "extension", "append-one-trailing-byte", MALFORMED,
    (hello) => concat(hello, Buffer.from([0x00]))],
  ["transcript-length", "truncation", "drop-the-last-byte", MALFORMED,
    (hello) => hello.subarray(0, hello.length - 1)],
  ["transcript-length", "one-over", "pad-past-the-handshake-maximum", RESOURCE_LIMIT,
    (hello) => concat(hello, Buffer.alloc(MAX_HANDSHAKE + 1 - hello.length, 0x00))],
];

/// Signature mutations are verified against the transcript, not parsed from it.
const SIGNATURE_MUTATIONS = [
  ["signature", "altered-bit", "flip-one-signature-bit", AUTH_FAILED],
  ["signature", "truncation", "sixty-three-byte-signature", MALFORMED],
  ["signature", "extension", "sixty-five-byte-signature", MALFORMED],
];

/// The fields the daemon contributes live in the server proof, which the client
/// parses and the daemon signs. A peer replaying a vector does not hold the
/// daemon's private key, so the production check that catches a mutation here is
/// verification of the fixed signature over the recomputed transcript: change any
/// one of these inputs and the transcript no longer matches what was signed.
const TRANSCRIPT_FIELD_MUTATIONS = [
  ["selected-contract", "downgraded", "select-below-the-negotiated-maximum",
    { selected_contract: 2 }],
  ["selected-contract", "substituted", "select-outside-the-client-range",
    { selected_contract: 4 }],
  ["selected-contract", "disjoint", "select-a-contract-neither-peer-offered",
    { selected_contract: 9 }],
  ["daemon-id", "substitution", "replace-the-daemon-identity",
    { daemon_id_hex: EXTENSION }],
  ["daemon-key", "substitution", "present-the-client-point-as-the-daemon-key",
    { daemon_identity_public_hex: hex(publicFromScalar(CLIENT_IDENTITY_SCALAR)) }],
  ["server-nonce", "substitution", "replace-the-server-nonce",
    { server_nonce_hex: hex(Buffer.alloc(NONCE_LEN, 0xcc)) }],
  ["server-key", "substitution", "replace-the-server-ephemeral-point",
    { server_ephemeral_public_hex: hex(publicFromScalar(CLIENT_EPHEMERAL_SCALAR)) }],
  ["connection-id", "substitution", "replace-the-connection-uuid",
    { connection_id_hex: PRINCIPAL }],
];

const FRAME_MUTATIONS = [
  ["version", "substitution", "set-frame-version-two", MALFORMED,
    (f) => { const o = Buffer.from(f); o[LENGTH_LEN] = 2; return o; }],
  ["version", "one-over", "set-frame-version-to-0xff", MALFORMED,
    (f) => { const o = Buffer.from(f); o[LENGTH_LEN] = 0xff; return o; }],
  ["connection-id", "substitution", "replace-connection-uuid", MALFORMED,
    (f) => { const o = Buffer.from(f); bytes(PRINCIPAL).copy(o, LENGTH_LEN + 1); return o; }],
  ["connection-id", "invalid-uuid", "zero-the-connection-uuid", MALFORMED,
    (f) => { const o = Buffer.from(f); Buffer.alloc(16).copy(o, LENGTH_LEN + 1); return o; }],
  ["ciphertext", "altered-ciphertext", "flip-one-ciphertext-bit", CRYPTO_FAILED,
    (f) => { const o = Buffer.from(f); o[LENGTH_LEN + HEADER_LEN] ^= 1; return o; }],
  ["tag", "altered-tag", "flip-one-tag-bit", CRYPTO_FAILED,
    (f) => { const o = Buffer.from(f); o[o.length - 1] ^= 1; return o; }],
  ["tag", "truncation", "drop-one-tag-byte", CRYPTO_FAILED,
    (f) => { const body = f.subarray(LENGTH_LEN, f.length - 1); return concat(u32(body.length), body); }],
  ["declared-length", "bad-length-prefix", "forge-a-four-gigabyte-prefix", RESOURCE_LIMIT,
    (f) => { const o = Buffer.from(f); o.writeUInt32BE(0xffffffff, 0); return o; }],
  ["declared-length", "one-over", "declare-one-past-the-frame-maximum", RESOURCE_LIMIT,
    (f) => { const o = Buffer.from(f); o.writeUInt32BE(MAX_FRAME + 1, 0); return o; }],
  ["declared-length", "one-under", "declare-below-header-plus-tag", MALFORMED,
    (f) => { const o = Buffer.from(f); o.writeUInt32BE(HEADER_LEN + TAG_LEN - 1, 0); return o; }],
  ["declared-length", "truncation", "keep-the-prefix-and-drop-a-body-byte", MALFORMED,
    (f) => f.subarray(0, f.length - 1)],
  ["declared-length", "extension", "keep-the-prefix-and-append-a-body-byte", MALFORMED,
    (f) => concat(f, Buffer.from([0x00]))],
  ["declared-length", "empty", "three-byte-frame", MALFORMED,
    (f) => f.subarray(0, 3)],
];

/// Frame cases whose mutation is in the sealed inputs, not the encoded bytes.
/// Each names the session state it is replayed against.
const FRAME_STATE_CASES = [
  {
    id: "valid.frame.client-to-daemon.counter-1", valid: true,
    seal: { counter: 1n, payload_hex: "01020304" },
    state: { receiveCounter: "1" }, allocation: "bounded",
  },
  {
    id: "valid.frame.client-to-daemon.counter-maximum", valid: true,
    seal: { counter: U64_MAX, payload_hex: "01020304" },
    state: { receiveCounter: U64_MAX.toString() }, allocation: "bounded",
  },
  {
    id: "valid.frame.daemon-to-client.counter-0", valid: true,
    seal: { direction: "daemon-to-client", counter: 0n, payload_hex: "01020304" },
    state: { direction: "daemon-to-client", receiveCounter: "0" }, allocation: "bounded",
  },
  {
    id: "valid.frame.daemon-to-client.counter-1", valid: true,
    seal: { direction: "daemon-to-client", counter: 1n, payload_hex: "01020304" },
    state: { direction: "daemon-to-client", receiveCounter: "1" }, allocation: "bounded",
  },
  {
    id: "valid.frame.daemon-to-client.counter-maximum", valid: true,
    seal: { direction: "daemon-to-client", counter: U64_MAX, payload_hex: "01020304" },
    state: { direction: "daemon-to-client", receiveCounter: U64_MAX.toString() },
    allocation: "bounded",
  },
  {
    id: "valid.frame.payload.zero", valid: true,
    seal: { counter: 0n, payload_hex: "" }, state: { receiveCounter: "0" }, allocation: "bounded",
  },
  {
    id: "valid.frame.payload.one", valid: true,
    seal: { counter: 0n, payload_hex: "5a" }, state: { receiveCounter: "0" }, allocation: "bounded",
  },
  {
    id: "valid.frame.payload.exact-maximum", valid: true,
    seal: { counter: 0n, payload_len: MAX_PAYLOAD, payload_repeat_byte_hex: "5a" },
    state: { receiveCounter: "0" }, allocation: "maximum",
  },
  {
    id: "mutate.frame.counter.duplicate", valid: false,
    mutation: { field: "counter", boundary: "duplicate", operation: "replay-a-consumed-counter" },
    seal: { counter: 0n, payload_hex: "01020304" },
    state: { receiveCounter: "1" }, failure_code: REPLAY, allocation: "none",
  },
  {
    id: "mutate.frame.counter.skipped", valid: false,
    mutation: { field: "counter", boundary: "skipped", operation: "skip-four-counters" },
    seal: { counter: 5n, payload_hex: "01020304" },
    state: { receiveCounter: "0" }, failure_code: COUNTER, allocation: "none",
  },
  {
    id: "mutate.frame.counter.wrapped", valid: false,
    mutation: { field: "counter", boundary: "wrapped", operation: "wrap-past-the-maximum-to-zero" },
    seal: { counter: 0n, payload_hex: "01020304" },
    state: { receiveCounter: U64_MAX.toString() }, failure_code: REPLAY, allocation: "none",
  },
  {
    id: "mutate.frame.counter.exact-boundary", valid: false,
    mutation: { field: "counter", boundary: "exact-boundary", operation: "reuse-the-maximum-after-it-closed" },
    seal: { counter: U64_MAX, payload_hex: "01020304" },
    state: { receiveCounter: U64_MAX.toString(), exhausted: true },
    failure_code: COUNTER, allocation: "none",
  },
  {
    id: "mutate.frame.direction.wrong-direction", valid: false,
    mutation: { field: "direction", boundary: "wrong-direction", operation: "seal-for-the-opposite-direction" },
    seal: { direction: "daemon-to-client", counter: 0n, payload_hex: "01020304" },
    state: { direction: "client-to-daemon", receiveCounter: "0" },
    failure_code: CRYPTO_FAILED, allocation: "bounded",
  },
  {
    id: "mutate.frame.payload-kind.substitution", valid: false,
    mutation: { field: "payload-kind", boundary: "substitution", operation: "seal-a-response-shape" },
    seal: { counter: 0n, kind: 2, payload_hex: "01020304" },
    state: { receiveCounter: "0" }, failure_code: MALFORMED, allocation: "bounded",
  },
  {
    id: "mutate.frame.payload.one-over", valid: false,
    mutation: { field: "payload", boundary: "one-over", operation: "one-byte-past-the-plaintext-maximum" },
    seal: { counter: 0n, payload_len: MAX_PAYLOAD + 1, payload_repeat_byte_hex: "5a" },
    state: { receiveCounter: "0" }, failure_code: RESOURCE_LIMIT, allocation: "none",
    sender_rejects: true,
  },
  {
    id: "mutate.frame.counter.overflow", valid: false,
    mutation: { field: "counter", boundary: "overflow", operation: "declare-two-to-the-sixty-four" },
    counter_text: "18446744073709551616",
    state: { receiveCounter: "0" }, failure_code: MALFORMED, allocation: "none",
    out_of_range_counter: true,
  },
];

// ---------------------------------------------------------------------------
// Corpus generation
// ---------------------------------------------------------------------------
function expectBlock(valid, code, allocation, dispatch) {
  return {
    result: valid ? "accept" : "reject",
    failure_code: valid ? null : code,
    channel_state: valid ? "open" : "closed",
    dispatch_count: dispatch,
    allocation,
    secret_scan: "pass",
  };
}

/// ECDSA signing is randomised, so a freshly minted signature would change the
/// salt and every traffic key derived from it and the corpus would not be
/// byte-reproducible. The signatures are therefore minted once and pinned: a
/// regeneration reuses them, and `--mint-signatures` is the deliberate way to
/// roll them. A pinned signature that does not verify fails closed here.
async function generate(pinned) {
  const { serverSignature, clientSignature } = pinned ?? (await signFixedInputs());
  const parts = await deterministicParts(serverSignature, clientSignature);
  if (pinned) {
    const serverOk = await subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      await verifyKey(DAEMON_IDENTITY_SCALAR), serverSignature, parts.serverProof);
    const clientOk = await subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      await verifyKey(CLIENT_IDENTITY_SCALAR), clientSignature, parts.clientProof);
    if (!serverOk || !clientOk) fail("a pinned signature no longer verifies");
  }
  const base = helloSegments(parts.facts);
  const key = parts.clientToDaemon;
  const validFrame = await sealFrame(key, { counter: 0n, payload_hex: "01020304" });
  const vectors = [];

  vectors.push({
    id: "valid.handshake",
    kind: "handshake",
    valid: true,
    inputs: {
      endpoint: ENDPOINT,
      principal_id_hex: PRINCIPAL,
      daemon_id_hex: DAEMON,
      connection_id_hex: CONNECTION,
      epoch: Number(EPOCH),
      client_contract_min: CLIENT_MIN,
      client_contract_max: CLIENT_MAX,
      server_contract_min: SERVER_MIN,
      server_contract_max: SERVER_MAX,
      selected_contract: SELECTED,
      client_nonce_hex: hex(CLIENT_NONCE),
      server_nonce_hex: hex(SERVER_NONCE),
      client_identity_public_hex: hex(parts.clientIdentityPublic),
      daemon_identity_public_hex: hex(parts.daemonIdentityPublic),
      client_ephemeral_public_hex: hex(parts.clientEphemeralPublic),
      server_ephemeral_public_hex: hex(parts.serverEphemeralPublic),
      client_hello_hex: hex(parts.hello),
      transcript_hex: hex(parts.serverProof),
      server_proof_input_hex: hex(parts.serverProof),
      server_signature_p1363_hex: hex(serverSignature),
      client_proof_input_hex: hex(parts.clientProof),
      client_signature_p1363_hex: hex(clientSignature),
      ecdh_shared_secret_hex: hex(parts.shared),
      hkdf_salt_hex: hex(parts.salt),
      client_to_daemon_key_hex: hex(parts.clientToDaemon),
      daemon_to_client_key_hex: hex(parts.daemonToClient),
    },
    expect: expectBlock(true, null, "bounded", 0),
  });

  vectors.push({
    id: "valid.frame",
    kind: "frame",
    valid: true,
    inputs: {
      base: "valid.handshake",
      direction: "client-to-daemon",
      counter: "0",
      receive_counter: "0",
      payload_kind: "command",
      plaintext_hex: hex(validFrame.plaintext),
      application_payload_hex: hex(validFrame.payload),
      payload_hex: hex(validFrame.payload),
      header_hex: hex(validFrame.header),
      nonce_hex: hex(validFrame.nonce),
      aad_hex: hex(validFrame.aad),
      ciphertext_and_tag_hex: hex(validFrame.sealed),
      framed_hex: hex(validFrame.framed),
    },
    expect: expectBlock(true, null, "bounded", 1),
  });

  for (const [field, boundary, operation, code, mutate] of HANDSHAKE_MUTATIONS) {
    vectors.push({
      id: `mutate.handshake.${field}.${boundary}`,
      kind: "handshake",
      valid: false,
      mutation: { field, boundary, operation },
      inputs: { base: "valid.handshake", client_hello_hex: hex(encodeHello(mutate(base))) },
      expect: expectBlock(false, code, "none", 0),
    });
  }

  for (const [field, boundary, operation, code, mutate] of HANDSHAKE_ENVELOPE_MUTATIONS) {
    vectors.push({
      id: `mutate.handshake.${field}.${boundary}`,
      kind: "handshake",
      valid: false,
      mutation: { field, boundary, operation },
      inputs: { base: "valid.handshake", client_hello_hex: hex(mutate(parts.hello)) },
      expect: expectBlock(false, code, "none", 0),
    });
  }

  for (const [field, boundary, operation, code] of SIGNATURE_MUTATIONS) {
    let signature = Buffer.from(serverSignature);
    if (boundary === "altered-bit") signature[0] ^= 1;
    if (boundary === "truncation") signature = signature.subarray(0, SIGNATURE_LEN - 1);
    if (boundary === "extension") signature = concat(signature, Buffer.from([0x00]));
    vectors.push({
      id: `mutate.handshake.${field}.${boundary}`,
      kind: "handshake",
      valid: false,
      mutation: { field, boundary, operation },
      inputs: {
        base: "valid.handshake",
        transcript_hex: hex(parts.serverProof),
        server_signature_p1363_hex: hex(signature),
      },
      expect: expectBlock(false, code, "none", 0),
    });
  }

  for (const [field, boundary, operation, override] of TRANSCRIPT_FIELD_MUTATIONS) {
    const facts = {
      selected_contract: SELECTED,
      server_contract_min: SERVER_MIN,
      server_contract_max: SERVER_MAX,
      daemon_id_hex: DAEMON,
      daemon_identity_public_hex: hex(parts.daemonIdentityPublic),
      server_nonce_hex: hex(SERVER_NONCE),
      server_ephemeral_public_hex: hex(parts.serverEphemeralPublic),
      connection_id_hex: CONNECTION,
      ...override,
    };
    vectors.push({
      id: `mutate.handshake.${field}.${boundary}`,
      kind: "handshake",
      valid: false,
      mutation: { field, boundary, operation },
      inputs: {
        base: "valid.handshake",
        rebuild_transcript: true,
        client_hello_hex: hex(parts.hello),
        ...facts,
        server_signature_p1363_hex: hex(serverSignature),
      },
      expect: expectBlock(false, AUTH_FAILED, "none", 0),
    });
  }

  for (const [field, boundary, operation, code, mutate] of FRAME_MUTATIONS) {
    vectors.push({
      id: `mutate.frame.${field}.${boundary}`,
      kind: "frame",
      valid: false,
      mutation: { field, boundary, operation },
      inputs: {
        base: "valid.frame",
        direction: "client-to-daemon",
        receive_counter: "0",
        framed_hex: hex(mutate(validFrame.framed)),
      },
      // The body is copied only to attempt AEAD, so a cryptographic rejection is
      // the first one that allocates; everything earlier rejects before any copy.
      expect: expectBlock(false, code, code === CRYPTO_FAILED ? "bounded" : "none", 0),
    });
  }

  for (const entry of FRAME_STATE_CASES) {
    const inputs = {
      base: "valid.frame",
      direction: entry.state.direction ?? "client-to-daemon",
      receive_counter: entry.state.receiveCounter,
    };
    if (entry.state.exhausted) inputs.receive_exhausted = true;
    if (entry.out_of_range_counter) {
      inputs.counter_text = entry.counter_text;
    } else {
      inputs.counter = (entry.seal.counter ?? 0n).toString();
      if (entry.seal.kind !== undefined) inputs.payload_kind_code = entry.seal.kind;
      if (entry.seal.payload_hex !== undefined) {
        inputs.payload_hex = entry.seal.payload_hex;
        const sealed = await sealFrame(
          (entry.seal.direction ?? "client-to-daemon") === "client-to-daemon"
            ? parts.clientToDaemon : parts.daemonToClient,
          entry.seal,
        );
        inputs.framed_hex = hex(sealed.framed);
      } else {
        inputs.payload_len = entry.seal.payload_len;
        inputs.payload_repeat_byte_hex = entry.seal.payload_repeat_byte_hex;
      }
      if (entry.sender_rejects) inputs.sender_rejects = true;
    }
    const vector = {
      id: entry.id,
      kind: "frame",
      valid: entry.valid,
      inputs,
      expect: expectBlock(entry.valid, entry.failure_code ?? null, entry.allocation,
        entry.valid ? 1 : 0),
    };
    if (!entry.valid) {
      vectors.push({
        id: vector.id, kind: vector.kind, valid: false,
        mutation: entry.mutation, inputs: vector.inputs, expect: vector.expect,
      });
    } else {
      vectors.push(vector);
    }
  }

  return { schema: CONTEXT, schema_version: 1, vectors, evidence_schema: EVIDENCE_SCHEMA };
}

// ---------------------------------------------------------------------------
// Corpus verification: one evidence line per vector, per-label results.
// ---------------------------------------------------------------------------
/// Content that must never reach a vector or an evidence record. Field labels
/// such as `ecdh_shared_secret_hex` are labels, not material, so the scan runs
/// over values only.
///
/// A private scalar is checked as a whole value rather than as a substring: the
/// fixture scalars are zero-padded, so `000…04` occurs by coincidence inside any
/// zero-padded blob (a DER-encoded key, for one) and a substring rule would fire
/// on data that carries no key at all. A leaked scalar appears as its own field
/// value, which is what this matches. The base64url form is distinctive enough to
/// scan as a substring and catches a leaked JWK.
const SECRET_VALUES = [
  CLIENT_IDENTITY_SCALAR, DAEMON_IDENTITY_SCALAR,
  CLIENT_EPHEMERAL_SCALAR, SERVER_EPHEMERAL_SCALAR,
].map((scalar) => scalar.toLowerCase());

const SECRET_MARKERS = [
  ...SECRET_VALUES.map((scalar) => b64url(Buffer.from(scalar, "hex")).toLowerCase()),
  "-----begin", "private key", "pkcs8", "cookie:", "authorization:",
  "password", "https://", "http://",
];

function scanValues(node, found) {
  if (typeof node === "string") {
    const lowered = node.toLowerCase();
    if (SECRET_VALUES.includes(lowered)) found.push("private-scalar");
    for (const marker of SECRET_MARKERS) {
      if (lowered.includes(marker)) found.push(marker);
    }
    return found;
  }
  if (Array.isArray(node)) {
    for (const item of node) scanValues(item, found);
    return found;
  }
  if (node && typeof node === "object") {
    for (const value of Object.values(node)) scanValues(value, found);
  }
  return found;
}

function secretScan(node) {
  return scanValues(node, []).length === 0 ? "pass" : "fail";
}

function evidence(vector, result, code, nonceBytes, aadBytes) {
  const expected = vector.valid ? "accept" : "reject";
  return {
    evidence_schema: EVIDENCE_SCHEMA,
    vector_id: vector.id,
    runtime: "webcrypto",
    result,
    expected,
    failure_code: code,
    channel_state: vector.valid ? "open" : "closed",
    dispatch_count: vector.valid && vector.kind === "frame" ? 1 : 0,
    allocation: vector.expect.allocation,
    nonce_hex: nonceBytes === null ? "redacted" : `derived:${nonceBytes}`,
    aad_hex: aadBytes === null ? "redacted" : `derived:${aadBytes}`,
    event: {
      boundary: "channel",
      code: code ?? null,
      outcome: vector.valid ? "accepted" : "rejected",
      safe_next_action: vector.valid ? "continue" : "discard_and_reconnect",
      principal: null,
      connection_id: null,
      metadata: {},
    },
    secret_scan: secretScan(vector),
  };
}

async function classifyHandshakeVector(vector, reference, keys) {
  const inputs = vector.inputs;
  if (inputs.server_signature_p1363_hex !== undefined && inputs.client_hello_hex === undefined) {
    const signature = bytes(inputs.server_signature_p1363_hex);
    const transcript = bytes(inputs.transcript_hex);
    if (signature.length !== SIGNATURE_LEN) reject(MALFORMED);
    const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      await verifyKey(DAEMON_IDENTITY_SCALAR), signature, transcript);
    if (!ok) reject(AUTH_FAILED);
    return null;
  }
  if (inputs.rebuild_transcript === true) {
    const transcript = concat(
      lp(text("server-proof")), bytes(inputs.client_hello_hex),
      contract(inputs.selected_contract),
      contract(inputs.server_contract_min), contract(inputs.server_contract_max),
      lp(bytes(inputs.daemon_id_hex)), lp(bytes(inputs.daemon_identity_public_hex)),
      lp(bytes(inputs.server_nonce_hex)), lp(bytes(inputs.server_ephemeral_public_hex)),
      lp(bytes(inputs.connection_id_hex)),
    );
    const signature = bytes(inputs.server_signature_p1363_hex);
    if (signature.length !== SIGNATURE_LEN) reject(MALFORMED);
    const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      await verifyKey(DAEMON_IDENTITY_SCALAR), signature, transcript);
    if (!ok) reject(AUTH_FAILED);
    return null;
  }
  const hello = bytes(inputs.client_hello_hex);
  const selected = classifyHello(hello, reference);
  if (selected !== SELECTED) reject(UNSUPPORTED_CONTRACT);
  if (vector.id === "valid.handshake") {
    const signature = bytes(inputs.server_signature_p1363_hex);
    const ok = await subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      await verifyKey(DAEMON_IDENTITY_SCALAR), signature, bytes(inputs.transcript_hex));
    if (!ok) reject(AUTH_FAILED);
    const clientOk = await subtle.verify({ name: "ECDSA", hash: "SHA-256" },
      await verifyKey(CLIENT_IDENTITY_SCALAR), bytes(inputs.client_signature_p1363_hex),
      bytes(inputs.client_proof_input_hex));
    if (!clientOk) reject(AUTH_FAILED);
    equal("client_to_daemon_key_hex", hex(keys.clientToDaemon), inputs.client_to_daemon_key_hex);
    equal("daemon_to_client_key_hex", hex(keys.daemonToClient), inputs.daemon_to_client_key_hex);
  }
  return null;
}

async function classifyFrameVector(vector, keys) {
  const inputs = vector.inputs;
  if (inputs.counter_text !== undefined) {
    // A counter past u64 is never wrapped: the reader refuses the declared value.
    let parsed;
    try { parsed = BigInt(inputs.counter_text); } catch { return reject(MALFORMED); }
    if (parsed > U64_MAX) reject(MALFORMED);
    fail(`${vector.id}: an out-of-range counter must not parse`);
  }
  const direction = inputs.direction ?? "client-to-daemon";
  const key = direction === "client-to-daemon" ? keys.clientToDaemon : keys.daemonToClient;
  let framed;
  if (inputs.framed_hex !== undefined) {
    framed = bytes(inputs.framed_hex);
  } else {
    const sealed = await sealFrame(key, {
      counter: BigInt(inputs.counter), direction,
      kind: inputs.payload_kind_code, payload_len: inputs.payload_len,
      payload_repeat_byte_hex: inputs.payload_repeat_byte_hex,
    });
    framed = sealed.framed;
  }
  const state = {
    connection: CONNECTION,
    direction,
    key,
    receiveCounter: BigInt(inputs.receive_counter),
    exhausted: inputs.receive_exhausted === true,
  };
  const opened = await classifyFrame(framed, state);
  return { nonce: opened.nonce.length, aad: opened.aad.length };
}

async function verify(corpus) {
  equal("schema", corpus.schema, CONTEXT);
  equal("schema_version", String(corpus.schema_version), "1");
  equal("evidence_schema", corpus.evidence_schema, EVIDENCE_SCHEMA);
  if (!Array.isArray(corpus.vectors) || corpus.vectors.length === 0) fail("empty corpus");

  const valid = corpus.vectors.find((vector) => vector.id === "valid.handshake");
  if (!valid) fail("corpus has no valid.handshake vector");
  const parts = await deterministicParts(
    bytes(valid.inputs.server_signature_p1363_hex),
    bytes(valid.inputs.client_signature_p1363_hex));
  const keys = { clientToDaemon: parts.clientToDaemon, daemonToClient: parts.daemonToClient };
  const reference = {
    endpoint: ENDPOINT,
    selector: selectorFor(PRINCIPAL),
    identityHex: hex(parts.clientIdentityPublic),
    epoch: EPOCH,
    serverMin: SERVER_MIN,
    serverMax: SERVER_MAX,
  };

  const seen = new Set();
  const records = [];
  let passed = 0;
  let unsupported = 0;
  for (const vector of corpus.vectors) {
    if (seen.has(vector.id)) fail(`duplicate vector id ${vector.id}`);
    seen.add(vector.id);
    const shape = Object.keys(vector);
    const required = vector.valid
      ? ["id", "kind", "valid", "inputs", "expect"]
      : ["id", "kind", "valid", "mutation", "inputs", "expect"];
    equal(`${vector.id} key order`, shape.join(","), required.join(","));
    if (!vector.valid) {
      equal(`${vector.id} expect.result`, vector.expect.result, "reject");
      equal(`${vector.id} channel_state`, vector.expect.channel_state, "closed");
      equal(`${vector.id} dispatch_count`, String(vector.expect.dispatch_count), "0");
      equal(`${vector.id} secret_scan`, vector.expect.secret_scan, "pass");
      if (!vector.expect.failure_code) fail(`${vector.id} has no stable failure code`);
    }

    let result;
    let code = null;
    let derived = { nonce: null, aad: null };
    try {
      const measured = vector.kind === "handshake"
        ? await classifyHandshakeVector(vector, reference, keys)
        : await classifyFrameVector(vector, keys);
      if (measured) derived = measured;
      result = vector.valid ? "pass" : "fail";
      if (!vector.valid) fail(`${vector.id}: an invalid vector was accepted`);
    } catch (error) {
      if (!(error instanceof Reject)) throw error;
      code = error.code;
      if (vector.valid) fail(`${vector.id}: a valid vector was rejected as ${code}`);
      equal(`${vector.id} failure_code`, code, vector.expect.failure_code);
      result = "pass";
    }
    if (result === "pass") passed += 1;
    if (result === "unsupported") unsupported += 1;
    const record = evidence(vector, result, code, derived.nonce, derived.aad);
    if (record.secret_scan !== "pass") fail(`${vector.id}: secret scan failed`);
    records.push(record);
    process.stdout.write(`${JSON.stringify(record)}\n`);
  }

  const labels = {};
  for (const record of records) labels[record.vector_id] = record.result;
  const fields = new Set();
  for (const vector of corpus.vectors) {
    if (vector.mutation) fields.add(`${vector.kind}.${vector.mutation.field}`);
  }
  process.stdout.write(`${JSON.stringify({
    schema: corpus.schema,
    schema_version: corpus.schema_version,
    result: unsupported === 0 && passed === records.length ? "pass" : "fail",
    peer: "Node.js WebCrypto",
    vectors: records.length,
    passed,
    unsupported,
    valid_vectors: corpus.vectors.filter((vector) => vector.valid).length,
    mutations_rejected: corpus.vectors.filter((vector) => !vector.valid).length,
    mutated_fields: [...fields].sort(),
    labels,
  })}\n`);
  if (unsupported !== 0 || passed !== records.length) fail("corpus run did not pass");
}

// ---------------------------------------------------------------------------
// SC-003: the seeded 1,000-case handshake campaign, classified independently.
// ---------------------------------------------------------------------------
const MASK64 = (1n << 64n) - 1n;

class SplitMix64 {
  constructor(seed) { this.state = BigInt(seed) & MASK64; }
  next() {
    this.state = (this.state + 0x9e3779b97f4a7c15n) & MASK64;
    let z = this.state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    return (z ^ (z >> 31n)) & MASK64;
  }
}

/// Each family declares the outcome the protocol fixes for it. `nonce-rotate`
/// accepts on purpose: the client nonce is not bound at hello, it is bound by
/// the signature that follows, so a fresh nonce is a valid hello.
const CAMPAIGN_FAMILIES = [
  ["valid", true, null],
  ["nonce-rotate", true, null],
  ["context.substitution", false, AUTH_FAILED],
  ["hello-label.substitution", false, AUTH_FAILED],
  ["endpoint.substitution", false, AUTH_FAILED],
  ["endpoint.malformed-utf8", false, MALFORMED],
  ["endpoint.empty", false, AUTH_FAILED],
  ["endpoint.extension", false, RESOURCE_LIMIT],
  ["principal-selector.substitution", false, AUTH_FAILED],
  ["principal-selector.invalid-uuid", false, AUTH_FAILED],
  ["epoch.one-over", false, STALE_EPOCH],
  ["epoch.one-under", false, STALE_EPOCH],
  ["epoch.truncation", false, RESOURCE_LIMIT],
  ["minimum-contract.disjoint", false, DOWNGRADE],
  ["minimum-contract.leading-zero", false, MALFORMED],
  ["maximum-contract.disjoint", false, UNSUPPORTED_CONTRACT],
  ["client-nonce.short", false, MALFORMED],
  ["client-nonce.extension", false, RESOURCE_LIMIT],
  ["client-ephemeral-key.compressed-key", false, MALFORMED],
  ["client-ephemeral-key.der-key", false, MALFORMED],
  ["client-key.substitution", false, AUTH_FAILED],
  ["client-key.compressed-key", false, MALFORMED],
  ["client-key.bad-length-prefix", false, RESOURCE_LIMIT],
  ["transcript-length.extension", false, MALFORMED],
  ["transcript-length.truncation", false, MALFORMED],
  ["transcript-length.one-over", false, RESOURCE_LIMIT],
];

function campaignNonce(rng) {
  const out = Buffer.alloc(NONCE_LEN);
  for (let word = 0; word < 4; word += 1) out.writeBigUInt64BE(rng.next(), word * 8);
  return out;
}

/// Build one campaign hello. Rust runs the identical construction, so a case is
/// the same bytes on both peers.
function campaignHello(family, principalHex, nonce) {
  const facts = { ...baseFacts(), selector: selectorFor(principalHex), nonce };
  let segments = helloSegments(facts);
  const identity = facts.identity;
  const ephemeral = facts.ephemeral;
  switch (family) {
    case "valid":
    case "nonce-rotate":
      break;
    case "context.substitution":
      segments = mutateHello(segments, "context", { body: text("matinee.secure-channel.v2") });
      break;
    case "hello-label.substitution":
      segments = mutateHello(segments, "hello-label", { body: text("client-hell0") });
      break;
    case "endpoint.substitution":
      segments = mutateHello(segments, "endpoint", { body: text("127.0.0.1:7778") });
      break;
    case "endpoint.malformed-utf8":
      segments = mutateHello(segments, "endpoint",
        { body: concat(text("127.0.0.1:777"), Buffer.from([0xff])) });
      break;
    case "endpoint.empty":
      segments = mutateHello(segments, "endpoint", { body: Buffer.alloc(0) });
      break;
    case "endpoint.extension":
      segments = mutateHello(segments, "endpoint", { declared: 257 });
      break;
    case "principal-selector.substitution":
      segments = mutateHello(segments, "principal-selector",
        { body: text(selectorFor(principalHex === PRINCIPAL ? EXTENSION : PRINCIPAL)) });
      break;
    case "principal-selector.invalid-uuid":
      segments = mutateHello(segments, "principal-selector",
        { body: text("id:zzzzzzzz-0000-0000-0000-000000000002") });
      break;
    case "epoch.one-over":
      segments = mutateHello(segments, "epoch", { body: u64(EPOCH + 1n) });
      break;
    case "epoch.one-under":
      segments = mutateHello(segments, "epoch", { body: u64(EPOCH - 1n) });
      break;
    case "epoch.truncation":
      segments = mutateHello(segments, "epoch", { body: u64(EPOCH).subarray(0, 7) });
      break;
    case "minimum-contract.disjoint":
      segments = mutateHello(segments, "minimum-contract", { body: text("4") });
      break;
    case "minimum-contract.leading-zero":
      segments = mutateHello(segments, "minimum-contract", { body: text("01") });
      break;
    case "maximum-contract.disjoint":
      segments = mutateHello(segments, "maximum-contract", { body: text("1") });
      break;
    case "client-nonce.short":
      segments = mutateHello(segments, "client-nonce", { body: nonce.subarray(0, 31) });
      break;
    case "client-nonce.extension":
      segments = mutateHello(segments, "client-nonce",
        { body: concat(nonce, Buffer.from([0xaa])) });
      break;
    case "client-ephemeral-key.compressed-key":
      segments = mutateHello(segments, "client-ephemeral-key", { body: compressed(ephemeral) });
      break;
    case "client-ephemeral-key.der-key":
      segments = mutateHello(segments, "client-ephemeral-key", { body: derKeyBytes() });
      break;
    case "client-key.substitution":
      segments = mutateHello(segments, "client-key", { body: bytes(OTHER_KEY_HEX) });
      break;
    case "client-key.compressed-key":
      segments = mutateHello(segments, "client-key", { body: compressed(identity) });
      break;
    case "client-key.bad-length-prefix":
      segments = mutateHello(segments, "client-key", { declared: KEY_LEN + 1 });
      break;
    case "transcript-length.extension":
      return concat(encodeHello(segments), Buffer.from([0x00]));
    case "transcript-length.truncation": {
      const encoded = encodeHello(segments);
      return encoded.subarray(0, encoded.length - 1);
    }
    case "transcript-length.one-over": {
      const encoded = encodeHello(segments);
      return concat(encoded, Buffer.alloc(MAX_HANDSHAKE + 1 - encoded.length, 0x00));
    }
    default:
      fail(`unknown campaign family ${family}`);
  }
  return encodeHello(segments);
}

function campaign(seedText, count) {
  const rng = new SplitMix64(seedText);
  const identityHex = hex(publicFromScalar(CLIENT_IDENTITY_SCALAR));
  const families = {};
  let accepted = 0;
  let rejected = 0;
  for (let index = 0; index < count; index += 1) {
    const [family, expectAccept, expectedCode] = CAMPAIGN_FAMILIES[index % CAMPAIGN_FAMILIES.length];
    const kindDraw = rng.next();
    const nonce = campaignNonce(rng);
    rng.next();
    const extension = (kindDraw & 1n) === 1n;
    const principalHex = extension ? EXTENSION : PRINCIPAL;
    const hello = campaignHello(family, principalHex, nonce);
    const reference = {
      endpoint: ENDPOINT,
      selector: selectorFor(principalHex),
      identityHex,
      epoch: EPOCH,
      serverMin: SERVER_MIN,
      serverMax: SERVER_MAX,
    };
    let result = "accept";
    let code = null;
    try {
      classifyHello(hello, reference);
    } catch (error) {
      if (!(error instanceof Reject)) throw error;
      result = "reject";
      code = error.code;
    }
    if (result === "accept") accepted += 1; else rejected += 1;
    const expected = expectAccept ? "accept" : "reject";
    families[family] = (families[family] ?? 0) + 1;
    process.stdout.write(`${JSON.stringify({
      case: index,
      family,
      peer: extension ? "browser-extension" : "mcp-client",
      hello_hex: hex(hello),
      expected,
      expected_failure_code: expectedCode,
      result,
      failure_code: code,
      agrees: result === expected && code === expectedCode,
    })}\n`);
  }
  process.stdout.write(`${JSON.stringify({
    campaign: "sc-003.handshake",
    peer: "Node.js WebCrypto",
    seed: seedText,
    cases: count,
    accepted,
    rejected,
    families,
    result: "pass",
  })}\n`);
}

// ---------------------------------------------------------------------------
const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
function flag(name, fallback) {
  const at = argv.indexOf(name);
  return at === -1 ? fallback : argv[at + 1];
}

const corpusPath = flag("--vectors", resolve(scriptDirectory, "../../vectors/secure-channel-v1.json"));

if (argv.includes("--generate")) {
  // The corpus is written in place rather than to stdout: a shell redirection
  // truncates the file before this process can read the signatures it must pin.
  let pinned = null;
  if (!argv.includes("--mint-signatures")) {
    const existing = JSON.parse(await readFile(corpusPath, "utf8"));
    const inputs = existing.vectors.find((vector) => vector.id === "valid.handshake").inputs;
    pinned = {
      serverSignature: bytes(inputs.server_signature_p1363_hex),
      clientSignature: bytes(inputs.client_signature_p1363_hex),
    };
  }
  const corpus = await generate(pinned);
  await writeFile(corpusPath, `${JSON.stringify(corpus, null, 2)}\n`, "utf8");
  process.stdout.write(`${JSON.stringify({
    wrote: corpusPath,
    vectors: corpus.vectors.length,
    signatures: pinned ? "pinned" : "minted",
  })}\n`);
} else if (argv.includes("--campaign")) {
  campaign(flag("--seed", "0"), Number(flag("--cases", "1000")));
} else {

  await verify(JSON.parse(await readFile(corpusPath, "utf8")));
}
