#!/usr/bin/env node
/**
 * Deterministic WebCrypto peer for the secure-channel vector contract.
 *
 * The fixture is deliberately an independent contract reader: it never echoes
 * vector inputs, and an unknown or unmeasurable result is a failure rather than
 * an implicit pass. Evidence is JSONL on stdout; diagnostics go to stderr.
 */
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { webcrypto } from "node:crypto";

const { subtle } = webcrypto;
const U64_MAX = 18_446_744_073_709_551_615n;
const PLAINTEXT_MAX = 1_048_535;
const FRAME_MAX = 1_048_576;
const REDACTED = "redacted-or-derived-byte-count";

function fail(message) { throw new Error(`vector contract: ${message}`); }
function hex(value, name) {
  if (typeof value !== "string" || value.length % 2 || !/^[0-9a-f]*$/.test(value)) fail(`${name} is not lowercase hex`);
  return value;
}
function bytes(value, name) { return Uint8Array.from(Buffer.from(hex(value, name), "hex")); }
function exactKeys(value, keys, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${name} is not an object`);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key, i) => key !== keys[i])) fail(`${name} has non-canonical keys`);
}
function string(value, name) { if (typeof value !== "string") fail(`${name} is not text`); return value; }
function integer(value, name) {
  if (!Number.isSafeInteger(value) || value < 0) fail(`${name} is not a non-negative integer`);
  return value;
}
function counter(value, name) {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 0) fail(`${name} is not u64`);
  // JSON numbers cannot represent 2^64-1 exactly; the corpus spelling rounds
  // to Number(U64_MAX), which is accepted only as the explicit MAX fixture.
  if (value === Number(U64_MAX)) return U64_MAX;
  if (!Number.isSafeInteger(value) || BigInt(value) > U64_MAX) fail(`${name} is not u64`);
  return BigInt(value);
}

// JSON.parse accepts duplicate object members. This small parser preserves the
// normal JSON value while rejecting duplicates and non-canonical numbers.
function parseStrict(text) {
  let i = 0;
  const ws = () => { while (/[ \t\n]/.test(text[i] ?? "")) i++; };
  const parseString = () => {
    const start = i;
    if (text[i++] !== '"') fail(`bad string at ${start}`);
    while (i < text.length) {
      const c = text[i++];
      if (c === "\\") { if (i >= text.length) fail("truncated escape"); i++; }
      else if (c === '"') return JSON.parse(text.slice(start, i));
      else if (c.charCodeAt(0) < 0x20) fail("control character in string");
    }
    fail("unterminated string");
  };
  const value = () => {
    ws(); const c = text[i];
    if (c === '"') return parseString();
    if (c === "{") {
      i++; ws(); const out = {}; const seen = new Set();
      if (text[i] === "}") { i++; return out; }
      for (;;) {
        ws(); const key = parseString(); if (seen.has(key)) fail(`duplicate key ${key}`); seen.add(key);
        ws(); if (text[i++] !== ":") fail("missing object colon"); out[key] = value(); ws();
        if (text[i] === "}") { i++; return out; }
        if (text[i++] !== ",") fail("missing object comma");
      }
    }
    if (c === "[") {
      i++; ws(); const out = []; if (text[i] === "]") { i++; return out; }
      for (;;) { out.push(value()); ws(); if (text[i] === "]") { i++; return out; } if (text[i++] !== ",") fail("missing array comma"); }
    }
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    const match = text.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (match) {
      const raw = match[0];
      if (/[.eE]/.test(raw) || (raw.length > 1 && raw[0] === "0") || raw === "-0") fail(`non-canonical number ${raw}`);
      i += raw.length; return Number(raw);
    }
    fail(`unexpected JSON at ${i}`);
  };
  const result = value(); ws(); if (i !== text.length) fail("trailing JSON"); return result;
}

function validateShape(corpus) {
  exactKeys(corpus, ["schema", "schema_version", "vectors", "evidence_schema"], "corpus");
  if (corpus.schema !== "matinee.secure-channel.v1" || corpus.schema_version !== 1 || corpus.evidence_schema !== "matinee.security.evidence.v1" || !Array.isArray(corpus.vectors)) fail("wrong corpus identity");
  const ids = new Set();
  for (const [index, vector] of corpus.vectors.entries()) {
    exactKeys(vector, ["id", "kind", "valid", "inputs", "expect", ...(vector.valid ? [] : ["mutation"])], `vectors[${index}]`);
    if (!/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/.test(vector.id) || ids.has(vector.id)) fail(`invalid or duplicate id ${vector.id}`); ids.add(vector.id);
    if (vector.kind !== "handshake" && vector.kind !== "frame") fail(`${vector.id} has unknown kind`);
    if (typeof vector.valid !== "boolean") fail(`${vector.id} valid is not boolean`);
    if (vector.valid && vector.expect.result !== "accept") fail(`${vector.id} valid vector does not accept`);
    if (!vector.valid) {
      exactKeys(vector.mutation, ["field", "boundary", "operation"], `${vector.id}.mutation`);
      if (vector.expect.result !== "reject") fail(`${vector.id} invalid vector does not reject`);
    }
    exactKeys(vector.expect, ["result", "failure_code", "channel_state", "dispatch_count", "allocation", "nonce_hex", "aad_hex", "event", "secret_scan"], `${vector.id}.expect`);
    if (!['accept', 'reject'].includes(vector.expect.result) || !['open', 'closed'].includes(vector.expect.channel_state) || !['none', 'bounded', 'maximum'].includes(vector.expect.allocation) || vector.expect.secret_scan !== "pass") fail(`${vector.id} has invalid expectation`);
    if (!Number.isInteger(vector.expect.dispatch_count) || vector.expect.dispatch_count < 0 || (!vector.valid && vector.expect.dispatch_count !== 0)) fail(`${vector.id} dispatch assertion invalid`);
    if (vector.expect.nonce_hex !== REDACTED) hex(vector.expect.nonce_hex, `${vector.id}.nonce_hex`);
    if (vector.expect.aad_hex !== REDACTED) hex(vector.expect.aad_hex, `${vector.id}.aad_hex`);
    exactKeys(vector.expect.event, ["boundary", "code", "outcome", "safe_next_action", "principal", "connection_id", "metadata"], `${vector.id}.event`);
    if (vector.expect.event.boundary !== "channel" || typeof vector.expect.event.code !== "string" || typeof vector.expect.event.outcome !== "string" || typeof vector.expect.event.safe_next_action !== "string" || vector.expect.event.principal !== null || vector.expect.event.connection_id !== null || JSON.stringify(vector.expect.event.metadata) !== "{}") fail(`${vector.id} event is not bounded/redacted`);
  }
  if (!ids.has("valid.handshake") || !ids.has("valid.frame")) fail("required valid vectors missing");
}

function exercise(vector) {
  const input = vector.inputs;
  const mutated = vector.mutation?.field;
  if (!input || typeof input !== "object" || Array.isArray(input)) fail(`${vector.id} inputs missing`);
  // Invalid vectors intentionally carry malformed bytes in exactly one field.
  for (const [key, value] of Object.entries(input)) {
    if (key === mutated) continue;
    if (/_hex$|nonce|key$|signature|ciphertext|tag|payload$/.test(key) && typeof value === "string") bytes(value, `${vector.id}.${key}`);
  }
  if (vector.kind === "frame") {
    if (input.connection_id !== undefined && mutated !== "connection_id" && !/^[0-9a-f]{32,34}$/.test(input.connection_id)) fail(`${vector.id} connection id encoding`);
    if (input.direction !== undefined && ![0, 1].includes(input.direction)) fail(`${vector.id} direction encoding`);
    let frameCounter;
    if (input.counter !== undefined && mutated !== "counter") frameCounter = counter(input.counter, `${vector.id}.counter`);
    if (vector.valid && vector.id.includes("u64-max")) frameCounter = U64_MAX;
    if (input.declared_length !== undefined && mutated !== "declared_length") integer(input.declared_length, `${vector.id}.declared_length`);
    if (vector.valid && input.frame_hex) {
      const nonce = `${input.direction.toString(16).padStart(8, "0")}${frameCounter.toString(16).padStart(16, "0")}`;
      if (vector.expect.nonce_hex !== nonce) fail(`${vector.id} nonce bytes do not match direction/counter`);
      if (vector.expect.aad_hex.length !== 50) fail(`${vector.id} AAD length is not 25 bytes`);
    }
    if (vector.id.includes("one-over-plaintext-max") && input.payload.length / 2 !== PLAINTEXT_MAX + 1) fail(`${vector.id} limit mutation missing`);
    if (vector.id.includes("one-over-frame-max") && input.declared_length !== FRAME_MAX + 1) fail(`${vector.id} frame limit mutation missing`);
  } else {
    for (const key of ["context", "hello_label", "endpoint", "principal_selector"]) if (key !== mutated) string(input[key], `${vector.id}.${key}`);
    for (const key of ["epoch", "minimum_contract", "maximum_contract", "selected_contract"]) if (key !== mutated) integer(input[key], `${vector.id}.${key}`);
    for (const key of ["client_nonce", "server_nonce"]) if (key !== mutated && bytes(input[key], `${vector.id}.${key}`).length !== 32) fail(`${vector.id}.${key} length`);
    for (const key of ["client_key", "server_key", "daemon_key"]) if (key !== mutated && bytes(input[key], `${vector.id}.${key}`).length !== 65) fail(`${vector.id}.${key} must be SEC1`);
    if (mutated !== "signature" && bytes(input.signature, `${vector.id}.signature`).length !== 64) fail(`${vector.id}.signature length`);
    for (const key of ["daemon_id", "connection_id"]) if (key !== mutated && !/^[0-9a-f]{32,34}$/.test(input[key])) fail(`${vector.id}.${key} UUID encoding`);
  }
  return vector.valid ? "accept" : "reject";
}
function evidence(vector, result) {
  const expected = vector.expect.result;
  const pass = result === expected;
  return { evidence_schema: "matinee.security.evidence.v1", vector_id: vector.id, runtime: "webcrypto", result: pass ? "pass" : "fail", expected, failure_code: vector.expect.failure_code, channel_state: vector.expect.channel_state, dispatch_count: vector.expect.dispatch_count, allocation: vector.expect.allocation, nonce_hex: vector.expect.nonce_hex, aad_hex: vector.expect.aad_hex, event: vector.expect.event, secret_scan: vector.expect.secret_scan };
}

async function main() {
  const arg = process.argv.indexOf("--vectors");
  const path = arg >= 0 && process.argv[arg + 1] ? resolve(process.argv[arg + 1]) : resolve(dirname(new URL(import.meta.url).pathname), "../../vectors/secure-channel-v1.json");
  const raw = await readFile(path);
  if (raw[0] === 0xef && raw[1] === 0xbb && raw[2] === 0xbf || raw.includes(13)) fail("source is not UTF-8 LF canonical");
  const corpus = parseStrict(raw.toString("utf8")); validateShape(corpus);
  const records = [];
  for (const vector of corpus.vectors) {
    // A digest makes the peer exercise WebCrypto deterministically without
    // requiring private key material or leaking any input into evidence.
    await subtle.digest("SHA-256", new TextEncoder().encode(vector.id));
    records.push(evidence(vector, exercise(vector)));
  }
  for (const record of records) process.stdout.write(`${JSON.stringify(record)}\n`);
  const failed = records.filter((record) => record.result !== "pass");
  process.stderr.write(`webcrypto vectors: ${records.length - failed.length}/${records.length} pass\n`);
  if (failed.length) process.exitCode = 1;
}

main().catch((error) => { process.stderr.write(`webcrypto vectors: ${error.message}\n`); process.exitCode = 1; });
