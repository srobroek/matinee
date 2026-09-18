#!/usr/bin/env node
import { createECDH, webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const { subtle } = webcrypto;
const CONTEXT = "matinee.secure-channel.v1";
const ENDPOINT = "127.0.0.1:7777";
const PRINCIPAL = "00000000000000000000000000000002";
const DAEMON = "00000000000000000000000000000003";
const CONNECTION = "0000abcdefabcdefabcdefabcdefabcd";
const CLIENT_IDENTITY_SCALAR = "1".padStart(64, "0");
const DAEMON_IDENTITY_SCALAR = "2".padStart(64, "0");
const CLIENT_EPHEMERAL_SCALAR = "3".padStart(64, "0");
const SERVER_EPHEMERAL_SCALAR = "4".padStart(64, "0");
const CLIENT_NONCE = Buffer.alloc(32, 0xaa);
const SERVER_NONCE = Buffer.alloc(32, 0xbb);
const EPOCH = 7n;
const SELECTED = 3;

function fail(message) { throw new Error(message); }
function bytes(hex) { return Buffer.from(hex, "hex"); }
function hex(value) { return Buffer.from(value).toString("hex"); }
function concat(...parts) { return Buffer.concat(parts.map((part) => Buffer.from(part))); }
function u32(value) { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; }
function u64(value) { const out = Buffer.alloc(8); out.writeBigUInt64BE(value); return out; }
function lp(value) { const body = Buffer.from(value); return concat(u32(body.length), body); }
function text(value) { return Buffer.from(value, "utf8"); }
function contract(value) { return lp(text(String(value))); }
function b64url(value) { return Buffer.from(value).toString("base64url"); }
function equal(name, actual, expected) {
  if (actual !== expected) fail(`${name} mismatch\nactual:   ${actual}\nexpected: ${expected}`);
}

function publicFromScalar(scalarHex) {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(bytes(scalarHex));
  return ecdh.getPublicKey(undefined, "uncompressed");
}

function jwk(scalarHex) {
  const publicKey = publicFromScalar(scalarHex);
  return {
    kty: "EC",
    crv: "P-256",
    x: b64url(publicKey.subarray(1, 33)),
    y: b64url(publicKey.subarray(33, 65)),
    d: b64url(bytes(scalarHex)),
    ext: true,
  };
}

async function signingKey(scalarHex) {
  return subtle.importKey(
    "jwk",
    jwk(scalarHex),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

async function verifyKey(scalarHex) {
  const value = jwk(scalarHex);
  delete value.d;
  return subtle.importKey(
    "jwk",
    value,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

async function agreementKey(scalarHex, usages) {
  return subtle.importKey(
    "jwk",
    jwk(scalarHex),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    usages,
  );
}

async function agreementPublic(scalarHex) {
  const value = jwk(scalarHex);
  delete value.d;
  return subtle.importKey(
    "jwk",
    value,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
}

async function sha256(value) {
  return Buffer.from(await subtle.digest("SHA-256", value));
}

async function deriveKey(shared, salt, direction) {
  const material = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
  const info = concat(lp(text(CONTEXT)), contract(SELECTED), lp(text(direction)));
  return Buffer.from(await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    material,
    256,
  ));
}

function clientHello(clientIdentityPublic, clientEphemeralPublic) {
  return concat(
    lp(text(CONTEXT)),
    lp(text("client-hello")),
    lp(text(ENDPOINT)),
    lp(text("id:00000000-0000-0000-0000-000000000002")),
    u64(EPOCH),
    contract(1),
    contract(3),
    lp(CLIENT_NONCE),
    lp(clientEphemeralPublic),
    lp(clientIdentityPublic),
  );
}

function serverProofInput(hello, daemonIdentityPublic, serverEphemeralPublic) {
  return concat(
    lp(text("server-proof")),
    hello,
    contract(SELECTED),
    contract(2),
    contract(4),
    lp(bytes(DAEMON)),
    lp(daemonIdentityPublic),
    lp(SERVER_NONCE),
    lp(serverEphemeralPublic),
    lp(bytes(CONNECTION)),
  );
}

async function clientProofInput(serverProof, serverSignature) {
  return concat(
    lp(text("client-proof")),
    await sha256(serverProof),
    lp(serverSignature),
  );
}

async function deterministicParts(serverSignature, clientSignature) {
  const clientIdentityPublic = publicFromScalar(CLIENT_IDENTITY_SCALAR);
  const daemonIdentityPublic = publicFromScalar(DAEMON_IDENTITY_SCALAR);
  const clientEphemeralPublic = publicFromScalar(CLIENT_EPHEMERAL_SCALAR);
  const serverEphemeralPublic = publicFromScalar(SERVER_EPHEMERAL_SCALAR);
  const hello = clientHello(clientIdentityPublic, clientEphemeralPublic);
  const serverProof = serverProofInput(hello, daemonIdentityPublic, serverEphemeralPublic);
  const clientProof = serverSignature ? await clientProofInput(serverProof, serverSignature) : null;
  const clientPrivate = await agreementKey(CLIENT_EPHEMERAL_SCALAR, ["deriveBits"]);
  const serverPublic = await agreementPublic(SERVER_EPHEMERAL_SCALAR);
  const serverPrivate = await agreementKey(SERVER_EPHEMERAL_SCALAR, ["deriveBits"]);
  const clientPublic = await agreementPublic(CLIENT_EPHEMERAL_SCALAR);
  const clientShared = Buffer.from(await subtle.deriveBits(
    { name: "ECDH", public: serverPublic }, clientPrivate, 256,
  ));
  const serverShared = Buffer.from(await subtle.deriveBits(
    { name: "ECDH", public: clientPublic }, serverPrivate, 256,
  ));
  equal("ECDH peers", hex(clientShared), hex(serverShared));
  const salt = clientProof && clientSignature
    ? await sha256(concat(clientProof, clientSignature))
    : null;
  const clientToDaemon = salt ? await deriveKey(clientShared, salt, "client-to-daemon") : null;
  const daemonToClient = salt ? await deriveKey(clientShared, salt, "daemon-to-client") : null;
  return {
    clientIdentityPublic,
    daemonIdentityPublic,
    clientEphemeralPublic,
    serverEphemeralPublic,
    hello,
    serverProof,
    clientProof,
    shared: clientShared,
    salt,
    clientToDaemon,
    daemonToClient,
  };
}

async function signFixedInputs() {
  const initial = await deterministicParts(null, null);
  const daemonSigning = await signingKey(DAEMON_IDENTITY_SCALAR);
  const serverSignature = Buffer.from(await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, daemonSigning, initial.serverProof,
  ));
  if (serverSignature.length !== 64) fail("WebCrypto did not produce a 64-byte P1363 signature");
  const clientProof = await clientProofInput(initial.serverProof, serverSignature);
  const clientSigning = await signingKey(CLIENT_IDENTITY_SCALAR);
  const clientSignature = Buffer.from(await subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, clientSigning, clientProof,
  ));
  if (clientSignature.length !== 64) fail("WebCrypto did not produce a 64-byte P1363 signature");
  return { serverSignature, clientSignature };
}

async function frameVector(key) {
  const plaintext = bytes("0101020304");
  const header = concat(Buffer.from([1]), bytes(CONNECTION), u64(0n));
  const nonce = concat(u32(0), u64(0n));
  const aad = concat(
    header,
    lp(text(CONTEXT)),
    contract(SELECTED),
    u64(EPOCH),
    lp(text("client-to-daemon")),
  );
  const aes = await subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
  const ciphertextAndTag = Buffer.from(await subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    aes,
    plaintext,
  ));
  const body = concat(header, ciphertextAndTag);
  const framed = concat(u32(body.length), body);
  const opened = Buffer.from(await subtle.decrypt(
    { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
    aes,
    ciphertextAndTag,
  ));
  equal("AES-GCM round trip", hex(opened), hex(plaintext));
  return { plaintext, header, nonce, aad, ciphertextAndTag, framed };
}

async function generate() {
  const { serverSignature, clientSignature } = await signFixedInputs();
  const parts = await deterministicParts(serverSignature, clientSignature);
  const frame = await frameVector(parts.clientToDaemon);
  return {
    schema: CONTEXT,
    schema_version: 2,
    provenance: "Node.js WebCrypto fixed P-256 private scalars; signatures generated once and verified on every run",
    handshake: {
      endpoint: ENDPOINT,
      principal_id_hex: PRINCIPAL,
      daemon_id_hex: DAEMON,
      connection_id_hex: CONNECTION,
      epoch: Number(EPOCH),
      client_contract_min: 1,
      client_contract_max: 3,
      server_contract_min: 2,
      server_contract_max: 4,
      selected_contract: SELECTED,
      client_nonce_hex: hex(CLIENT_NONCE),
      server_nonce_hex: hex(SERVER_NONCE),
      client_identity_public_hex: hex(parts.clientIdentityPublic),
      daemon_identity_public_hex: hex(parts.daemonIdentityPublic),
      client_ephemeral_public_hex: hex(parts.clientEphemeralPublic),
      server_ephemeral_public_hex: hex(parts.serverEphemeralPublic),
      client_hello_hex: hex(parts.hello),
      server_proof_input_hex: hex(parts.serverProof),
      server_signature_p1363_hex: hex(serverSignature),
      client_proof_input_hex: hex(parts.clientProof),
      client_signature_p1363_hex: hex(clientSignature),
      ecdh_shared_secret_hex: hex(parts.shared),
      hkdf_salt_hex: hex(parts.salt),
      client_to_daemon_key_hex: hex(parts.clientToDaemon),
      daemon_to_client_key_hex: hex(parts.daemonToClient),
    },
    frame: {
      direction: "client-to-daemon",
      counter: "0",
      plaintext_hex: hex(frame.plaintext),
      application_payload_hex: hex(frame.plaintext.subarray(1)),
      header_hex: hex(frame.header),
      nonce_hex: hex(frame.nonce),
      aad_hex: hex(frame.aad),
      ciphertext_and_tag_hex: hex(frame.ciphertextAndTag),
      framed_hex: hex(frame.framed),
    },
    mutations: [
      "server-signature-bit",
      "client-signature-bit",
      "ephemeral-key-compressed",
      "frame-length-oversize",
      "frame-counter-replay",
      "frame-wrong-direction",
      "frame-tag-bit",
    ],
  };
}

async function verify(corpus) {
  const h = corpus.handshake;
  const fixedServerSignature = bytes(h.server_signature_p1363_hex);
  const fixedClientSignature = bytes(h.client_signature_p1363_hex);
  const parts = await deterministicParts(fixedServerSignature, fixedClientSignature);
  const deterministic = {
    client_identity_public_hex: hex(parts.clientIdentityPublic),
    daemon_identity_public_hex: hex(parts.daemonIdentityPublic),
    client_ephemeral_public_hex: hex(parts.clientEphemeralPublic),
    server_ephemeral_public_hex: hex(parts.serverEphemeralPublic),
    client_hello_hex: hex(parts.hello),
    server_proof_input_hex: hex(parts.serverProof),
    client_proof_input_hex: hex(parts.clientProof),
    ecdh_shared_secret_hex: hex(parts.shared),
    hkdf_salt_hex: hex(parts.salt),
    client_to_daemon_key_hex: hex(parts.clientToDaemon),
    daemon_to_client_key_hex: hex(parts.daemonToClient),
  };
  for (const [name, value] of Object.entries(deterministic)) equal(name, value, h[name]);

  const daemonVerify = await verifyKey(DAEMON_IDENTITY_SCALAR);
  const clientVerify = await verifyKey(CLIENT_IDENTITY_SCALAR);
  if (!await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, daemonVerify, fixedServerSignature, parts.serverProof)) {
    fail("fixed server P1363 signature rejected");
  }
  if (!await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, clientVerify, fixedClientSignature, parts.clientProof)) {
    fail("fixed client P1363 signature rejected");
  }
  const mutatedSignature = Buffer.from(fixedServerSignature);
  mutatedSignature[0] ^= 1;
  if (await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, daemonVerify, mutatedSignature, parts.serverProof)) {
    fail("mutated server signature accepted");
  }

  const frame = await frameVector(parts.clientToDaemon);
  for (const [name, value] of Object.entries({
    plaintext_hex: hex(frame.plaintext),
    application_payload_hex: hex(frame.plaintext.subarray(1)),
    header_hex: hex(frame.header),
    nonce_hex: hex(frame.nonce),
    aad_hex: hex(frame.aad),
    ciphertext_and_tag_hex: hex(frame.ciphertextAndTag),
    framed_hex: hex(frame.framed),
  })) equal(`frame.${name}`, value, corpus.frame[name]);
  if (frame.framed.readUInt32BE(0) !== frame.framed.length - 4) fail("frame length prefix mismatch");

  const fresh = await signFixedInputs();
  if (!await subtle.verify({ name: "ECDSA", hash: "SHA-256" }, daemonVerify, fresh.serverSignature, parts.serverProof)) {
    fail("fresh WebCrypto server signature rejected");
  }
  process.stdout.write(JSON.stringify({
    schema: corpus.schema,
    result: "pass",
    fixed_outputs: 17,
    mutations_rejected: corpus.mutations.length,
    peer: "Node.js WebCrypto",
  }) + "\n");
}

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
if (process.argv.includes("--generate")) {
  process.stdout.write(JSON.stringify(await generate(), null, 2) + "\n");
} else {
  const path = resolve(scriptDirectory, "../../vectors/secure-channel-v1.json");
  await verify(JSON.parse(await readFile(path, "utf8")));
}
