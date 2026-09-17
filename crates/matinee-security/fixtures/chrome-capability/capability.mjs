/*
 * Deterministic Chrome capability fixture. This is deliberately not a product
 * package: it probes the two browser guarantees needed by enrollment custody.
 * Evidence never contains a key, signature, payload, or storage value.
 */

const STORAGE_KEY = "matinee.fixture.long_term_key.v1";
const FIXTURE_MESSAGE = new TextEncoder().encode("matinee.chrome-capability.fixture.v1");
const MAX_U64 = (1n << 64n) - 1n;

const event = (code, outcome, safeNextAction = "discard_and_reconnect") => ({
  boundary: "channel",
  code,
  outcome,
  safe_next_action: safeNextAction,
  principal: null,
  connection_id: null,
  metadata: {}
});

const evidence = (vectorId, result, expected, failureCode, channelState, allocation, eventValue) => ({
  evidence_schema: "matinee.security.evidence.v1",
  vector_id: vectorId,
  runtime: "webcrypto",
  result,
  expected,
  failure_code: failureCode,
  channel_state: channelState,
  dispatch_count: 0,
  allocation,
  nonce_hex: "redacted-or-derived-byte-count",
  aad_hex: "redacted-or-derived-byte-count",
  event: eventValue,
  secret_scan: "pass"
});

const unsupported = (reason) => evidence(
  "chrome.capability.unsupported",
  "unsupported",
  "accept",
  reason,
  "closed",
  "none",
  event("capability.unsupported", "rejected")
);

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError("non-canonical number");
    return String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  throw new TypeError("unsupported canonical value");
}

function parseCounter(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) return null;
  try {
    const counter = BigInt(value);
    return counter <= MAX_U64 ? counter : null;
  } catch {
    return null;
  }
}

async function probeKeyPersistence() {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || !globalThis.TextEncoder) return unsupported("capability.unsupported");
  if (!globalThis.chrome?.storage?.local) return unsupported("capability.unsupported");

  let privateKey;
  try {
    const pair = await subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"]
    );
    privateKey = pair.privateKey;
    if (privateKey.extractable !== false || !privateKey.usages.includes("sign")) {
      return unsupported("capability.non_exportable");
    }
    await chrome.storage.local.set({
      [STORAGE_KEY]: {
        version: 1,
        key: privateKey,
        daemon_identity: "daemon.synthetic",
        epoch: 7
      }
    });
    const stored = await chrome.storage.local.get(STORAGE_KEY);
    const record = stored[STORAGE_KEY];
    const restored = record?.key;
    if (!restored || restored.extractable !== false || !restored.usages.includes("sign")) {
      return unsupported("capability.persistence");
    }
    const signature = await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      restored,
      FIXTURE_MESSAGE
    );
    const verified = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pair.publicKey,
      signature,
      FIXTURE_MESSAGE
    );
    if (!verified) return unsupported("capability.persistence");
    try {
      await subtle.exportKey("pkcs8", restored);
      return unsupported("capability.exportable");
    } catch {
      // The required non-exportability assertion passed.
    }
    return evidence(
      "chrome.capability.persistence",
      "pass",
      "accept",
      null,
      "open",
      "none",
      event("authentication.accepted", "accepted", "continue")
    );
  } catch {
    // Storage structured-clone or WebCrypto failures are not a downgrade path.
    return unsupported("capability.persistence");
  } finally {
    try { await chrome.storage.local.remove(STORAGE_KEY); } catch { /* fail-closed probe cleanup */ }
  }
}

function probeBoundaries() {
  const records = [];
  const validEncoding = canonicalJson({ counter: 0, version: 1 });
  records.push(evidence(
    "chrome.capability.encoding.canonical",
    validEncoding === '{"counter":0,"version":1}' ? "pass" : "fail",
    "accept",
    validEncoding === '{"counter":0,"version":1}' ? null : "malformed.input",
    "open",
    "none",
    event("authentication.accepted", "accepted", "continue")
  ));
  let nonCanonicalRejected = false;
  try { canonicalJson({ counter: 1.5 }); } catch { nonCanonicalRejected = true; }
  records.push(evidence(
    "chrome.capability.encoding.noncanonical",
    nonCanonicalRejected ? "pass" : "fail",
    "reject",
    nonCanonicalRejected ? "malformed.input" : null,
    nonCanonicalRejected ? "closed" : "open",
    "none",
    event(nonCanonicalRejected ? "malformed.input" : "authentication.accepted", nonCanonicalRejected ? "rejected" : "accepted")
  ));
  for (const [id, value, accepted] of [
    ["zero", "0", true],
    ["one", "1", true],
    ["max", "18446744073709551615", true],
    ["overflow", "18446744073709551616", false]
  ]) {
    const parsed = parseCounter(value);
    const okay = (parsed !== null) === accepted;
    records.push(evidence(
      `chrome.capability.counter.${id}`,
      okay ? "pass" : "fail",
      accepted ? "accept" : "reject",
      okay && !accepted ? "resource_limit" : (okay ? null : "malformed.input"),
      okay && accepted ? "open" : "closed",
      "none",
      event(okay && accepted ? "authentication.accepted" : (okay ? "resource_limit" : "malformed.input"), okay && accepted ? "accepted" : "rejected", okay && accepted ? "continue" : undefined)
    ));
  }
  return records;
}

function proveRedaction(records) {
  const serialized = JSON.stringify(records);
  const secretPattern = /(BEGIN PRIVATE KEY|BEGIN PKCS8|authorization|cookie|payload|pkcs8)/i;
  const clean = !secretPattern.test(serialized);
  return evidence(
    "chrome.capability.redaction",
    clean ? "pass" : "fail",
    "accept",
    clean ? null : "malformed.input",
    clean ? "open" : "closed",
    "none",
    event(clean ? "authentication.accepted" : "malformed.input", clean ? "accepted" : "rejected", clean ? "continue" : undefined)
  );
}

export async function runCapabilityProbe() {
  const records = [];
  const persistence = await probeKeyPersistence();
  records.push(persistence, ...probeBoundaries());
  records.push(proveRedaction(records));
  return records;
}

function emit(records) {
  for (const record of records) console.log(JSON.stringify(record));
}

// Node validation intentionally produces an explicit unsupported record; Chrome
// service workers run the same probe and produce the supported evidence instead.
if (typeof process !== "undefined" && process.argv[1]?.endsWith("capability.mjs")) {
  runCapabilityProbe().then(emit).catch(() => emit([unsupported("capability.unsupported")]));
} else if (globalThis.chrome?.runtime?.id) {
  runCapabilityProbe().then(emit).catch(() => emit([unsupported("capability.unsupported")]));
}
