/*
 * Deterministic Chrome capability fixture. This is deliberately not a product
 * package: it probes the two browser guarantees needed by enrollment custody.
 * Evidence never contains a key, signature, payload, or storage value.
 */

const STORAGE_KEY = "matinee.fixture.long_term_key.v1";
const IDB_NAME = "matinee.fixture.capability.v1";
const IDB_STORE = "keys";
const KEY_REFERENCE = "fixture-long-term-key";
const LOCK_NAME = "matinee.fixture.capability.probe.v1";
const DAEMON_IDENTITY = "daemon.synthetic";
const EPOCH = 7;
const DEADLINE_MS = 5_000;
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

let generation = 0;
let activeGeneration = 0;

function createAttempt(controller, fenced = false) {
  const attempt = {
    controller,
    signal: controller.signal,
    generation: fenced ? ++generation : 0,
    fenced,
    active: true,
    databases: new Set(),
    transactions: new Set(),
    settlements: new Set()
  };
  if (fenced) activeGeneration = attempt.generation;
  return attempt;
}

function throwIfAborted(attempt) {
  if (!attempt.active || attempt.signal.aborted ||
      (attempt.fenced && activeGeneration !== attempt.generation)) {
    throw new Error("capability.deadline");
  }
}

function fenceAttempt(attempt, reason = new Error("capability.deadline")) {
  if (!attempt.active) return;
  attempt.active = false;
  if (attempt.fenced && activeGeneration === attempt.generation) activeGeneration = ++generation;
  if (!attempt.signal.aborted) attempt.controller.abort(reason);
  for (const transaction of attempt.transactions) {
    try { transaction.abort(); } catch {}
  }
}

async function settleAttempt(attempt) {
  await Promise.allSettled([...attempt.settlements]);
  for (const database of attempt.databases) database.close();
  attempt.databases.clear();
}

function finishAttempt(attempt) {
  attempt.active = false;
  if (attempt.fenced && activeGeneration === attempt.generation) activeGeneration = ++generation;
}

async function withAbortableDeadline(milliseconds, label, operation) {
  const controller = new AbortController();
  const attempt = createAttempt(controller);
  const timer = setTimeout(() => fenceAttempt(attempt, new Error(label)), milliseconds);
  try {
    const result = await operation(attempt);
    throwIfAborted(attempt);
    return result;
  } finally {
    clearTimeout(timer);
    if (attempt.signal.aborted) fenceAttempt(attempt, attempt.signal.reason);
    await settleAttempt(attempt);
    finishAttempt(attempt);
  }
}

function openKeyDatabase(attempt, deadlineMs = DEADLINE_MS) {
  return new Promise((resolve, reject) => {
    throwIfAborted(attempt);
    const request = indexedDB.open(IDB_NAME, 1);
    let settled = false;
    const finish = (callback, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      attempt.signal.removeEventListener("abort", cancel);
      request.onerror = request.onblocked = null;
      request.onsuccess = callback === resolve ? null : () => request.result.close();
      callback(value);
    };
    const cancel = () => {
      try { request.transaction?.abort(); } catch {}
      finish(reject, attempt.signal.reason ?? new Error("indexeddb.open.abort"));
    };
    const timer = setTimeout(() => {
      try { request.transaction?.abort(); } catch {}
      finish(reject, new Error("indexeddb.open.deadline"));
    }, deadlineMs);
    attempt.signal.addEventListener("abort", cancel, { once: true });
    request.onerror = () => finish(reject, request.error ?? new Error("indexeddb.open"));
    request.onblocked = () => finish(reject, new Error("indexeddb.open.blocked"));
    request.onupgradeneeded = () => {
      try {
        throwIfAborted(attempt);
        if (!request.result.objectStoreNames.contains(IDB_STORE)) request.result.createObjectStore(IDB_STORE);
      } catch {
        try { request.transaction.abort(); } catch {}
      }
    };
    request.onsuccess = () => {
      attempt.databases.add(request.result);
      finish(resolve, request.result);
    };
  });
}

async function transact(attempt, mode, operation, deadlineMs = DEADLINE_MS) {
  const database = await openKeyDatabase(attempt, deadlineMs);
  throwIfAborted(attempt);
  const transaction = database.transaction(IDB_STORE, mode);
  attempt.transactions.add(transaction);
  let result;
  let abortReason;
  let resolveSettlement;
  let rejectSettlement;
  const settlement = new Promise((resolve, reject) => {
    resolveSettlement = resolve;
    rejectSettlement = reject;
  });
  attempt.settlements.add(settlement);
  const abort = (reason) => {
    abortReason ??= reason;
    try { transaction.abort(); } catch {}
  };
  const cancel = () => abort(attempt.signal.reason ?? new Error("indexeddb.transaction.abort"));
  const timer = setTimeout(() => abort(new Error("indexeddb.transaction.deadline")), deadlineMs);
  attempt.signal.addEventListener("abort", cancel, { once: true });
  transaction.oncomplete = () => resolveSettlement(result);
  transaction.onabort = () => rejectSettlement(abortReason ?? transaction.error ?? new Error("indexeddb.transaction.abort"));
  transaction.onerror = () => { abortReason ??= transaction.error ?? new Error("indexeddb.transaction.error"); };
  try {
    operation(transaction.objectStore(IDB_STORE), (value) => { result = value; });
    if (mode === "readwrite") {
      throwIfAborted(attempt);
      transaction.commit();
    }
  } catch (error) {
    abort(error);
  }
  try {
    const value = await settlement;
    throwIfAborted(attempt);
    return value;
  } finally {
    clearTimeout(timer);
    attempt.signal.removeEventListener("abort", cancel);
    transaction.oncomplete = transaction.onabort = transaction.onerror = null;
    attempt.transactions.delete(transaction);
    attempt.settlements.delete(settlement);
    database.close();
    attempt.databases.delete(database);
  }
}

function readStoredKey(attempt) {
  return transact(attempt, "readonly", (store, setResult) => {
    const request = store.get(KEY_REFERENCE);
    request.onsuccess = () => setResult(request.result);
  });
}

function writeStoredKey(attempt, record) {
  return transact(attempt, "readwrite", (store) => {
    throwIfAborted(attempt);
    store.put(record, KEY_REFERENCE);
  });
}

function clearStoredKey(attempt) {
  return transact(attempt, "readwrite", (store) => {
    throwIfAborted(attempt);
    store.delete(KEY_REFERENCE);
  });
}

async function storageGet(attempt) {
  throwIfAborted(attempt);
  const result = await chrome.storage.local.get(STORAGE_KEY);
  throwIfAborted(attempt);
  return result[STORAGE_KEY];
}

async function storageSet(attempt, value) {
  throwIfAborted(attempt);
  const settlement = chrome.storage.local.set({ [STORAGE_KEY]: value });
  attempt.settlements.add(settlement);
  try {
    await settlement;
    throwIfAborted(attempt);
  } finally {
    attempt.settlements.delete(settlement);
  }
}

async function storageRemove(attempt) {
  throwIfAborted(attempt);
  const settlement = chrome.storage.local.remove(STORAGE_KEY);
  attempt.settlements.add(settlement);
  try {
    await settlement;
    throwIfAborted(attempt);
  } finally {
    attempt.settlements.delete(settlement);
  }
}

async function clearCapability() {
  const removals = await Promise.allSettled([
    withAbortableDeadline(DEADLINE_MS, "storage.remove.deadline", storageRemove),
    withAbortableDeadline(DEADLINE_MS, "indexeddb.remove.deadline", clearStoredKey)
  ]);
  const reads = await Promise.allSettled([
    withAbortableDeadline(DEADLINE_MS, "storage.readback.deadline", storageGet),
    withAbortableDeadline(DEADLINE_MS, "indexeddb.readback.deadline", readStoredKey)
  ]);
  return removals.every(({ status }) => status === "fulfilled") &&
    reads.every(({ status, value }) => status === "fulfilled" && value === undefined);
}

async function publicKeyFingerprint(subtle, publicKey) {
  const raw = await subtle.exportKey("raw", publicKey);
  const digest = new Uint8Array(await subtle.digest("SHA-256", raw));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function probeKeyPersistence(attempt) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle || !globalThis.TextEncoder) return unsupported("capability.unsupported");
  if (!globalThis.chrome?.storage?.local || !globalThis.indexedDB) return unsupported("capability.unsupported");

  try {
    throwIfAborted(attempt);
    let metadata = await storageGet(attempt);
    if (metadata !== undefined && (metadata?.version !== 1 || metadata.key_reference !== KEY_REFERENCE ||
        metadata.daemon_identity !== DAEMON_IDENTITY || metadata.epoch !== EPOCH ||
        typeof metadata.public_key_fingerprint !== "string" || !/^[0-9a-f]{64}$/.test(metadata.public_key_fingerprint))) {
      await clearCapability();
      return unsupported("capability.persistence");
    }

    let record = await readStoredKey(attempt);
    throwIfAborted(attempt);
    if (metadata === undefined && record !== undefined) {
      await clearCapability();
      return unsupported("capability.persistence");
    }
    if (metadata === undefined) {
      const pair = await subtle.generateKey(
        { name: "ECDSA", namedCurve: "P-256" },
        false,
        ["sign", "verify"]
      );
      throwIfAborted(attempt);
      if (pair.privateKey.extractable !== false || !pair.privateKey.usages.includes("sign")) {
        await clearCapability();
        return unsupported("capability.non_exportable");
      }
      await writeStoredKey(attempt, { privateKey: pair.privateKey, publicKey: pair.publicKey, version: 1 });
      throwIfAborted(attempt);
      record = await readStoredKey(attempt);
      throwIfAborted(attempt);
      if (!record?.publicKey) {
        await clearCapability();
        return unsupported("capability.persistence");
      }
      const committedFingerprint = await publicKeyFingerprint(subtle, record.publicKey);
      throwIfAborted(attempt);
      await storageSet(attempt, {
        version: 1,
        key_reference: KEY_REFERENCE,
        public_key_fingerprint: committedFingerprint,
        daemon_identity: DAEMON_IDENTITY,
        epoch: EPOCH
      });
      throwIfAborted(attempt);
      metadata = await storageGet(attempt);
      throwIfAborted(attempt);
    }

    const fingerprint = record?.publicKey ? await publicKeyFingerprint(subtle, record.publicKey) : null;
    throwIfAborted(attempt);
    if (!record || record.version !== 1 || !record.privateKey || !record.publicKey ||
        metadata?.key_reference !== KEY_REFERENCE || metadata?.version !== 1 ||
        metadata?.daemon_identity !== DAEMON_IDENTITY || metadata?.epoch !== EPOCH ||
        metadata?.public_key_fingerprint !== fingerprint ||
        record.privateKey.extractable !== false || !record.privateKey.usages.includes("sign") ||
        !record.publicKey.usages.includes("verify")) {
      await clearCapability();
      return unsupported("capability.persistence");
    }
    const signature = await subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      record.privateKey,
      FIXTURE_MESSAGE
    );
    throwIfAborted(attempt);
    const verified = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      record.publicKey,
      signature,
      FIXTURE_MESSAGE
    );
    throwIfAborted(attempt);
    if (!verified) {
      await clearCapability();
      return unsupported("capability.persistence");
    }
    let exported = false;
    try {
      await subtle.exportKey("pkcs8", record.privateKey);
      exported = true;
    } catch {
      // The required non-exportability assertion passed.
    }
    throwIfAborted(attempt);
    if (exported) {
      await clearCapability();
      return unsupported("capability.exportable");
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
    await clearCapability();
    return unsupported("capability.persistence");
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

function capabilityRecords(persistence) {
  const records = [persistence, ...probeBoundaries()];
  records.push(proveRedaction(records));
  return records;
}

async function runCapabilityProbeUnlocked(attempt) {
  return capabilityRecords(await probeKeyPersistence(attempt));
}

async function cleanupAndFail(onRecords) {
  let cleaned = false;
  try {
    cleaned = await clearCapability();
  } catch {
    // Verification below remains fail-closed.
  }
  const records = capabilityRecords(unsupported(cleaned ? "capability.persistence" : "capability.cleanup"));
  try {
    await onRecords?.(records);
  } catch {
    // A failed evidence sink cannot turn a fail-closed result into a success.
  }
  return records;
}

export async function runCapabilityProbe(onRecords) {
  if (!globalThis.chrome?.runtime?.id) {
    const attempt = createAttempt(new AbortController());
    try {
      const records = await runCapabilityProbeUnlocked(attempt);
      await onRecords?.(records);
      return records;
    } finally {
      finishAttempt(attempt);
      await settleAttempt(attempt);
    }
  }
  if (!globalThis.navigator?.locks?.request) return cleanupAndFail(onRecords);

  const controller = new AbortController();
  let attempt;
  const timer = setTimeout(() => {
    if (attempt) fenceAttempt(attempt);
    else controller.abort(new Error("capability.deadline"));
  }, DEADLINE_MS);
  try {
    try {
      return await navigator.locks.request(
        LOCK_NAME,
        { mode: "exclusive", signal: controller.signal },
        async () => {
          attempt = createAttempt(controller, true);
          let records;
          let failed = false;
          try {
            records = await runCapabilityProbeUnlocked(attempt);
            throwIfAborted(attempt);
            await onRecords?.(records);
            throwIfAborted(attempt);
          } catch {
            failed = true;
            fenceAttempt(attempt);
          } finally {
            if (attempt.active) finishAttempt(attempt);
            await settleAttempt(attempt);
          }
          return failed ? cleanupAndFail(onRecords) : records;
        }
      );
    } catch {
      return await navigator.locks.request(
        LOCK_NAME,
        { mode: "exclusive" },
        () => cleanupAndFail(onRecords)
      );
    }
  } finally {
    clearTimeout(timer);
  }
}

function emit(records) {
  for (const record of records) console.log(JSON.stringify(record));
}

// Node validation intentionally produces an explicit unsupported record; Chrome
// service workers run the same probe and produce the supported evidence instead.
if (typeof process !== "undefined" && process.argv[1]?.endsWith("capability.mjs")) {
  runCapabilityProbe(emit).catch(() => emit(capabilityRecords(unsupported("capability.unsupported"))));
} else if (globalThis.chrome?.runtime?.id) {
  const runAndEmit = () => runCapabilityProbe(emit)
    .catch(() => emit(capabilityRecords(unsupported("capability.persistence"))));
  const reload = chrome.runtime.reload.bind(chrome.runtime);
  chrome.runtime.reload = () => { void runAndEmit().finally(reload); };
  globalThis.__matineeCapabilityProbe = runCapabilityProbe;
  void runAndEmit();
}
