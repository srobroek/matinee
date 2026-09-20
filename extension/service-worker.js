import { loadIdentityKey } from "./key-store.js";

const PROTOCOL_VERSION = "matinee.extension.v1";
const DEFAULT_DAEMON_ENDPOINT = "ws://127.0.0.1:7777/v1/extension";
const FIXTURE_HOST = "127.0.0.1";
const RECONNECT_MIN_MS = 250;
const RECONNECT_MAX_MS = 10_000;
const OPERATION_TIMEOUT_MS = 30_000;

let channelGeneration = 0;
let activeChannel = null;
let reconnectTimer = null;
let reconnectDelay = RECONNECT_MIN_MS;
let pairingInProgress = false;

const sessions = new Map();
const operations = new Map();
const sessionQueues = new Map();
const injectedDocuments = new Map();
const seenIncarnations = new Set();

function correlationId() {
  return crypto.randomUUID();
}

function base64Url(bytes) {
  let value = "";
  for (const byte of new Uint8Array(bytes)) value += String.fromCharCode(byte);
  return btoa(value).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const normalized = String(value).replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function extensionOrigin() {
  return `chrome-extension://${chrome.runtime.id}`;
}

function isFixtureUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" && url.hostname === FIXTURE_HOST;
  } catch {
    return false;
  }
}

function commandTarget(command) {
  const target = command.target && typeof command.target === "object" ? command.target : {};
  return {
    sessionId: command.session_id ?? target.session_id,
    tabIncarnation: command.tab_incarnation ?? target.tab_incarnation ?? target.incarnation,
    documentGeneration: command.document_generation ?? target.document_generation ?? target.generation,
    tabId: command.tab_id ?? target.tab_id,
    windowId: command.window_id ?? target.window_id
  };
}

function failure(code, summary, failedBoundary = "extension") {
  return {
    code,
    class: code.startsWith("authorization.") ? "authorization" : "stale_state",
    summary,
    failed_boundary: failedBoundary,
    retryable: code !== "incarnation.stale" && code !== "authorization.denied",
    next_actions: ["refresh the observation and retry with the current target"]
  };
}

function frame(channel, type, fields = {}) {
  return {
    type,
    protocol_version: PROTOCOL_VERSION,
    channel_generation: channel.generation,
    correlation_id: fields.correlation_id ?? correlationId(),
    ...fields
  };
}

function send(channel, type, fields = {}) {
  if (!channel || channel !== activeChannel || channel.socket.readyState !== WebSocket.OPEN) return false;
  channel.socket.send(JSON.stringify(frame(channel, type, fields)));
  return true;
}

function sendResult(channel, command, outcome, extra = {}) {
  const target = commandTarget(command);
  const session = sessions.get(target.sessionId);
  return send(channel, "result", {
    correlation_id: command.correlation_id ?? correlationId(),
    operation_id: command.operation_id,
    request_id: command.request_id,
    session_id: target.sessionId,
    tab_incarnation: session?.incarnation ?? target.tabIncarnation ?? null,
    document_generation: session?.documentGeneration ?? target.documentGeneration ?? null,
    action_sequence: command.action_sequence ?? command.sequence ?? null,
    outcome,
    ...extra
  });
}

function sendFailure(channel, command, code, summary, boundary = "extension") {
  return sendResult(channel, command, { status: "failed", failure: failure(code, summary, boundary) });
}

function sendUnobserved(channel, command, boundary) {
  return send(channel, "outcome_unobserved", {
    correlation_id: command.correlation_id ?? correlationId(),
    operation_id: command.operation_id,
    request_id: command.request_id,
    session_id: commandTarget(command).sessionId,
    boundary,
    failure: failure("operation.target_lost", `The extension lost the ${boundary} outcome.`, boundary)
  });
}

function sendIncarnationLost(session, command = null) {
  if (!activeChannel || !activeChannel.authenticated) return false;
  return send(activeChannel, "incarnation_lost", {
    correlation_id: command?.correlation_id ?? correlationId(),
    operation_id: command?.operation_id ?? null,
    request_id: command?.request_id ?? null,
    session_id: session.sessionId,
    tab_incarnation: session.incarnation,
    document_generation: session.documentGeneration,
    boundary: "tab",
    failure: failure("incarnation.stale", "The owned tab no longer exists.", "tab")
  });
}

function sendGenerationChanged(session, oldGeneration, newGeneration) {
  if (!activeChannel?.authenticated || activeChannel.generation !== channelGeneration) return false;
  return send(activeChannel, "generation_changed", {
    correlation_id: correlationId(),
    session_id: session.sessionId,
    tab_incarnation: session.incarnation,
    previous_document_generation: oldGeneration,
    document_generation: newGeneration,
    boundary: "document.navigation"
  });
}

function newIncarnation() {
  let value;
  do { value = `tab-incarnation-${crypto.randomUUID()}`; } while (seenIncarnations.has(value));
  seenIncarnations.add(value);
  return value;
}

function currentChannel(channel) {
  return channel && channel === activeChannel && channel.generation === channelGeneration;
}

function staleGeneration(channel, command) {
  if (currentChannel(channel) && command.channel_generation !== channel.generation) {
    send(channel, "generation_changed", {
      correlation_id: command.correlation_id ?? correlationId(),
      operation_id: command.operation_id ?? null,
      request_id: command.request_id ?? null,
      expected_generation: channel.generation,
      received_generation: command.channel_generation,
      failure: failure("generation.stale", "The command belongs to a superseded channel generation.", "channel")
    });
  }
  return false;
}

function commandIsWellFormed(command) {
  return typeof command.operation_id === "string" && command.operation_id.length > 0 &&
    typeof command.request_id === "string" && command.request_id.length > 0 &&
    typeof command.correlation_id === "string" && command.correlation_id.length > 0;
}

function verifyCommand(channel, command, options = {}) {
  if (!currentChannel(channel) || command.channel_generation !== channel.generation) {
    staleGeneration(channel, command);
    return { ok: false };
  }
  if (!channel.authenticated) {
    sendFailure(channel, command, "authorization.denied", "The pairing challenge has not completed.", "pairing");
    return { ok: false };
  }
  if (!commandIsWellFormed(command)) {
    sendFailure(channel, command, "authorization.denied", "The command identity is incomplete.", "command-admission");
    return { ok: false };
  }
  const target = commandTarget(command);
  if (options.bind) {
    if (typeof target.sessionId !== "string" || !command.target) {
      sendFailure(channel, command, "authorization.denied", "The bind target is incomplete.", "bind-admission");
      return { ok: false };
    }
    return { ok: true, target };
  }
  const session = sessions.get(target.sessionId);
  if (!session || session.lost) {
    sendFailure(channel, command, "incarnation.stale", "The requested session is not bound to a live tab.", "session");
    return { ok: false };
  }
  if (session.incarnation !== target.tabIncarnation) {
    sendFailure(channel, command, "incarnation.stale", "The tab incarnation does not match the owned tab.", "incarnation");
    return { ok: false };
  }
  if (session.documentGeneration !== target.documentGeneration) {
    sendFailure(channel, command, "generation.stale", "The document generation changed before dispatch.", "generation");
    return { ok: false };
  }
  const existingOperation = operations.get(command.operation_id);
  if (existingOperation && (existingOperation.sessionId !== session.sessionId || existingOperation.requestId !== command.request_id)) {
    sendFailure(channel, command, "authorization.denied", "The operation identity is bound to another session.", "operation");
    return { ok: false };
  }
  operations.set(command.operation_id, {
    sessionId: session.sessionId,
    requestId: command.request_id,
    actionSequence: command.action_sequence ?? command.sequence ?? null
  });
  return { ok: true, target, session };
}

async function documentGeneration(tabId) {
  if (!chrome.webNavigation?.getAllFrames) throw new Error("document generation API unavailable");
  const frames = await chrome.webNavigation.getAllFrames({ tabId });
  const mainFrame = frames?.find((frameInfo) => frameInfo.frameId === 0);
  if (!mainFrame?.documentId) throw new Error("document generation unavailable");
  return mainFrame.documentId;
}

async function bindSession(channel, command) {
  const admission = verifyCommand(channel, command, { bind: true });
  if (!admission.ok) return;
  const target = admission.target;
  const sessionId = target.sessionId;
  const existing = sessions.get(sessionId);
  let tab;
  try {
    if (existing) {
      tab = await chrome.tabs.get(existing.tabId);
      if (existing.lost || !tab) throw new Error("target lost");
    } else if (target.tabId !== undefined && target.tabId !== null) {
      tab = await chrome.tabs.get(target.tabId);
    } else if (command.target.create === true || command.target.create_tab === true) {
      const url = command.target.url;
      if (!isFixtureUrl(url)) {
        sendFailure(channel, command, "origin.rejected", "New sessions may only open the loopback fixture.", "origin");
        return;
      }
      tab = await chrome.tabs.create({ url, windowId: target.windowId, active: false });
    } else {
      sendFailure(channel, command, "authorization.denied", "The bind target does not name a tab or creation request.", "bind-admission");
      return;
    }
    if (!tab?.id || !isFixtureUrl(tab.url)) {
      if (!existing && tab?.id && (command.target.create === true || command.target.create_tab === true)) {
        await chrome.tabs.remove(tab.id).catch(() => {});
      }
      sendFailure(channel, command, "origin.rejected", "The owned tab is outside the pinned loopback fixture.", "origin");
      return;
    }
    const generation = await documentGeneration(tab.id);
    const session = existing ?? {
      sessionId,
      tabId: tab.id,
      windowId: tab.windowId,
      incarnation: newIncarnation(),
      documentGeneration: generation,
      seenGenerations: new Set(),
      lost: false,
      pendingGeneration: null
    };
    if (existing && existing.tabId !== tab.id) {
      sendFailure(channel, command, "incarnation.stale", "The session cannot be retargeted to another tab.", "incarnation");
      return;
    }
    session.tabId = tab.id;
    session.windowId = tab.windowId;
    session.documentGeneration = generation;
    session.seenGenerations.add(generation);
    session.lost = false;
    sessions.set(sessionId, session);
    sendResult(channel, command, {
      status: "succeeded",
      session_id: sessionId,
      tab_id: session.tabId,
      window_id: session.windowId,
      tab_incarnation: session.incarnation,
      document_generation: session.documentGeneration
    });
  } catch (error) {
    if (error?.message === "target lost") {
      const session = existing ?? { sessionId, incarnation: target.tabIncarnation ?? null, documentGeneration: target.documentGeneration ?? null, lost: true };
      sendIncarnationLost(session, command);
      return;
    }
    sendFailure(channel, command, "operation.target_lost", error instanceof Error ? error.message : "The tab could not be bound.", "bind");
  }
}

async function ensureContentScript(session) {
  if (injectedDocuments.get(session.tabId) === session.documentGeneration) return;
  await chrome.scripting.executeScript({ target: { tabId: session.tabId, frameIds: [0] }, files: ["content-script.js"] });
  injectedDocuments.set(session.tabId, session.documentGeneration);
}

async function contentCommand(session, message) {
  await ensureContentScript(session);
  try {
    return await chrome.tabs.sendMessage(session.tabId, message, { frameId: 0 });
  } catch (firstError) {
    injectedDocuments.delete(session.tabId);
    await ensureContentScript(session);
    try {
      return await chrome.tabs.sendMessage(session.tabId, message, { frameId: 0 });
    } catch {
      throw new Error(`content script unavailable: ${firstError?.message ?? "unknown error"}`);
    }
  }
}

function ensureContentSuccess(response) {
  if (!response?.ok) {
    const error = new Error(response?.failure?.summary ?? "content command failed");
    error.code = response?.failure?.code ?? "operation.target_lost";
    throw error;
  }
  return response.value;
}

async function observe(channel, command, admission) {
  const value = ensureContentSuccess(await contentCommand(admission.session, {
    action: "observe",
    document_generation: admission.session.documentGeneration
  }));
  if (admission.session.documentGeneration !== commandTarget(command).documentGeneration) {
    sendFailure(channel, command, "generation.stale", "The document changed while observing.", "generation");
    return;
  }
  sendResult(channel, command, { status: "succeeded", observation: value });
}

async function navigate(channel, command, admission) {
  const url = command.url ?? command.target?.url;
  if (!isFixtureUrl(url)) {
    sendFailure(channel, command, "origin.rejected", "Navigation is limited to the loopback fixture.", "origin");
    return;
  }
  admission.session.pendingGeneration = commandTarget(command).documentGeneration;
  const generationPromise = waitForGeneration(admission.session.tabId, 5_000);
  await chrome.tabs.update(admission.session.tabId, { url });
  const nextGeneration = await generationPromise;
  admission.session.documentGeneration = nextGeneration;
  admission.session.pendingGeneration = null;
  admission.session.seenGenerations.add(nextGeneration);
  injectedDocuments.delete(admission.session.tabId);
  sendResult(channel, command, {
    status: "succeeded",
    url,
    document_generation: nextGeneration
  });
}

function waitForGeneration(tabId, timeoutMs) {
  return new Promise((resolve, reject) => {
    let timer;
    const listener = (details) => {
      if (details.tabId !== tabId || details.frameId !== 0 || !details.documentId) return;
      chrome.webNavigation.onCommitted.removeListener(listener);
      clearTimeout(timer);
      resolve(details.documentId);
    };
    timer = setTimeout(() => {
      chrome.webNavigation.onCommitted.removeListener(listener);
      reject(new Error("document generation did not arrive"));
    }, timeoutMs);
    chrome.webNavigation.onCommitted.addListener(listener);
  });
}

async function elementAction(channel, command, admission, action) {
  const target = commandTarget(command);
  const value = ensureContentSuccess(await contentCommand(admission.session, {
    action,
    reference: command.element_reference ?? command.reference ?? command.element?.reference,
    text: command.text,
    document_generation: target.documentGeneration,
    operation_id: command.operation_id,
    session_id: admission.session.sessionId
  }));
  sendResult(channel, command, { status: "succeeded", observation: value });
}

async function screenshot(channel, command, admission) {
  const session = admission.session;
  const activeTabs = await chrome.tabs.query({ windowId: session.windowId, active: true });
  const previousTabId = activeTabs[0]?.id ?? null;
  let activated = false;
  let maskToken = null;
  let captureSucceeded = false;
  let dataUrl = null;
  let failureReason = null;
  try {
    if (previousTabId !== session.tabId) {
      await chrome.tabs.update(session.tabId, { active: true });
      activated = true;
    }
    const prepared = ensureContentSuccess(await contentCommand(session, {
      action: "prepare_screenshot",
      document_generation: session.documentGeneration
    }));
    if (!prepared.masked || typeof prepared.token !== "string") throw new Error("screenshot masking was not confirmed");
    maskToken = prepared.token;
    dataUrl = await chrome.tabs.captureVisibleTab(session.windowId, { format: "png" });
    captureSucceeded = true;
    if (typeof dataUrl !== "string" || !dataUrl.startsWith("data:image/png;base64,")) throw new Error("PNG capture was not returned");
  } catch (error) {
    failureReason = error;
  }
  if (maskToken) {
    try {
      ensureContentSuccess(await contentCommand(session, { action: "restore_screenshot", token: maskToken }));
    } catch (error) {
      failureReason ??= error;
    }
  }
  if (previousTabId !== null && previousTabId !== session.tabId) {
    try {
      await chrome.tabs.update(previousTabId, { active: true });
    } catch (error) {
      failureReason ??= error;
    }
  }
  if (failureReason) {
    if (captureSucceeded) {
      sendUnobserved(channel, command, "screenshot.restore");
    } else {
      sendFailure(channel, command, failureReason?.code ?? "operation.target_lost", failureReason instanceof Error ? failureReason.message : "Screenshot failed.", "screenshot");
    }
    return;
  }
  sendResult(channel, command, {
    status: "succeeded",
    screenshot_data: dataUrl,
    activated_tab_id: session.tabId,
    restored_tab_id: previousTabId,
    activation_changed: activated
  });
}

async function releaseSession(channel, command, admission) {
  const session = admission.session;
  try {
    if (command.close_tab === true || command.target?.close_tab === true) await chrome.tabs.remove(session.tabId);
    sessions.delete(session.sessionId);
    injectedDocuments.delete(session.tabId);
    sendResult(channel, command, {
      status: "succeeded",
      released: true,
      close_tab: command.close_tab === true || command.target?.close_tab === true
    });
  } catch (error) {
    sendFailure(channel, command, "operation.target_lost", error instanceof Error ? error.message : "The tab could not be released.", "release");
  }
}

function queueForSession(sessionId, operation) {
  const previous = sessionQueues.get(sessionId) ?? Promise.resolve();
  const current = previous.catch(() => {}).then(operation);
  const settled = current.finally(() => {
    if (sessionQueues.get(sessionId) === settled) sessionQueues.delete(sessionId);
  });
  sessionQueues.set(sessionId, settled);
  return current;
}

async function dispatch(channel, command) {
  if (!currentChannel(channel)) return;
  if (command.type === "bind_session") {
    await bindSession(channel, command);
    return;
  }
  const admission = verifyCommand(channel, command);
  if (!admission.ok) return;
  const task = async () => {
    if (!currentChannel(channel)) return;
    const currentAdmission = verifyCommand(channel, command);
    if (!currentAdmission.ok) return;
    operations.get(command.operation_id).pending = true;
    try {
      switch (command.type) {
        case "observe": await observe(channel, command, currentAdmission); break;
        case "navigate": await navigate(channel, command, currentAdmission); break;
        case "click": await elementAction(channel, command, currentAdmission, "click"); break;
        case "type": await elementAction(channel, command, currentAdmission, "type"); break;
        case "screenshot": await screenshot(channel, command, currentAdmission); break;
        case "release_session": await releaseSession(channel, command, currentAdmission); break;
        default: sendFailure(channel, command, "authorization.denied", `Unsupported command: ${command.type}`, "command-admission");
      }
    } catch (error) {
      if (error?.code === "generation.stale") {
        sendFailure(channel, command, "generation.stale", error.message, "generation");
      } else if (error?.name === "InvalidStateError" || error?.message?.includes("closed")) {
        sendUnobserved(channel, command, "extension-dispatch");
      } else {
        sendFailure(channel, command, error?.code ?? "operation.target_lost", error instanceof Error ? error.message : "The browser command failed.", "dispatch");
      }
    } finally {
      const record = operations.get(command.operation_id);
      if (record) record.pending = false;
    }
  };
  const sessionId = admission.session.sessionId;
  await queueForSession(sessionId, () => Promise.race([
    task(),
    new Promise((_, reject) => setTimeout(() => reject(new Error("operation deadline expired")), OPERATION_TIMEOUT_MS))
  ])).catch((error) => {
    if (error?.message === "operation deadline expired") {
      const record = operations.get(command.operation_id);
      if (record?.timedOut) return;
      if (record) record.timedOut = true;
      if (currentChannel(channel)) sendUnobserved(channel, command, "operation.deadline");
    }
  });
}

async function pairingHello(channel) {
  const stored = await chrome.storage.local.get("matineePairing");
  const pairing = stored.matineePairing;
  const identity = await loadIdentityKey().catch(() => null);
  if (!pairing || !identity?.publicKey || !identity?.privateKey || pairing.fingerprint !== identity.fingerprint) {
    pairingInProgress = false;
    return false;
  }
  pairingInProgress = true;
  return send(channel, "pairing_hello", {
    origin: extensionOrigin(),
    one_time_key: pairing.oneTimeKey ?? null,
    public_key: pairing.publicKey,
    fingerprint: pairing.fingerprint
  });
}

async function pairingProof(channel, message) {
  if (!pairingInProgress || !currentChannel(channel)) return;
  const stored = await chrome.storage.local.get("matineePairing");
  const pairing = stored.matineePairing;
  const identity = await loadIdentityKey();
  if (!pairing || !identity?.privateKey || pairing.fingerprint !== identity.fingerprint) return;
  const challenge = message.challenge ?? message.challenge_bytes;
  if (typeof challenge !== "string") return;
  const transcript = new TextEncoder().encode(
    `matinee.browser.pairing.v1\0${extensionOrigin()}\0${pairing.fingerprint}\0${challenge}`
  );
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    identity.privateKey,
    transcript
  );
  send(channel, "pairing_proof", {
    public_key: pairing.publicKey,
    fingerprint: pairing.fingerprint,
    signature: base64Url(signature),
    challenge
  });
}

async function pairingAccepted(channel) {
  pairingInProgress = false;
  const stored = await chrome.storage.local.get("matineePairing");
  if (stored.matineePairing) {
    await chrome.storage.local.set({ matineePairing: { ...stored.matineePairing, oneTimeKey: null } });
  }
  channel.authenticated = true;
  reconnectDelay = RECONNECT_MIN_MS;
}

function rejectSupersededChannel(channel, message) {
  if (channel !== activeChannel) return;
  staleGeneration(channel, message);
}

async function receive(channel, message) {
  if (!currentChannel(channel)) return;
  if (message.channel_generation !== channel.generation) {
    rejectSupersededChannel(channel, message);
    return;
  }
  if (message.type === "pairing_challenge") {
    await pairingProof(channel, message);
    return;
  }
  if (message.type === "pairing_complete" || message.type === "pairing_accepted") {
    await pairingAccepted(channel);
    return;
  }
  if (!channel.authenticated) {
    if (message.operation_id) sendFailure(channel, message, "authorization.denied", "The pairing challenge has not completed.", "pairing");
    return;
  }
  if (["bind_session", "observe", "navigate", "click", "type", "screenshot", "release_session"].includes(message.type)) {
    await dispatch(channel, message);
  }
}

function scheduleReconnect() {
  if (reconnectTimer !== null) return;
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    connect().catch(() => scheduleReconnect());
  }, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, RECONNECT_MAX_MS);
}

async function connect(endpoint = null) {
  const configured = await chrome.storage.local.get("matineePairing");
  const url = endpoint ?? configured.matineePairing?.endpoint ?? DEFAULT_DAEMON_ENDPOINT;
  if (activeChannel?.socket) {
    try { activeChannel.socket.close(1000, "superseded channel generation"); } catch {}
  }
  const generation = ++channelGeneration;
  const channel = { generation, socket: new WebSocket(url, PROTOCOL_VERSION), authenticated: false };
  activeChannel = channel;
  channel.socket.onopen = async () => {
    if (!currentChannel(channel)) return;
    reconnectDelay = RECONNECT_MIN_MS;
    await pairingHello(channel);
  };
  channel.socket.onmessage = (event) => {
    if (!currentChannel(channel)) return;
    let message;
    try { message = JSON.parse(event.data); } catch { return; }
    receive(channel, message).catch(() => {});
  };
  channel.socket.onerror = () => {};
  channel.socket.onclose = () => {
    if (!currentChannel(channel)) return;
    channel.authenticated = false;
    activeChannel = null;
    scheduleReconnect();
  };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type !== "configure_pairing") return false;
  const endpoint = message.endpoint;
  if (typeof endpoint !== "string" || !/^wss?:\/\/127\.0\.0\.1(?::[0-9]+)?(?:\/.*)?$/.test(endpoint)) {
    sendResponse({ ok: false, error: "the daemon endpoint must use ws:// or wss:// on 127.0.0.1" });
    return false;
  }
  connect(endpoint).then(() => sendResponse({ ok: true })).catch((error) => sendResponse({ ok: false, error: String(error) }));
  return true;
});

chrome.webNavigation?.onCommitted?.addListener((details) => {
  if (details.frameId !== 0 || !details.documentId) return;
  const session = Array.from(sessions.values()).find((candidate) => candidate.tabId === details.tabId);
  if (!session) return;
  const oldGeneration = session.documentGeneration;
  if (oldGeneration === details.documentId) return;
  if (session.seenGenerations.has(details.documentId)) {
    session.lost = true;
    sendIncarnationLost(session);
    return;
  }
  session.documentGeneration = details.documentId;
  session.seenGenerations.add(details.documentId);
  injectedDocuments.delete(details.tabId);
  if (session.pendingGeneration !== oldGeneration) sendGenerationChanged(session, oldGeneration, details.documentId);
});

chrome.tabs?.onRemoved?.addListener((tabId) => {
  for (const session of sessions.values()) {
    if (session.tabId !== tabId) continue;
    session.lost = true;
    injectedDocuments.delete(tabId);
    sendIncarnationLost(session);
  }
});

chrome.runtime.onStartup?.addListener(() => connect().catch(() => scheduleReconnect()));
chrome.runtime.onInstalled?.addListener(() => connect().catch(() => scheduleReconnect()));
connect().catch(() => scheduleReconnect());
