const MAX_REFERENCES = 128;
const MAX_TEXT_LENGTH = 256;
const REFERENCE_PREFIX = "matinee-ref-v1";
const screenshotMasks = new Map();
let nextScreenshotMask = 1;
const localState = {
  documentGeneration: null,
  references: new Map(),
  nextReference: 1
};

function screenshotToken() {
  return `matinee-mask-v1-${nextScreenshotMask++}`;
}

function boundedText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim().slice(0, MAX_TEXT_LENGTH);
}

function isSecretElement(element) {
  return element.matches("input[type=password], [data-matinee-secret], [aria-label*='password' i]") ||
    element.closest("[data-matinee-secret]") !== null;
}

function visibleElement(element) {
  const style = getComputedStyle(element);
  const rect = element.getBoundingClientRect();
  return style.display !== "none" && style.visibility !== "hidden" &&
    rect.width > 0 && rect.height > 0;
}

function describeElement(element) {
  if (isSecretElement(element) || !visibleElement(element)) return null;
  const role = element.getAttribute("role") || element.tagName.toLowerCase();
  const label = element.getAttribute("aria-label") ||
    element.getAttribute("name") ||
    element.labels?.[0]?.textContent ||
    element.textContent || "";
  const description = {
    reference: null,
    role: boundedText(role),
    name: boundedText(label)
  };
  if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element instanceof HTMLSelectElement) {
    if (element.type !== "password" && !element.hasAttribute("data-matinee-secret")) {
      description.value = boundedText(element.value);
    }
  }
  return description;
}

function ensureGeneration(documentGeneration) {
  if (typeof documentGeneration !== "string" || documentGeneration.length === 0) {
    throw new Error("generation.stale");
  }
  if (localState.documentGeneration !== documentGeneration) {
    localState.documentGeneration = documentGeneration;
    localState.references.clear();
    localState.nextReference = 1;
  }
}

function makeReference(element, documentGeneration) {
  const ordinal = localState.nextReference++;
  const reference = `${REFERENCE_PREFIX}:${btoa(JSON.stringify({ documentGeneration, ordinal }))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")}`;
  localState.references.set(reference, element);
  return reference;
}

function candidates() {
  const selector = "button, input, textarea, select, a, [role], [contenteditable='true']";
  return Array.from(document.querySelectorAll(selector)).slice(0, MAX_REFERENCES);
}

function observe(documentGeneration) {
  ensureGeneration(documentGeneration);
  localState.references.clear();
  const elements = [];
  for (const element of candidates()) {
    const description = describeElement(element);
    if (!description) continue;
    description.reference = makeReference(element, documentGeneration);
    elements.push(description);
    if (elements.length >= MAX_REFERENCES) break;
  }
  return {
    document_generation: documentGeneration,
    elements,
    bounded: true
  };
}

function decodeReference(reference) {
  if (typeof reference !== "string" || !reference.startsWith(`${REFERENCE_PREFIX}:`)) return null;
  try {
    const encoded = reference.slice(REFERENCE_PREFIX.length + 1)
      .replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(encoded));
  } catch {
    return null;
  }
}

function resolveReference(reference, documentGeneration) {
  const decoded = decodeReference(reference);
  if (!decoded || decoded.documentGeneration !== documentGeneration) throw new Error("generation.stale");
  const element = localState.references.get(reference);
  if (!element || !element.isConnected || isSecretElement(element)) throw new Error("generation.stale");
  return element;
}

function indicator(operationId, sessionId, element) {
  document.querySelector("#matinee-owner-indicator")?.remove();
  document.querySelector("#matinee-synthetic-cursor")?.remove();
  const owner = document.createElement("div");
  owner.id = "matinee-owner-indicator";
  owner.textContent = `Matinee · ${sessionId} · ${operationId}`;
  Object.assign(owner.style, {
    position: "fixed", zIndex: "2147483647", top: "10px", right: "10px",
    padding: "6px 10px", borderRadius: "5px", color: "#fff",
    background: "#173b6c", font: "12px system-ui, sans-serif", pointerEvents: "none"
  });
  document.documentElement.append(owner);

  const rect = element.getBoundingClientRect();
  const highlight = element;
  const previousOutline = highlight.style.outline;
  const previousOutlineOffset = highlight.style.outlineOffset;
  highlight.style.outline = "3px solid #f2b134";
  highlight.style.outlineOffset = "2px";

  const cursor = document.createElement("div");
  cursor.id = "matinee-synthetic-cursor";
  Object.assign(cursor.style, {
    position: "fixed", zIndex: "2147483646", left: `${rect.left + rect.width / 2 - 8}px`,
    top: `${rect.top + rect.height / 2 - 8}px`, width: "16px", height: "16px",
    border: "2px solid #fff", borderRadius: "50%", background: "#e45756",
    boxShadow: "0 0 0 2px #e45756", pointerEvents: "none"
  });
  document.documentElement.append(cursor);
  return () => {
    highlight.style.outline = previousOutline;
    highlight.style.outlineOffset = previousOutlineOffset;
    owner.remove();
    cursor.remove();
  };
}

async function activate(reference, documentGeneration, operationId, sessionId, action, text = "") {
  ensureGeneration(documentGeneration);
  const element = resolveReference(reference, documentGeneration);
  const clearIndicator = indicator(operationId, sessionId, element);
  await new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  try {
    if (action === "click") {
      element.click();
    } else {
      if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement || element.isContentEditable)) {
        throw new Error("target is not editable");
      }
      element.focus();
      const bounded = String(text).slice(0, MAX_TEXT_LENGTH);
      if (element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement) {
        element.select();
        element.value = bounded;
      } else {
        element.textContent = bounded;
      }
      element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "insertText", data: bounded }));
      element.dispatchEvent(new Event("change", { bubbles: true }));
    }
  } finally {
    clearIndicator();
  }
  return observe(documentGeneration);
}

function prepareScreenshot(documentGeneration) {
  ensureGeneration(documentGeneration);
  const hidden = [];
  for (const element of document.querySelectorAll("input[type=password], [data-matinee-secret]")) {
    hidden.push({ element, visibility: element.style.visibility });
    element.style.visibility = "hidden";
  }
  const token = screenshotToken();
  screenshotMasks.set(token, hidden);
  return { masked: true, token, count: hidden.length };
}

function restoreScreenshot(token) {
  const hidden = screenshotMasks.get(token);
  if (!hidden) throw new Error("screenshot masking token is invalid");
  for (const entry of hidden) {
    if (entry?.element) entry.element.style.visibility = entry.visibility ?? "";
  }
  screenshotMasks.delete(token);
  return { restored: true };
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  Promise.resolve().then(() => {
    switch (message?.action) {
      case "observe":
        return { ok: true, value: observe(message.document_generation) };
      case "click":
        return activate(message.reference, message.document_generation, message.operation_id, message.session_id, "click")
          .then((value) => ({ ok: true, value }));
      case "type":
        return activate(message.reference, message.document_generation, message.operation_id, message.session_id, "type", message.text)
          .then((value) => ({ ok: true, value }));
      case "prepare_screenshot":
        return { ok: true, value: prepareScreenshot(message.document_generation) };
      case "restore_screenshot":
        return { ok: true, value: restoreScreenshot(message.token) };
      default:
        return { ok: false, failure: { code: "authorization.denied", summary: "unknown content command" } };
    }
  }).then(sendResponse).catch((error) => sendResponse({
    ok: false,
    failure: {
      code: error?.message === "generation.stale" ? "generation.stale" : "operation.target_lost",
      summary: error instanceof Error ? error.message : String(error)
    }
  }));
  return true;
});
