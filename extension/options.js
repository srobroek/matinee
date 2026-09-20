import { storeIdentityKey } from "./key-store.js";

const form = document.querySelector("#pairing-form");
const endpointInput = document.querySelector("#endpoint");
const pairingKeyInput = document.querySelector("#pairing-key");
const statusOutput = document.querySelector("#status");

function setStatus(message, isError = false) {
  statusOutput.textContent = message;
  statusOutput.dataset.state = isError ? "error" : "ok";
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function validDaemonEndpoint(value) {
  let parsed;
  try { parsed = new URL(value); } catch { return false; }
  return (parsed.protocol === "ws:" || parsed.protocol === "wss:") &&
    parsed.hostname === "127.0.0.1" && parsed.pathname.startsWith("/") &&
    parsed.username === "" && parsed.password === "";
}

async function createIdentity() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign", "verify"]
  );
  if (pair.privateKey.extractable !== false || !pair.privateKey.usages.includes("sign")) {
    throw new Error("the browser did not create a non-exportable signing key");
  }
  const publicBytes = await crypto.subtle.exportKey("raw", pair.publicKey);
  const fingerprintBytes = await crypto.subtle.digest("SHA-256", publicBytes);
  const publicKey = bytesToBase64Url(publicBytes);
  const fingerprint = bytesToHex(fingerprintBytes);
  await storeIdentityKey(pair.privateKey, pair.publicKey, fingerprint);
  return { publicKey, fingerprint };
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const endpoint = endpointInput.value.trim();
  const oneTimeKey = pairingKeyInput.value;
  if (!validDaemonEndpoint(endpoint)) {
    setStatus("Use a ws:// or wss:// endpoint on 127.0.0.1.", true);
    return;
  }
  if (oneTimeKey.length === 0) {
    setStatus("Enter the one-time pairing key.", true);
    return;
  }
  setStatus("Generating the extension identity…");
  try {
    const identity = await createIdentity();
    await chrome.storage.local.set({
      matineePairing: {
        version: 1,
        endpoint,
        oneTimeKey,
        publicKey: identity.publicKey,
        fingerprint: identity.fingerprint
      }
    });
    const response = await chrome.runtime.sendMessage({
      type: "configure_pairing",
      endpoint,
      oneTimeKey,
      publicKey: identity.publicKey,
      fingerprint: identity.fingerprint
    });
    if (!response?.ok) throw new Error(response?.error ?? "the service worker rejected pairing");
    pairingKeyInput.value = "";
    setStatus(`Pairing started. Public-key fingerprint: ${identity.fingerprint}`);
  } catch (error) {
    setStatus(`Pairing failed: ${error instanceof Error ? error.message : String(error)}`, true);
  }
});
