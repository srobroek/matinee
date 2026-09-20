# Matinee MV3 extension

An unpacked Manifest V3 extension controls the local Matinee fixture through one authenticated loopback WebSocket.

## Load the extension

1. `manifest.json` already carries a development `key`, so the unpacked extension loads with the fixed id `ebdmpbapkdbgnhlglhggkdfbekgojgcm` and the paired origin `chrome-extension://ebdmpbapkdbgnhlglhggkdfbekgojgcm`. Confirm the id Chrome shows matches that value before pairing. To pin a different key, replace `key` with a base64 SPKI public key, then derive its id from the first 32 hex digits of the key's SHA-256 digest, mapping each digit `0`-`f` to `a`-`p`.
2. Open `chrome://extensions` in Chrome or Chromium.
3. Turn on **Developer mode**.
4. Select **Load unpacked**. Choose this `extension/` directory.
5. Open the extension **Details** page. Select **Extension options**.
6. Enter the loopback WebSocket endpoint and one-time pairing key supplied by setup.
7. Retain the displayed public-key fingerprint with the pairing record.

The extension stores the signing key in extension-local IndexedDB. The private key uses `extractable: false`. Pairing messages contain only the public key, fingerprint, and one-time pairing key.

Keep the same `key` value after pairing. A different value changes the extension origin.

## Permissions

The manifest contains these permissions:

- `scripting`: injects `content-script.js` into an owned fixture tab for observation and DOM actions.
- `activeTab`: permits activation of the owned tab for PNG capture.
- `webNavigation`: supplies the main-frame `documentId` used as the document generation.
- `http://127.0.0.1/*`: limits browser automation to the loopback fixture.

The extension uses no capability beyond the permissions listed above.

## Protocol behavior

The worker sends the pinned extension origin in the pairing hello. It passes `matinee.extension.v1` as the WebSocket subprotocol. It accepts daemon commands only after it signs the pairing challenge with the local private key.

Every frame contains `protocol_version`, `channel_generation`, and `correlation_id`. Command frames add `operation_id`, `request_id`, and a target descriptor.

The worker handles these daemon commands:

- `bind_session`
- `observe`
- `navigate`
- `click`
- `type`
- `screenshot`
- `release_session`

The worker emits these extension frames:

- `result`
- `outcome_unobserved`
- `generation_changed`
- `incarnation_lost`

Each reconnect increments `channel_generation`. The worker ignores frames from an older generation. A wrong generation on the current socket receives `generation_changed` with `generation.stale`.

Each bound tab receives a fresh opaque incarnation. Main-frame `documentId` scopes observations and element references. A missing tab emits `incarnation_lost`. Any session, operation, incarnation, or document-generation mismatch fails before browser dispatch.

The screenshot flow activates the owned tab. It captures PNG bytes with `captureVisibleTab`. It restores the active tab before returning the result.
Click and type show these indicators before activation:

- owner indicator
- operation boundary
- synthetic cursor
- target highlight

## Validation

Run these commands from the repository root:

```sh
node --check extension/service-worker.js
node --check extension/content-script.js
node --check extension/options.js
node --check extension/key-store.js
node -e "JSON.parse(require('fs').readFileSync('extension/manifest.json', 'utf8'))"
```
