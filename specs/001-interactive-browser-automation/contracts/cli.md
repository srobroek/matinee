# CLI Contract

## Invocation

```text
matinee [--config <path>] [--state-dir <path>] [--output human|json] <command>
```

`--output json` emits one `matinee.cli.v1` envelope to stdout. Human output goes to
stdout. Diagnostics go to stderr. The CLI never prints a reusable private key. A
single-use enrollment value appears only in the dedicated interactive pairing flow.

## Commands

### `matinee setup`

```text
matinee setup [--browser chrome|chromium] [--mcp-client <name>]
              [--allow-development-extension <id>]
```

Setup performs these steps:

1. Create the state directory.
2. Bootstrap the first native principal and start one daemon.
3. Create a ten-minute enrollment and open the expected extension's pairing surface.
4. Wait for extension activation.
5. Register or reuse the uniquely named MCP client.
6. Print client configuration containing its principal ID.

Re-running setup preserves healthy registrations. Rotating a stale credential requires an
explicit rotation action.

### `matinee doctor`

```text
matinee doctor [--check browser|daemon|extension|storage|protocol|permissions]
```

Runs read-only checks. JSON output contains an ordered `checks` array with `id`,
`status`, `summary`, `observed`, and `next_actions`. Status is `pass`, `warn`, or `fail`.

### `matinee status`

```text
matinee status [--requests active|all] [--limit <1..100>]
```

Returns daemon readiness, contract range, resolved non-secret configuration sources,
paired extension summaries, active sessions, active requests, pending attention,
queue depth, and degraded dependencies.

### `matinee stop`

```text
matinee stop [--deadline <duration>]
```

Requests draining shutdown. The result lists requests that reached safe boundaries and
operations requiring reconciliation. The command does not force-kill a daemon.

### `matinee mcp`

```text
matinee mcp --client <principal-id>
```

Runs the stdio MCP adapter. stdout is reserved for MCP frames. Logs go to stderr. The
adapter resolves exactly one credential-store entry under service `matinee` and account
`<state-directory-fingerprint>:<principal-id>`. That entry contains the client's private
key and pinned daemon identity. A missing, mismatched, or revoked entry fails before MCP
initialization. Setup emits this exact argument in each client configuration. The adapter
connects to or guardedly starts the daemon, completes negotiation, and serves until stdin
closes or the MCP client disconnects.

### `matinee diagnostics export`

```text
matinee diagnostics export --request <request-id> --destination <path>
```

Creates one redacted diagnostic bundle for an authorized retained request. The command
fails instead of overwriting an existing path. Its result returns the bundle digest,
byte size, redaction status, and expiry.

### `matinee version`

Returns package version, Rust minimum version, state-schema version, CLI JSON version,
secure-channel version and cipher suite, daemon application-contract range, extension
application-contract range, and MCP tool contract version.

### `matinee uninstall`

```text
matinee uninstall --data retain|delete
```

Stops the daemon, revokes client and extension registrations, removes installed runtime
integration, and applies the explicit data choice. `delete` removes history, artifacts,
and stored credentials after listing their locations.

## Default Locations

| Platform | User configuration | State directory |
|---|---|---|
| macOS | `~/Library/Application Support/Matinee/config.toml` | `~/Library/Application Support/Matinee/state/` |
| Linux | `${XDG_CONFIG_HOME:-~/.config}/matinee/config.toml` | `${XDG_STATE_HOME:-~/.local/state}/matinee/` |
| Windows | `%APPDATA%\Matinee\config.toml` | `%LOCALAPPDATA%\Matinee\state\` |

The project configuration is `matinee.toml` in the invocation's working directory.
Matinee does not search parent directories. `--config` replaces the project-file path,
and `--state-dir` replaces the state directory. Environment keys use the `MATINEE_`
prefix and double underscores for nesting.

## JSON Success Envelope

```json
{
  "contract": "matinee.cli.v1",
  "command": "status",
  "ok": true,
  "result": {},
  "warnings": []
}
```

Failures use the common failure envelope and include `command`.

## Exit Codes

| Code | Meaning |
|---:|---|
| 0 | Command completed |
| 2 | Invalid invocation or configuration |
| 3 | Selection or user input required |
| 4 | Authentication or authorization failure |
| 5 | Incompatible package, protocol, or state version |
| 6 | Browser or extension unavailable |
| 7 | Timeout or cancellation |
| 8 | Persistence, artifact, or recovery failure |
| 9 | Resource limit |
| 10 | Internal invariant failure |

Human and JSON output use the same exit code mapping.
