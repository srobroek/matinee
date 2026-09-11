# Matinee External Contracts

This directory defines the first public Matinee contract family.

## Contract Family

| Contract | Owner | Consumer | Compatibility identifier |
|---|---|---|---|
| MCP tools | `matinee-cli` MCP mode | MCP clients | MCP protocol plus `matinee.tools.v1` |
| CLI | `matinee-cli` | Users and local automation | `matinee.cli.v1` for JSON output |
| Daemon protocol | `matinee-daemon` | CLI and MCP adapter | `matinee.daemon.v1` |
| Extension protocol | `matinee-daemon` and extension | Paired Chrome extension | `matinee.extension.v1` |
| Persistence schema | `matinee-store` | Newer Matinee releases | integer schema version |
| Artifact metadata | `matinee-daemon` | CLI and MCP clients | `matinee.artifact.v1` |
| MCP schemas | `matinee-protocol` | MCP adapter and clients | `matinee.tools.v1` |

## Rules

1. Every JSON object rejects unknown required-version values before mutation.
2. Additive optional fields are compatible within a contract version.
3. Removing a field, changing its meaning, narrowing an accepted value, or changing a
   state transition requires a new contract version.
4. Before Matinee 1.0, a release may remove an old contract version when its changelog,
   migration behavior, and peer rejection are explicit.
5. The daemon is authoritative for request, operation, attention, session, and artifact
   state. MCP and CLI clients do not synthesize state transitions.
6. User approval is absent from the MCP contract. Only the paired extension decision
   surface can produce an approval decision.
7. Rust types and generated JSON Schemas are canonical. Generated TypeScript types and
   checked-in schema fixtures must match them byte for byte after formatting.

## Common Failure Envelope

```json
{
  "contract": "matinee.daemon.v1",
  "ok": false,
  "failure": {
    "code": "selection.ambiguous",
    "class": "selection",
    "summary": "More than one eligible tab matches the request.",
    "boundary": "session.open.select-tab",
    "retryability": "client_after_change",
    "request_id": null,
    "operation_id": null,
    "safe_next_actions": [
      {"action": "select_tab", "candidate_ids": ["tab_a", "tab_b"]}
    ]
  }
}
```

The `details` object is optional and redacted. Secret fields never appear in the
envelope. Unknown failure codes remain displayable through `class`, `summary`,
`boundary`, and `safe_next_actions`.
