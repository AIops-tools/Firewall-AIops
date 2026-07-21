# Release notes — firewall-aiops 0.6.0

Previous release: 0.5.0.

## BREAKING — the authorization layer is removed

This tool no longer decides whether a write is permitted. Read-only mode
(`<PREFIX>_READ_ONLY`), the graduated-approval / approver gate, and the
`rules.yaml` deny engine are **all gone**. Whether an operation runs is the
agent's judgement, or the permission of the account you connect it with — point
it at a read-only credential and the write fails at the server, the place that
actually owns the permission.

What the tool guarantees instead is that **nothing is silent**: every operation,
over MCP **and** the CLI alike, lands a row in the audit log — there is no
unaudited entry point. Destructive writes still capture their before-state and
record an undo token where a clean inverse exists.

- If you set `<PREFIX>_READ_ONLY=1`, it now has **no effect** and the MCP server
  logs a warning at startup. Restrict writes via the connecting account instead.
- `<PREFIX>_AUDIT_APPROVED_BY` / `<PREFIX>_AUDIT_RATIONALE` still work, but are now
  **optional audit annotations** — recorded on the row when set, never required.
- The declared `risk_level` is carried into the audit row as a descriptive tier
  (a label, not a gate).

The governance harness is now: **audit (MCP+CLI, unbypassable) · runaway/budget
safety guard · undo recording · output sanitize**. `policy.py` is a small
risk-tier classifier; `governance/readonly.py` is deleted.


## Also in this tool

- **New `scheme:`** (default https).
