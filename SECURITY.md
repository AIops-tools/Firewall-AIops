# Security Policy

## Disclaimer

Community-maintained open-source project. **Not affiliated with, endorsed by, or
sponsored by the OPNsense project, Deciso, Netgate, or the pfSense project.**
Product and trademark names (OPNsense, pfSense, Netgate) belong to their owners.
Source is auditable under the MIT license.

## Reporting Vulnerabilities

Report privately via a GitHub Security Advisory on
[github.com/AIops-tools/Firewall-AIops](https://github.com/AIops-tools/Firewall-AIops/security/advisories)
or email zhouwei008@gmail.com. Please do not open public issues for security
reports.

## Security Design

### Credential Management
- Per-target secrets — the OPNsense API **secret** (paired with the API key for
  HTTP Basic auth) or the pfSense **API key** — live **encrypted** in
  `~/.firewall-aiops/secrets.enc` (Fernet/AES-128 + scrypt-derived key; chmod
  600), never in `config.yaml` and never in source. The master password is never
  stored — only a per-store random salt and the ciphertext are on disk.
- A legacy plaintext env var `FIREWALL_<TARGET_NAME_UPPER>_SECRET` is still
  honoured as a fallback with a deprecation warning (migrate with
  `firewall-aiops secret migrate`).
- The secret is held only in memory and never logged or echoed. It is presented
  as HTTP Basic auth (OPNsense) or an `X-API-Key` header (pfSense) at request
  time; the config file holds only platform, host, port, username, and TLS
  settings.

### Governed Operations
Every MCP tool runs through the bundled `@governed_tool` harness
(`firewall_aiops.governance`):
- **Audit** — every call logged to a local SQLite DB under `~/.firewall-aiops/`
  (relocatable via `FIREWALL_AIOPS_HOME`), agent-attributed, secret-redacted.
- **Token/runaway budget** — hard ceilings (`FIREWALL_MAX_TOOL_CALLS` /
  `FIREWALL_MAX_TOOL_SECONDS`) plus an on-by-default guard that trips a tight
  poll/retry loop, preventing unbounded API consumption.
- **Graduated risk tiers** — `~/.firewall-aiops/rules.yaml` `risk_tiers` gate
  writes by environment/tag; the highest tiers require a recorded approver.
- **Undo-token recording** — reversible writes capture the BEFORE state (via a
  real GET) and record an inverse descriptor (e.g. `toggle_rule` restores the
  prior enabled flag; `add_alias_entry`→`remove_alias_entry`) so the change can
  be rolled back.

### State-Changing Operations
The "make it live" commits — `apply_changes`, `reconfigure` — and `reboot` are
`risk_level=high`, accept a `dry_run` preview, and (under `risk_tiers`) require a
recorded approver (`FIREWALL_AUDIT_APPROVED_BY` + `FIREWALL_AUDIT_RATIONALE`).
`reboot` is irreversible (audit only, no undo). Rule toggle, alias entry
add/remove, `kill_states`, and `restart_service` are `risk_level=medium`;
reversible ones capture before-state and record an undo token.

### SSL/TLS Verification
`verify_ssl` defaults to true; disable only for self-signed lab certificates.

### Prompt-Injection Protection
All firewall-returned text (rule descriptions, alias entries, log lines, VPN peer
names, gateway names) is passed through a `sanitize()` truncate + control-character
strip before reaching the agent.

### Network Scope
No webhooks, no telemetry, no outbound calls beyond the configured OPNsense /
pfSense REST API endpoints. No post-install scripts or background services.

## Static Analysis

```bash
uvx bandit -r firewall_aiops/ mcp_server/
uv run ruff check .
```

## Supported Versions

The latest released version receives security fixes. This is a preview (0.x);
pin a version in production.
