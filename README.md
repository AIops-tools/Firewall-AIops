<!-- mcp-name: io.github.AIops-tools/firewall-aiops -->

# Firewall AIops

Governed, audited AI-ops for **OPNsense** and **pfSense** firewalls — for AI agents (via MCP) and humans (via CLI).

> **Disclaimer**: Community-maintained open-source project. **Not affiliated with, endorsed by, or sponsored by the OPNsense project, Deciso, Netgate, or the pfSense project.** OPNsense, pfSense and Netgate are trademarks of their respective owners. MIT licensed.

firewall-aiops speaks to two firewall platforms behind one MCP server — **OPNsense**
(REST API under `/api/...`, API key+secret via HTTP Basic auth) and **pfSense**
(REST API v2 under `/api/v2/...` from the pfSense-pkg-RESTAPI package, API key via
an `X-API-Key` header) — with the **same tools working on both**. Each target in the
config names its own `platform`; a name-keyed platform registry selects the API shape
(auth + resource paths), so an agent never has to know which firewall it is talking to.

Every tool runs through a **built-in governance harness** (vendored, zero external
dependency): audit log, token/call budget with runaway circuit-breaker, descriptive
risk-tier labelling, undo-token recording, and prompt-injection sanitisation.

## Why this exists

- **One server, both firewalls** — OPNsense and pfSense in a mixed estate, spoken to
  through identical tool names. Adding a third firewall later is a new platform
  descriptor, not a rewrite.
- **Read the whole firewall** — firmware/health, interfaces & gateways, filter rules
  (with hit counts and state table), NAT (port-forward / outbound / 1:1), aliases,
  VPN (WireGuard / OpenVPN / IPsec), DHCP leases & reservations, and the firewall log.
- **Flagship RCA analyses** — transparent heuristics that show their numbers, never a
  black-box verdict: `gateway_health_rca` (WAN loss/latency/down → cause + action),
  `rule_hit_and_shadow_analysis` (never-hit + shadowed/redundant rules), and
  `blocked_traffic_rca` (top blocked sources/ports → scan / brute-force / probe).
- **Governed writes** — toggle a rule, add/remove an alias entry (reversible,
  undo-recorded from the fetched before-state), flush states, restart a service, and
  the "make it live" commit (`apply_changes` / `reconfigure`) and `reboot` at
  **risk=high** with a dry-run preview. Every write, reversible or not, lands an
  audit row.

## What this tool does, and does not, decide

It delivers firewall operations — reads and writes — accurately and efficiently,
and records every one of them. It does **not** decide whether a write is allowed
to happen. That is the agent's judgement, or the permission of the account you
connect it with: give the OPNsense/pfSense API user a read-only role, and the
writes fail at the server — the place that actually owns the permission.

So there is no read-only switch, no policy file, no approval gate to configure.
The one thing the tool guarantees is that nothing is silent: **every call, over
MCP and over the CLI alike, lands an audit row** in `~/.firewall-aiops/audit.db`,
and reversible writes still capture their before-state and record an inverse
where one exists.

> Each tool declares a `risk_level`, matched to its `[READ]`/`[WRITE]`
> documentation tag, and carried into the audit row as a descriptive tier — so a
> reviewer can see at a glance that a row was a high-risk write. It is a label,
> not a gate.

Running a smaller / local model? See
[agent-guardrails.md](skills/firewall-aiops/references/agent-guardrails.md) — it lists
the guardrails this tool now enforces for you (so you don't spend prompt budget
restating them) and gives a ready-made system prompt for what's left.

## Tool inventory (35 tools)

| Domain | Tools | # | Kind |
|--------|-------|:-:|------|
| **System** | `firmware_status`, `health_status`, `interface_status`, `gateway_status` | 4 | read |
| **Rules** | `list_rules`, `rule_detail`, `rule_stats`, `rule_states` | 4 | read |
| **NAT** | `nat_port_forwards`, `nat_outbound`, `nat_one_to_one` | 3 | read |
| **Aliases** | `list_aliases`, `alias_entries` | 2 | read |
| **VPN** | `wireguard_status`, `openvpn_sessions`, `ipsec_sas` | 3 | read |
| **DHCP** | `dhcp_leases`, `dhcp_static_mappings` | 2 | read |
| **Diagnostics** | `firewall_log`, `states_table`, `top_talkers` | 3 | read |
| **Flagship analyses** | `gateway_health_rca`, `rule_hit_and_shadow_analysis`, `blocked_traffic_rca` | 3 | read |
| **Writes** | `toggle_rule`, `add_alias_entry`, `remove_alias_entry`, `kill_states`, `restart_service` | 5 | write (**med**) |
| **Writes** | `apply_changes`, `reconfigure`, `reboot` | 3 | write (**high**) |
| **Undo** | `undo_list`, `undo_apply` | 2 | read / write |

Reversible writes record an inverse **undo descriptor** built from the real fetched
before-state (`toggle_rule` restores the rule's prior enabled flag; alias add/remove
invert). `apply_changes` / `reconfigure` / `reboot` are high-risk with `dry_run`;
`reboot` is irreversible (audit only).

## Install

```bash
uv tool install firewall-aiops        # or: pipx install firewall-aiops
```

## Quick start

```bash
firewall-aiops init                     # wizard: pick platform (opnsense/pfsense) + store the secret (encrypted)
firewall-aiops doctor                   # verify config, secrets, and connectivity
firewall-aiops overview                 # one-shot: version + gateway/interface health + rule count
firewall-aiops rules list               # list filter rules
firewall-aiops rules toggle <uuid> --disable   # dry-run + double-confirm governed write
firewall-aiops log --action block -n 50 # recent blocked traffic
```

Run the MCP server (stdio) for an agent:

```bash
firewall-aiops mcp                      # or: firewall-aiops-mcp
```

### MCP client config

```json
{
  "mcpServers": {
    "firewall-aiops": {
      "command": "uvx",
      "args": ["--from", "firewall-aiops", "firewall-aiops-mcp"],
      "env": { "FIREWALL_AIOPS_MASTER_PASSWORD": "your-master-password" }
    }
  }
}
```

## Configuration

`~/.firewall-aiops/config.yaml` (non-secret connection details only):

```yaml
targets:
  - name: fw1
    platform: opnsense       # opnsense | pfsense
    host: 192.0.2.1
    port: 443
    username: <opnsense-api-key>   # OPNsense API key (unused for pfSense)
    verify_ssl: false        # false for self-signed lab certs
  - name: edge
    platform: pfsense
    host: 192.0.2.2
    verify_ssl: false
    scheme: http             # https (default) | http — for a GUI behind a TLS-terminating proxy
```

The **secret** — the OPNsense API *secret* (paired with the key for HTTP Basic auth)
or the pfSense **API key** — is stored **encrypted** in `~/.firewall-aiops/secrets.enc`
(Fernet + scrypt-derived key), never plaintext on disk. Set it with
`firewall-aiops secret set <target>` or the `init` wizard. The store is unlocked by a
master password from `FIREWALL_AIOPS_MASTER_PASSWORD` (non-interactive/MCP/CI) or an
interactive prompt (CLI on a TTY). A legacy plaintext env var
`FIREWALL_<TARGET>_SECRET` is honoured as a fallback (migrate with
`firewall-aiops secret migrate`).

## Governance

Every MCP tool is wrapped by `@governed_tool`:

- **Audit** — every call is logged to `~/.firewall-aiops/audit.db` (tool, params with
  secrets redacted, status, duration, risk tier, approver, rationale).
- **Budget / runaway guard** — per-process token/call caps and a repeat-call circuit
  breaker (`FIREWALL_MAX_TOOL_CALLS`, `FIREWALL_RUNAWAY_MAX`, …).
- **Risk-tier labelling** — each tool's declared `risk_level` is recorded on its
  audit row as a descriptive tier (a label, not a gate); there is no read-only
  switch, policy file, or approval gate. `FIREWALL_AUDIT_APPROVED_BY` and
  `FIREWALL_AUDIT_RATIONALE` are optional audit annotations, recorded when set but
  never required.
- **Undo recording** — reversible writes record an inverse descriptor to
  `~/.firewall-aiops/undo.db` from the fetched before-state (recording only; an
  external orchestrator executes it).
- **Sanitisation** — all firewall-returned text is bounded + injection-sanitised
  before it reaches the agent.

## Platform support & verification status

- **Platforms**: OPNsense (REST API) and pfSense (REST API v2, pfSense-pkg-RESTAPI).
- **Test coverage**: behaviour is validated against mocked OPNsense/pfSense JSON
  responses — every module imports, every MCP tool carries the governance marker, the
  RCA heuristics are unit-tested against synthetic telemetry, and reversible writes are
  asserted to record the correct inverse undo descriptor. The concrete REST paths are
  modelled from each project's public API and have not yet been exercised against a
  live firewall. See [docs/VERIFICATION.md](docs/VERIFICATION.md) for the checklist a
  live run must satisfy; `firewall-aiops doctor` (a firmware/version query on both
  platforms) is the fastest connectivity check. Both platforms are free and
  self-hostable (OPNsense is fully open-source; pfSense CE is free), so a home lab is
  the easiest place to run it.
- **Missing a capability?** Open an issue or PR at
  [github.com/AIops-tools/Firewall-AIops](https://github.com/AIops-tools/Firewall-AIops)
  — contributions and feedback welcome.

## License

MIT — see [LICENSE](LICENSE).
