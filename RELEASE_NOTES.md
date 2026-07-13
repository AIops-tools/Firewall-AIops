# Firewall AIops v0.1.0 — preview

Governed AI-ops for **OPNsense** and **pfSense** firewalls for AI agents, with a
built-in governance harness (audit, policy, token/runaway budget, undo-token
recording, graduated risk tiers) and an encrypted credential store. Standalone —
no external skill-family dependency. One MCP server spans both platforms: a
per-target `platform` field selects the API shape, and the same 32 tools work on
OPNsense (REST `/api/...`, key+secret via HTTP Basic) and pfSense (REST v2
`/api/v2/...`, API key via `X-API-Key` header).

> **Not affiliated with, endorsed by, or sponsored by the OPNsense project,
> Deciso, Netgate, or the pfSense project.** OPNsense, pfSense and Netgate are
> trademarks of their respective owners.

> **Preview / mock-only.** All behaviour is validated against mocked
> OPNsense/pfSense JSON responses; it has **not** been run against a live
> firewall. The concrete REST paths are modelled from each project's public API
> and need live verification. Both platforms are free/self-hostable, so a home
> lab is the easiest live check — `firewall-aiops doctor` is the fastest.

## Highlights

- **32 MCP tools** (24 read, 8 write), every one wrapped with `@governed_tool`:
  - **System** — `firmware_status`, `health_status`, `interface_status`,
    `gateway_status`.
  - **Rules** — `list_rules`, `rule_detail`, `rule_stats` (hit counts),
    `rule_states`.
  - **NAT** — `nat_port_forwards`, `nat_outbound`, `nat_one_to_one`.
  - **Aliases** — `list_aliases`, `alias_entries`.
  - **VPN** — `wireguard_status`, `openvpn_sessions`, `ipsec_sas`.
  - **DHCP** — `dhcp_leases`, `dhcp_static_mappings`.
  - **Diagnostics** — `firewall_log`, `states_table`, `top_talkers`.
  - **Writes** — `toggle_rule`, `add_alias_entry`, `remove_alias_entry`,
    `kill_states`, `restart_service` (med); `apply_changes`, `reconfigure`,
    `reboot` (**high**).
- **Flagship analyses** (transparent heuristics that show their numbers):
  - `gateway_health_rca` — rank gateways by loss + latency, flag down/degraded,
    map each to a likely cause + recommended action.
  - `rule_hit_and_shadow_analysis` — never-hit (0 evaluations) enabled rules,
    plus rules shadowed by an earlier terminating rule or duplicating one.
  - `blocked_traffic_rca` — noisiest blocked sources/ports classified as scan,
    service brute-force/probe, or generic — with an action.
- **Governed writes** — reversible writes capture the **real fetched
  before-state** and record an undo descriptor (`toggle_rule` restores the prior
  enabled flag; alias add/remove invert). High-risk commits (`apply_changes` /
  `reconfigure` / `reboot`) take a `dry_run` preview and require an approver;
  `reboot` is irreversible.
- **Encrypted secret store** — the OPNsense API secret or pfSense API key lives
  encrypted in `~/.firewall-aiops/secrets.enc` (Fernet + scrypt), never plaintext;
  legacy `FIREWALL_<TARGET>_SECRET` env fallback.
- **CLI** with an `init` platform-picking wizard, `doctor`, `overview`,
  `rules list/show/toggle`, `log`, and `secret` management.

## Install

```bash
uv tool install firewall-aiops
firewall-aiops init       # pick platform (opnsense/pfsense) + store the secret
firewall-aiops doctor
```

## Caveats

- Preview / mock-only: OPNsense and pfSense responses are mocked and need live
  verification against a real firewall (the modelled REST paths especially).
- **Missing a capability? Open an issue or PR** — contributions and feedback
  welcome.
