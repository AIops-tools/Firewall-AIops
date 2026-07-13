# firewall-aiops capabilities

> Preview / mock-only — not run against a live firewall. **32 MCP tools** (24 read,
> 8 write) across OPNsense (REST `/api/...`, API key+secret via HTTP Basic) and
> pfSense (REST v2 `/api/v2/...`, API key via `X-API-Key`). The concrete REST paths
> below are modelled from each project's public API and need live verification.

A per-target `platform` field (`opnsense` / `pfsense`) selects the API shape; the same
tool name resolves to the right path on each firewall via the platform registry.

## System (read)

| Tool | OPNsense path | pfSense path | Returns |
|------|---------------|--------------|---------|
| `firmware_status` | `/api/core/firmware/status` | `/api/v2/system/version` | version, product, updates available |
| `health_status` | `/api/diagnostics/system/systemInformation` | `/api/v2/status/system` | hostname, uptime, CPU %, mem %, load |
| `interface_status` | `/api/diagnostics/interface/getInterfaceNames` | `/api/v2/status/interfaces` | interfaces with link status + address (down first) |
| `gateway_status` | `/api/routes/gateway/status` | `/api/v2/status/gateways` | gateways with status, loss %, RTT |

## Rules (read)

| Tool | OPNsense path | pfSense path | Returns |
|------|---------------|--------------|---------|
| `list_rules` | `/api/firewall/filter/searchRule` | `/api/v2/firewall/rules` | filter rules normalized (uuid, enabled, action, if, src/dst, evaluations) |
| `rule_detail` | `/api/firewall/filter/getRule/{uuid}` | `/api/v2/firewall/rule?id=` | one rule's full detail |
| `rule_stats` | `/api/diagnostics/firewall/pfStatistics` | `/api/v2/firewall/rules` | per-rule hit counts / evaluations, busiest first |
| `rule_states` | `/api/diagnostics/firewall/queryStates` | `/api/v2/diagnostics/states` | active state-table entries tied to rules |

## NAT (read)

| Tool | Returns |
|------|---------|
| `nat_port_forwards` | inbound port-forward (DNAT) rules |
| `nat_outbound` | outbound (source) NAT mappings |
| `nat_one_to_one` | 1:1 NAT mappings (external ↔ internal) |

## Aliases (read)

| Tool | Returns |
|------|---------|
| `list_aliases` | all aliases (name, type, description, member count) |
| `alias_entries` | the member entries (hosts/networks/ports) of one alias |

## VPN (read)

| Tool | Returns |
|------|---------|
| `wireguard_status` | WireGuard peers with connected state, last handshake, transfer |
| `openvpn_sessions` | OpenVPN sessions / connected clients (name, address, bytes) |
| `ipsec_sas` | IPsec security associations (phase-1/phase-2) with state |

## DHCP (read)

| Tool | Returns |
|------|---------|
| `dhcp_leases` | active DHCP leases (IP, MAC, hostname, state); `online_only` filter |
| `dhcp_static_mappings` | DHCP static (reserved) mappings (MAC ↔ IP) |

## Diagnostics (read)

| Tool | Returns |
|------|---------|
| `firewall_log` | recent firewall-log entries, optional `action` filter (pass/block/…) |
| `states_table` | active pf state-table entries |
| `top_talkers` | busiest source hosts, aggregated from the state table by bytes |

## Flagship analyses (read, pure heuristics)

| Tool | What it does |
|------|--------------|
| `gateway_health_rca` | rank gateways by loss (x10) + latency; flag down (status down / 100% loss) and degraded (over threshold); map each to a cause + action. Pass `gateways=` for pure analysis or a target to pull live |
| `rule_hit_and_shadow_analysis` | never-hit enabled rules (0 evaluations), rules shadowed by an earlier terminating rule, and exact duplicates; each finding names the offending/covering rule uuid |
| `blocked_traffic_rca` | aggregate blocked log rows by source; classify as port scan (≥10 distinct ports), service brute-force/probe (busy sensitive port 22/3389/…), or generic; with an action |

## Writes (governed)

| Tool | Risk | Path(s) | Notes |
|------|------|---------|-------|
| `toggle_rule` | **med** | OPNsense `toggleRule/{uuid}/{0\|1}`; pfSense PATCH `firewall/rule` | reads the rule first; records undo (restore prior enabled). Staged — run `apply_changes` |
| `add_alias_entry` | **med** | OPNsense `alias_util/add/{name}`; pfSense `firewall/alias` | captures prior entries; undo removes the added entry |
| `remove_alias_entry` | **med** | OPNsense `alias_util/delete/{name}`; pfSense `firewall/alias` | captures prior entries; undo adds it back |
| `kill_states` | **med** | `diagnostics/…/killStates` / `diagnostics/states` | flush pf states (optionally one source IP) |
| `restart_service` | **med** | `service/restart/{service}` | restart a firewall service |
| `apply_changes` | **HIGH** | `filter/apply` / `firewall/apply` | commit staged config — makes edits live; `dry_run` + approver |
| `reconfigure` | **HIGH** | `filter/savepoint` / `firewall/apply` | reload/commit a subsystem; `dry_run` + approver |
| `reboot` | **HIGH** | `core/system/reboot` / `diagnostics/reboot` | IRREVERSIBLE — audit only, no undo; `dry_run` + approver |

## Out of scope (v0.1)

- Creating/deleting rules, aliases, or NAT entries from scratch (only toggle + alias
  entry add/remove today).
- Cloud security groups and vendor firewall appliances.
- **Missing something? Open an issue or PR** — contributions welcome.
