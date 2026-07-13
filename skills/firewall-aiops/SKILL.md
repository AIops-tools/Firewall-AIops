---
name: firewall-aiops
description: >
  Use this skill whenever the user needs to operate an OPNsense or pfSense firewall — a one-shot overview, firmware/health, interfaces and gateways, firewall rules with hit-counts and shadow analysis, NAT (port-forward/outbound/1:1), aliases and their entries, VPN (WireGuard/OpenVPN/IPsec), DHCP leases and static mappings, the firewall log and state table, three flagship RCAs (gateway health, rule hit/shadow, blocked traffic), and governed writes (toggle a rule, add/remove an alias entry, kill states, restart a service, apply/reconfigure to make edits live, reboot).
  Always use this skill for "OPNsense", "pfSense", "firewall rule", "port forward", "NAT", "alias", "WireGuard", "OpenVPN", "IPsec", "DHCP lease", "firewall log", "blocked traffic", "why is my WAN down", "gateway loss/latency", "unused / shadowed rules", "apply firewall changes", "reboot the firewall" when the context is an OPNsense/pfSense firewall.
  Do NOT use when the target is something other than an OPNsense/pfSense firewall (a hypervisor, storage appliance, backup product, container-orchestration cluster, multi-vendor router/switch config, or OT/industrial equipment) — route those to the appropriate other AIops-tools skill. Cloud security groups and vendor firewall appliances are out of scope.
  Preview — governed firewall operations with a built-in governance harness (audit, policy, token budget, undo, risk-tiers). Mock-validated only, not run against a live firewall; both OPNsense and pfSense are free/self-hostable, so a home lab is the easiest live check.
installer:
  kind: uv
  package: firewall-aiops
argument-hint: "[a rule/alias id, an IP, or describe your firewall task]"
allowed-tools:
  - Bash
metadata: {"openclaw":{"requires":{"env":["FIREWALL_AIOPS_CONFIG"],"bins":["firewall-aiops"],"config":["~/.firewall-aiops/config.yaml","~/.firewall-aiops/secrets.enc"]},"optional":{"env":["FIREWALL_AIOPS_MASTER_PASSWORD"]},"primaryEnv":"FIREWALL_AIOPS_CONFIG","homepage":"https://github.com/AIops-tools/Firewall-AIops","emoji":"🛡️","os":["macos","linux"]}}
compatibility: >
  Standalone, self-governed firewall operations across OPNsense (REST API /api/..., API key+secret via HTTP Basic auth) and pfSense (REST API v2 /api/v2/..., API key via X-API-Key header) — preview. Each target in the config names its own platform, and a name-keyed platform registry selects the API shape, so the same tools work on both and one config can span a mixed estate. The governance harness (audit, policy, token/runaway budget, undo, risk-tiers) is bundled in the package — no external skill-family dependency.
  All write operations are audited to a local SQLite DB under ~/.firewall-aiops/ (relocatable via FIREWALL_AIOPS_HOME).
  Credentials: the OPNsense API secret (paired with the API key) or the pfSense API key is stored ENCRYPTED in ~/.firewall-aiops/secrets.enc (Fernet/AES-128 + scrypt-derived key) — never plaintext on disk. Run 'firewall-aiops init' to onboard (it asks for the platform), or 'firewall-aiops secret set <target>' to add one. The store is unlocked by a master password from FIREWALL_AIOPS_MASTER_PASSWORD (non-interactive/MCP/CI) or an interactive prompt (CLI on a TTY). A legacy plaintext env var FIREWALL_<TARGET_NAME_UPPER>_SECRET is still honoured as a fallback with a deprecation warning (migrate with 'firewall-aiops secret migrate'). The secret is presented as HTTP Basic auth (OPNsense) or an X-API-Key header (pfSense) at request time and held only in memory; secrets are never logged or echoed.
  State-changing operations pass through the @governed_tool decorator (pre-check + budget guard + audit + risk-tier gate). The high-risk commits (apply_changes, reconfigure) and reboot are risk=high with dry_run + an approver gate; reboot is irreversible. Reversible writes (toggle_rule, add_alias_entry, remove_alias_entry) capture the real fetched before-state and record an inverse undo descriptor.
  Webhooks: none — no outbound network calls beyond the configured OPNsense / pfSense REST API.
  SSL: verify_ssl defaults to false-friendly for self-signed lab certs; enable for production.
  Transitive dependencies: httpx (HTTP client) and the MCP SDK. No post-install scripts or background services.
  PREVIEW: mock-validated only — not run against a live firewall. Both OPNsense and pfSense are free/self-hostable, so a home lab is the easiest live check.
---

# Firewall AIops (preview)

> **Disclaimer**: Community-maintained open-source project, **not affiliated with, endorsed by, or sponsored by the OPNsense project, Deciso, Netgate, or the pfSense project.** OPNsense, pfSense and Netgate are trademarks of their respective owners. Source at [github.com/AIops-tools/Firewall-AIops](https://github.com/AIops-tools/Firewall-AIops) under the MIT license.

Governed firewall operations — **32 MCP tools** across **OPNsense** (REST `/api/...`)
and **pfSense** (REST v2 `/api/v2/...`), every one wrapped with the bundled
`@governed_tool` harness: a local unified audit log under `~/.firewall-aiops/`,
policy engine, token/runaway budget guard, undo-token recording, and
graduated-autonomy risk tiers. A per-target `platform` field selects the API shape,
so the same tools work on both firewalls and one config can span a mixed estate. The
OPNsense API secret / pfSense API key is stored **encrypted**
(`~/.firewall-aiops/secrets.enc`, Fernet + scrypt) — never plaintext on disk.

> **Standalone**: the governance harness is bundled in the package
> (`firewall_aiops.governance`) — no external skill-family dependency.
> **Preview / mock-only**: not run against a live firewall; both platforms are
> free/self-hostable, so a home lab is the easiest live check.

## What This Skill Does

| Group | Tools | Count | R/W |
|-------|-------|:-----:|:---:|
| **System** | firmware_status, health_status, interface_status, gateway_status | 4 | read |
| **Rules** | list_rules, rule_detail, rule_stats, rule_states | 4 | read |
| **NAT** | nat_port_forwards, nat_outbound, nat_one_to_one | 3 | read |
| **Aliases** | list_aliases, alias_entries | 2 | read |
| **VPN** | wireguard_status, openvpn_sessions, ipsec_sas | 3 | read |
| **DHCP** | dhcp_leases, dhcp_static_mappings | 2 | read |
| **Diagnostics** | firewall_log, states_table, top_talkers | 3 | read |
| **Flagship analyses** | gateway_health_rca, rule_hit_and_shadow_analysis, blocked_traffic_rca | 3 | read |
| **Writes** | toggle_rule, add_alias_entry, remove_alias_entry, kill_states, restart_service | 5 | write (med) |
| **Writes** | apply_changes, reconfigure, reboot | 3 | write (**high**) |

The three flagship analyses are transparent heuristics that report their numbers,
never a black-box verdict: `gateway_health_rca` ranks gateways by loss + latency and
maps each down/degraded one to a cause + action; `rule_hit_and_shadow_analysis` finds
never-hit and shadowed/redundant rules; `blocked_traffic_rca` classifies the noisiest
blocked sources as scan / brute-force / probe.

## Quick Install

```bash
uv tool install firewall-aiops
firewall-aiops init       # wizard: pick platform (opnsense/pfsense) + encrypted secret
firewall-aiops doctor
```

## When to Use This Skill

- Get a one-shot snapshot (`overview` / `firmware_status` / `gateway_status`)
- Investigate a down/degraded WAN (`gateway_health_rca`) → cause + action
- Audit the ruleset (`rule_stats` hit counts, `rule_hit_and_shadow_analysis` for
  never-hit / shadowed / redundant rules)
- Triage hostile traffic (`firewall_log --action block`, `blocked_traffic_rca`,
  `top_talkers`)
- Inspect NAT, aliases, VPN tunnels (WireGuard/OpenVPN/IPsec), and DHCP leases
- Safely toggle a rule or edit an alias (`toggle_rule` / `add_alias_entry` /
  `remove_alias_entry`, reversible + undo-recorded), then **make it live** with
  `apply_changes` (dry-run + approver)

**Do NOT use when** the target is not an OPNsense/pfSense firewall — route hypervisor,
storage, backup, cluster, multi-vendor router/switch config, or OT/industrial work to
the appropriate other AIops-tools skill.

## Related Skills — Skill Routing

| If the user wants… | Use |
|--------------------|-----|
| OPNsense / pfSense firewall ops | **firewall-aiops** (this skill) |
| A non-firewall platform (hypervisor, storage, backup, cluster, network config, OT edge) | the appropriate **other AIops-tools** skill |
| Cloud security groups / vendor firewall appliances | out of scope for this tool |

## Common Workflows

### WAN is down / flaky

1. `gateway_status` → see which gateways report loss/latency/down
2. `gateway_health_rca` → ranked worst-first with a likely cause + recommended action
   (last-mile loss, congestion, latency, or a hard down)

### Clean up the ruleset

1. `rule_stats` → busiest rules by hit count/evaluations
2. `rule_hit_and_shadow_analysis` → enabled rules with 0 evaluations (dead/misordered),
   rules shadowed by an earlier terminating rule, and exact duplicates — each names the
   offending/covering rule uuid

### Triage blocked traffic

1. `firewall_log --action block` (or `firewall_log(action="block")`)
2. `blocked_traffic_rca` → noisiest sources ranked, each classified (port scan, service
   brute-force on 22/3389/…, or generic) with an action; cross-reference `top_talkers`

### Toggle a rule and make it live (reversible)

1. `list_rules` → find the rule uuid/id
2. `toggle_rule <uuid> --disable --dry-run` → preview
3. Re-run without `--dry-run` (double-confirm) — it captures the rule's prior enabled
   state and records an inverse undo descriptor
4. `apply_changes` (risk=high; set `FIREWALL_AUDIT_APPROVED_BY` +
   `FIREWALL_AUDIT_RATIONALE`) to commit staged config

## Governance & Safety

- Every tool is audited to `~/.firewall-aiops/audit.db` (relocatable via
  `FIREWALL_AIOPS_HOME`).
- High-risk ops (`apply_changes`, `reconfigure`, `reboot`) can require a named
  approver: set `FIREWALL_AUDIT_APPROVED_BY` and `FIREWALL_AUDIT_RATIONALE`.
- Writes support `--dry-run` and double confirmation at the CLI. `reboot` is
  irreversible (audit only).
- Reversible writes capture the real fetched before-state and record an inverse
  descriptor (toggle→toggle-back, add-alias↔remove-alias).

## References

- `references/capabilities.md` — full tool + platform + API-path reference
- `references/cli-reference.md` — CLI command reference
- `references/setup-guide.md` — onboarding, credentials, and connectivity
