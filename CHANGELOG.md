# Changelog

## v0.2.0 — 2026-07-13

Security-hardening release from a line-wide code review.

### Changed (behavior)
- **Secure by default**: with no `rules.yaml`, high/critical operations now require a
  named approver (`FIREWALL_AUDIT_APPROVED_BY`). A fresh install no longer allows
  destructive writes unattended; `init` seeds a starter `rules.yaml` you can edit,
  and an operator-authored rules file is honoured as-is.
- `__version__` is now single-sourced from package metadata (the previous release
  self-reported a stale version string).
- Sanitize docs no longer overstate scope: it strips control/format characters and
  truncates; semantic prompt-injection resistance must come from the consuming agent.

### Fixed
- Every platform URL template percent-encodes its values centrally in `Platform.path()` (path-traversal hardening).
- `init` TLS verification prompt now defaults to ON.
- Governance docstrings no longer reference a sibling tool.

### Tests
- Governance persistence is now tested against REAL `audit.db`/`undo.db` files
  (write → audit row + inverse undo row with captured prior state).
- The CLI confirmed-write path (dry-run / double-confirm / governed execution) is
  covered end-to-end.
- `pytest-cov` added to the dev dependencies.

## v0.1.1

- Fix: `FIREWALL_AIOPS_HOME` now also relocates `config.yaml` (was hardcoded to `~/.firewall-aiops`).
- Fix: **CLI writes are now audited + undo-recorded** via the governance path — previously only the MCP tools recorded audit/undo; CLI `manage`/`remediate`/etc. writes now go through the same `@governed_tool` layer (they keep their dry-run + double-confirm). CLI write output is now the governed JSON result. No API/tool changes.


All notable changes to firewall-aiops are documented here. This project adheres
to [Semantic Versioning](https://semver.org/).

## [0.1.0] — preview

Initial preview release: governed AI-ops for **OPNsense** and **pfSense**
firewalls, with a bundled governance harness. One MCP server spans both platforms
via a per-target `platform` field; the same tools work on either firewall.
**Mock-validated only — not yet verified against a live firewall.**

### Added

- **32 MCP tools** (24 read, 8 write), every one wrapped with the bundled
  `@governed_tool` harness (audit, policy, token/runaway budget, undo,
  risk-tiers):
  - **System (read)** — `firmware_status`, `health_status`, `interface_status`,
    `gateway_status`.
  - **Rules (read)** — `list_rules`, `rule_detail`, `rule_stats` (hit
    counts/evaluations), `rule_states`.
  - **NAT (read)** — `nat_port_forwards`, `nat_outbound`, `nat_one_to_one`.
  - **Aliases (read)** — `list_aliases`, `alias_entries`.
  - **VPN (read)** — `wireguard_status`, `openvpn_sessions`, `ipsec_sas`.
  - **DHCP (read)** — `dhcp_leases`, `dhcp_static_mappings`.
  - **Diagnostics (read)** — `firewall_log`, `states_table`, `top_talkers`.
  - **Flagship analyses (read)** — `gateway_health_rca`,
    `rule_hit_and_shadow_analysis`, `blocked_traffic_rca` — transparent
    heuristics that report their numbers, not a black-box verdict.
  - **Writes** — `toggle_rule` (med, undo restores prior enabled),
    `add_alias_entry` / `remove_alias_entry` (med, capture prior entries, invert),
    `kill_states` (med), `restart_service` (med), `apply_changes` (**high**),
    `reconfigure` (**high**), `reboot` (**high**, irreversible/audit-only). Every
    write takes a `dry_run` preview; high-risk writes require an approver.
- **Platform abstraction** — a name-keyed platform registry maps each target's
  `platform` (`opnsense` / `pfsense`) to its auth style + REST resource paths, so
  the ops/CLI/MCP layers stay platform-neutral. OPNsense uses HTTP Basic
  (key+secret); pfSense uses an `X-API-Key` header.
- **Encrypted secret store** — the OPNsense API secret or pfSense API key is
  stored encrypted in `~/.firewall-aiops/secrets.enc` (Fernet + scrypt); never
  plaintext on disk. Legacy `FIREWALL_<TARGET>_SECRET` env var honoured as a
  fallback.
- **CLI** (`firewall-aiops`) — `init` platform-picking wizard, `overview`,
  `rules list/show/toggle` (dry-run + double-confirm), `log`, `secret`
  management, and a `doctor` connectivity check (firmware/version query on both
  platforms).

### Known limitations

- Preview / mock-only: OPNsense and pfSense responses are mocked and need live
  verification against a real firewall; the modelled REST paths especially.
- **Missing a capability? Open an issue or PR** — contributions welcome.
