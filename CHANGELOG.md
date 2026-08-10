# Changelog

## v0.9.0 — 2026-08-10

### Fixed
- **An undetermined outcome no longer exits as a plain failure.** A write whose response was lost carries *both* `error` and `outcomeUnknown`, and the harness deliberately judges unknown first when writing the audit row — the change may have taken effect, so a blind retry could apply it twice. The CLI guard judged `error` first, so the audit said "may have taken effect" while the exit status told a script it had not happened. The two layers now agree (exit 2, not 1), and a test pins the ordering so it cannot silently flip back.
- **The CLI reported a refused or failed governed write as a success.** 1 write call site (`undo apply`) printed the governed twin's payload and exited **0** whatever it said — and `@tool_errors` flattens every refusal, guard rejection and upstream failure into `{"error": ...}` rather than raising, so nothing downstream of a `&&` chain or a CI step could tell a blocked write from a landed one. The dry-run path already exited non-zero, which made the asymmetry worse: the preview was stricter than the write it previews. Results now route through a `checked()` helper — exit 1 on an error payload, exit 2 on an undetermined outcome, unchanged on success. This defect class had been fixed repo-by-repo several times and kept coming back; an audit across the whole line found it live in **18 of the 24 tools at once (87 call sites)**, so each tool now carries an invariant test that fails if any future CLI command prints a governed result without checking it.

## v0.8.0 — 2026-08-03

### Fixed
- **`undo apply` replays against the target the original write ran on.** It dispatched the inverse against whatever target the *caller* named — in practice the config's first entry — while the write's own target sat unused in the undo record. On a multi-target config the inverse therefore ran against the wrong host; it only looks harmless because the resource usually is not there, but two hosts holding the same name and the inverse **succeeds on the wrong one, silently**. An explicitly named target still wins. Line-wide: all 24 copies had the identical defect. Caught live in container-host-aiops, where a stop recorded against a Podman target replayed against a Portainer one.

## v0.7.0 — 2026-08-02

### Changed (BREAKING)
- **Requires MCP SDK 2.0** (`mcp[cli]>=2.0,<3.0`). `mcp.server.fastmcp` no longer exists in 2.0; the server is now built with `MCPServer` and reports its package version in the stdio handshake.

### Fixed
- **`undo apply` works from the CLI.** Every write tool is imported lazily inside its own CLI command, so a CLI-driven undo ran in a process where the inverse tool was never registered and failed with "inverse tool is not registered" — for every write tool. Only the MCP entry point, which imports the whole server, worked. Found while live-verifying against a real cluster.
- **An undetermined outcome is audited `unknown`, not `ok`.** The harness only classified a result as undetermined when the payload *also* carried an `error` key, so a write that looked successful but had not been confirmed was recorded as a success.
- **Every read failed against a real OPNsense.** A global `Content-Type: application/json` header made OPNsense json-decode the request body of bodyless GETs, so each one returned `400 Invalid JSON syntax`. Live-verified against OPNsense 26.7. Only `Accept` is sent by default now; httpx adds the content type per request for calls that actually carry a body.
- The system version was read from the wrong level and came back null on every appliance; it now reads the nested `product` object.
- Rule evaluation, packet and byte counters render as integers rather than floats.
- **`as_int` no longer round-trips integers through float64** (see the line-wide sweep note in the sibling tools); the bool guard precedes the int short-circuit because `bool` subclasses `int`.


## v0.6.0 — 2026-07-21

### Changed (BREAKING)
- **Removed the authorization layer** — read-only mode, the approver gate, and rules.yaml deny are gone. The skill no longer decides read vs write; that is the agent's judgement or the connecting account's permissions. `<PREFIX>_READ_ONLY` now has no effect (a startup warning is logged); `<PREFIX>_AUDIT_APPROVED_BY`/`_RATIONALE` are optional audit annotations.
- The retained guarantee is **unbypassable audit over MCP and CLI alike** — no unaudited entry point. Harness = audit + runaway safety guard + undo + sanitize; `risk_level` is a descriptive audit label, not a gate.

See RELEASE_NOTES.md for tool-specific changes.


## v0.5.0 — 2026-07-20

### Fixed
- **`restart_service` refuses the service that serves the API**, and `apply_changes` / `reconfigure filter` refuse a staged change that would block management access to the configured host and port.
- **New `pending_changes` read, and the apply dry-run now shows the staged set.** `apply_changes` was a blind commit: its preview named only the platform, and nothing in the package could read what was pending — including edits staged outside the tool..
- **New `scheme:`** (default `https`).
- Harness: a write whose response is lost is audited `status=unknown`, not `error` — it may have taken effect. Undo tokens gain `effectVerified` (undo.db migrated in place).
- Harness: a dry-run no longer records an undo token, and no longer requires a named approver. Guards now run on the preview path.
- Truncated strings end in an ellipsis instead of being cut silently; error messages are capped at 800 chars, not 300.

See RELEASE_NOTES.md for the full detail.

## v0.3.0 — 2026-07-17

### Added
- **Undo executor**: `undo list` / `undo apply <id>` (CLI + MCP) — apply a recorded replayable inverse; the dispatched inverse is re-gated by its own risk tier; single-use, dry-run, double-confirm, both wrapper + inverse audited.

## v0.2.1 — 2026-07-16

### Fixed
- **`secrets.enc` now follows `FIREWALL_AIOPS_HOME`** (secretstore hardcoded the real
  home directory; config/audit/undo already relocated — found in live verification).
- **Audit fidelity**: failures sanitized into `{"error": ...}` results by the MCP error
  layer are now audited as `status=error` (they previously read as `ok`, hiding failed
  attempts from exception reports), and no undo is recorded for a call that failed.

### Tests
- `doctor` and the `init` wizard are now fully covered (previously ~10–20%); plus a
  regression test for the sanitized-failure audit status.

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
