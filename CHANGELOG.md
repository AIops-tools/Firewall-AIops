# Changelog

## v0.12.2 — 2026-09-12

### Changed
- **The ClawHub bundle plugin moved from `@aiops-tools/firewall-aiops` to
  `@zw008/firewall-aiops`**, matching the publisher the skill has always been under.
  ClawHub cannot move a package between scopes — the scope is the publisher
  identity — so this is a republish under the new name; the old name is
  withdrawn. Install with:
  `openclaw plugins install clawhub:@zw008/firewall-aiops`. Nothing about the Python
  package, the CLI, the MCP server or the Claude Code plugin changes.

## v0.12.1 — 2026-09-12

### Added
- **The OpenClaw install path is documented.** The ClawHub bundle channel went
  live but neither the README nor this skill said how to install from it:
  `openclaw plugins install clawhub:@aiops-tools/firewall-aiops`. States the `uvx`
  prerequisite (without it the skill installs but reports `Visible to model:
  no`) and that the MCP server is pinned to this exact release.
- **Where an exported master password lives** is now stated next to the
  instruction to export it: readable by every process the shell starts, and
  kept in shell history.

## v0.12.0 — 2026-09-12

### Fixed
- **The flagship rule analysis recommended deleting every working rule on any
  pfSense.** `unusedRules` flags an enabled rule whose `evaluations` is 0, and
  the rule normaliser defaulted an *absent* counter to 0 — but pfSense's REST
  API exposes no per-rule hit counter anywhere (checked against the appliance's
  own OpenAPI schema: 212 paths, none of them rule statistics). Live on pfSense
  CE 2.7.2 that meant 2 of 2 rules reported as "never hit — either dead or
  misordered". `evaluations` is now `null` when the platform reports none, the
  analysis skips those rules and counts them in `hitCountersUnavailable`, and
  `rule_stats` says `hitCountersAvailable: false` instead of sorting an all-null
  column and presenting the arbitrary order as "busiest first". A measured zero
  is still reported, so the check is not blunted where it can actually run.
- **A rule's interface came back as the literal string `"['lan']"`, and filtering
  by interface matched nothing.** pfSense reports `interface` as a list;
  stringifying it leaked a Python repr into the payload and made
  `list_rules(interface="lan")` return an empty list — which reads as "no rules
  on that interface" rather than "the filter is broken". A rule can also sit on
  several interfaces at once (floating rules), so the filter matches membership
  rather than the joined string: comparing `"wan,lan"` to `"wan"` would have kept
  silently dropping exactly those rules.
- **`sequence` was always null on pfSense**, so rule order had to be inferred
  from list position. pfSense has no `sequence` field because a rule's `id` *is*
  its position in the evaluation order; that is now stated in the payload.
- **The skill was invisible to the model in OpenClaw.** Its metadata
  declared `requires.config` (OpenClaw reads that as config *keys*, not file
  paths, so it can never be satisfied), `requires.env` and `requires.bins`
  naming our own CLI — which a plugin user never has on PATH — plus a
  `primaryEnv` that turned a config path into an API-key prompt. Measured on
  OpenClaw 2026.6.35: `Visible to model: no`. It now requires
  `anyBins: [firewall-aiops, uvx]` — either one suffices — with every variable kept
  in `optional.env` (still declared, no longer a load gate), which the same
  command reports as `Visible to model: yes`.

### Added
- `pending_changes` now carries `applyStatus` — the appliance's own answer to
  "is an apply outstanding?", read from pfSense's `GET /api/v2/firewall/apply`
  ("Read pending firewall change status", returning `applied` /
  `pending_subsystems`). It is subsystem-level rather than per-rule, so it
  supplements the staged rule listing rather than replacing it; a failure to
  read it is reported as an error, never as "nothing pending". It resolves
  through its own `apply_status` registry key, mapped only where a status read
  exists — OPNsense maps `apply` to an **action** endpoint, and `pending_changes`
  is a read that `apply_changes`' own dry-run calls, so issuing a GET there
  risked committing the config from inside a preview. On a platform without the
  key, no request is made at all.
- **Installable from ClawHub as an OpenClaw bundle plugin** (`@aiops-tools/firewall-aiops`): one install delivers the skill *and* its MCP
  server, pinned to this exact release. `clawhub.ai/plugins`.

## v0.10.0 — 2026-08-29

### Fixed
- **Eleven of the 31 pfSense endpoints could never have worked, and five of them
  are in no published pfSense API schema at all.** The first live run against a
  real pfSense (CE 2.7.2 + pfSense-pkg-RESTAPI 2.4_3) found that the whole VPN
  status surface (`wireguard_status`, `openvpn_sessions`, `ipsec_sas`), the whole
  state table (`states_table`, `top_talkers`, `rule_states` **and the
  `kill_states` write**), `restart_service`, `dhcp_static_mappings` and
  alias-lookup-by-name answered 404 or 400 on every call. The reads were the more
  dangerous half: each one catches its own failure and reports
  `{"error": ...}`, which the docstrings define as "that subsystem is not
  installed" — so a URL that does not exist was indistinguishable from a feature
  the operator had not enabled. The real endpoints (`/api/v2/firewall/states`,
  `/api/v2/status/openvpn/clients`, `/api/v2/status/ipsec/sas`,
  `/api/v2/status/services`, and the plural `/api/v2/firewall/aliases?name=`) are
  now used and were confirmed live, with three of the previously working paths as
  a control so a 404 means "absent", not "broken probe". Two structural tests fail
  if any of the five fictional paths is ever reached for again. OPNsense is
  unaffected.
- **Both pfSense alias writes were rejected by every real firewall.** Adding a
  member POSTed the alias again — a *create*, answered with
  `FIELD_MUST_BE_UNIQUE` — and removing one sent DELETE with a name in the body,
  answered with `MODEL_REQUIRES_ID`. pfSense has no add/remove-member verb: an
  alias is one object whose `address` **is** the list, so a member change is a
  PATCH of the whole list against the object's numeric id. The list written back
  is read from the alias record itself, never from the best-effort prior-state
  snapshot — that snapshot returns `[]` when its read fails, and writing it back
  would delete every other member of the alias.
- **`restart_service` on pfSense addressed the service by name in the path.**
  pfSense wants the service's numeric id in the body; a name-only request is
  refused with `MODEL_REQUIRES_ID`. The id is now resolved first, and an unknown
  service name fails loudly instead of issuing a request that cannot succeed.
- **A lost `kill_states` response is recorded as undetermined, not as a failure.**
  Flushing the state table drops the state entry for the very connection issuing
  the flush, so the reply has nowhere to go — that is the expected outcome, and
  the audit row previously called it `error` for a change that had almost
  certainly happened. It now records `unknown` with `outcomeUnknown: true`. A
  firewall that answers and refuses is still a real failure.
- **pfSense refuses an unfiltered mass state delete**
  (`MODEL_DELETE_MANY_REQUIRES_QUERY_PARAMS`), so "flush everything" is now spelled
  as a filter that matches everything (`?id__gte=0`). A made-up parameter such as
  `?all=true` satisfies that check and then matches nothing, answering 200 with an
  empty list — success reported for a flush that never happened.
- **State-table byte and packet counters rendered as floats, and packets were
  always zero.** pfSense names them `bytes_total` / `packets_total`; the packet key
  was not among those read, so every connection looked idle. Both are `as_int` now.
- **A 404 no longer claims the id must be stale.** For a collection URL with no id
  in it, the only possible cause is that the build does not serve that endpoint —
  which is exactly the case this release fixes, and the old message pointed the
  reader at the wrong thing.

### Added
- **Installable as a Claude Code plugin.** `.claude-plugin/plugin.json` plus a
  root `.mcp.json` make this repo a plugin, so `/plugin install firewall-aiops@aiops-tools`
  delivers the skill and registers the MCP server in one step. The server is
  pinned to the exact package version the manifest declares, so an audit row
  stays traceable to the code that produced it. Nothing about the tool itself
  changed — the CLI and the standalone MCP server work exactly as before.

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
