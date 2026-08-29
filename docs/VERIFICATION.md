# Live verification — OPNsense / pfSense

## ✅ OPNsense half — live-verified against real OPNsense 26.7 (2026-08-01)

Verified end-to-end against a real OPNsense 26.7 firewall (pre-installed serial
image in a KVM lab), driven through the real governed CLI + API key/secret
(HTTP Basic) path. **Three real bugs the mock suite could not see — all fixed +
regression-tested:**

1. **Every read failed with `400 "Invalid JSON syntax"`.** The client set a global
   `Content-Type: application/json` on *all* requests; OPNsense json-decodes the
   request body whenever that header is present, so a bodyless GET (every read)
   was rejected. Fixed: drop the global header — httpx adds it per-request only
   when a call passes `json=` (the POST/PUT writes). Reproduced exactly with curl.
2. **`version` came back `null` on every real OPNsense.** The version is nested
   under `product` (`product_version` / `product_id` / `CORE_VERSION`), but the
   code read the top level. Fixed by merging the `product` sub-object (pfSense's
   flat shape still works).
3. **Rule `evaluations` / `packets` / `bytes` rendered as float** (`0.0`) — bug
   class #2. Added `as_int` and applied it to the count fields.

Live loop that passed after the fixes: `doctor` (firmware/version query), `overview`
(version 26.7, 2 interfaces up, 25 rules), `rules list` (matched the API), and a full
**write → audit → undo → verified restore**: `rules toggle <uuid> --disable` → server
reports `enabled=0` → `undo apply` → server `enabled=1`, `effectVerified: true`, both
CLI write and undo audited.

> **API-key setup (no GUI needed):** OPNsense stores the apikey secret as
> `key|crypt($secret,'$6$')` and verifies with `password_verify`; its built-in
> `OPNsense\Auth\API::createKey('root')` mints a correct pair and returns the
> plaintext — run it from an SSH shell with a 6-line PHP script. Put the VM on a
> libvirt net matching its default LAN (192.168.1.0/24, host as .254) so the KVM
> host reaches 192.168.1.1 directly.

Not covered on the OPNsense side: alias/NAT/gateway *write* paths beyond the rule
toggle. The **pfSense** half is now live-verified too — see the next section.

---

## ✅ pfSense half — live-verified against pfSense CE 2.7.2 (2026-08-29)

Verified against a real pfSense CE 2.7.2 with **pfSense-pkg-RESTAPI 2.4_3**, installed
headless in a KVM lab from the *memstick-serial* image, driven through the real
`X-API-Key` path. **Eleven of the 31 modeled endpoints could never have worked** —
all fixed and regression-tested. This was the single largest defect count of any
platform half in this product line.

### How the sweep was made trustworthy

All 31 registry paths were probed against the live box **with a positive control**:
three modeled paths that do answer `200` were probed in the same run, so a `404`
means the endpoint is absent rather than the probe being broken. Every candidate
absence was then checked against the package's own OpenAPI schema at **two**
versions (2.4.3 and 2.10.2) to separate *fictional* from *version-gated* — a
distinction the fix depends on.

| result | count |
|---|---|
| answered `200` | 18 |
| `404` — path in **no** published schema (fictional) | 8 keys / 5 paths |
| `404` — exists only in newer pfSense-pkg-RESTAPI | 1 |
| `400` on every call — singular endpoint filtered by name | 2 |
| `405` on a GET probe of a POST-only path (correct) | 1 |

### The fictional five

`/api/v2/diagnostics/states` (behind `states_table`, `top_talkers`, `rule_states`
and the **`kill_states` write**), `/api/v2/status/wireguard`,
`/api/v2/status/openvpn`, `/api/v2/status/ipsec`, and
`/api/v2/services/{service}/restart`.

**Why nobody noticed:** every VPN/diagnostic read catches its own failure and
returns `{"error": ...}`, which those functions' docstrings define as "that VPN
subsystem is not installed/enabled". A URL that does not exist therefore looked
exactly like a feature the operator had chosen not to turn on. That is bug class
\#3 (a failure disguised as health) wearing bug class \#9 (a fabricated endpoint).

### What was verified after the fix

- **Reads**, all `200` with real data: `states_table` / `top_talkers`
  (`/api/v2/firewall/states`), `openvpn_sessions`
  (`/api/v2/status/openvpn/clients`), `ipsec_sas` (`/api/v2/status/ipsec/sas`),
  `alias_entries` (plural `/api/v2/firewall/aliases?name=`).
- **Full governed write loop**, twice: `add_alias_entry` → the alias on the
  firewall carries the new member (checked through the API, not the tool's own
  return) → audit row `ok` / tier `confirm` → `undo_apply` → the member is gone
  from the firewall again, `effectVerified: true`. A second consecutive add
  confirmed earlier members survive.
- **`restart_service`**: resolves the numeric id via
  `/api/v2/status/services?name=`, then `POST /api/v2/status/service` with
  `{id, action}`. The self-lockout guard still refuses `nginx`, on the dry run too.
- **`kill_states`**: the DELETE times out every time because it drops this
  connection's own state entry — the audit row is now `unknown`, not `error`.
  That "flush everything" needs a match-everything filter was established with a
  **negative control**: a filter matching nothing answers `200` with an empty list
  and the connection survives; `?id__gte=0` kills the connection mid-request.
- **Counters**: `bytes` / `packets` are ints carrying real values (`packets` used
  to be `0.0` on every row because pfSense calls the field `packets_total`).

### Still not verified on pfSense

`wireguard_status` and `dhcp_static_mappings` need a newer pfSense-pkg-RESTAPI
than 2.4_3 (2.4_3 is the last build supporting CE 2.7.2, and CE 2.8.x is not on the
public mirror). Both now fail with a 404 that names the path rather than implying
the subsystem is absent. NAT, gateway and rule-toggle *writes* on pfSense, and
`pending_changes` staged-config semantics, remain mock-only.

> **Lab recipe.** The CE images are on `https://atxfiles.netgate.com/mirror/downloads/`
> and download **anonymously** — no Netgate account, contrary to what this repo
> previously assumed. Use the *memstick-serial* image with
> `qemu -serial tcp:...,server,wait` (**`wait`**, not `nowait`: with `nowait` the VM
> boots immediately and every byte before your client connects is lost). Do not send
> arrow keys to `bsdinstall` over serial — a bare `ESC` reads as Cancel and the
> trailing `[B` leaks into the next prompt; use the letter hotkeys (`a` cycles the
> Auto entries, `f` fires Finish). Install the API package with
> `pkg-static -C /dev/null add <the v2.4.3 pfSense-2.7.2-pkg-RESTAPI.pkg>`, mint a key
> with `POST /api/v2/auth/key` under basic auth, then **`PATCH
> /api/v2/system/restapi/settings` with `auth_methods:["KeyAuth","BasicAuth"]`** —
> without that, every `X-API-Key` request is `401`.

### What the mock suite guarantees on top of that

- Every module imports; the CLI builds; **all 35 MCP tools** carry the
  `@governed_tool` harness marker (`tests/test_smoke.py`, which also asserts the tool
  count and that `__version__` matches `pyproject.toml`).
- The three flagship analyses (`gateway_health_rca`, `rule_hit_and_shadow_analysis`,
  `blocked_traffic_rca`) are unit-tested against synthetic telemetry: thresholds fire
  where they should, findings cite the measured number, and no crash on missing or
  partial fields.
- The **platform registry** resolves the same tool name to the correct OPNsense
  (`/api/...`, HTTP Basic) and pfSense (`/api/v2/...`, `X-API-Key`) request shape.
- Reversible writes (`toggle_rule`, `add_alias_entry`, `remove_alias_entry`) record the
  correct **inverse** undo descriptor, built from a fetched before-state rather than a
  guess, against a mocked connection.
- Governance persistence is tested against a real on-disk SQLite audit DB: calls land
  as rows, failures are recorded `status=error` and record no undo, and a high-risk
  write with no approver runs and is audited (the risk tier is a descriptive label,
  not a gate).
- The **self-lockout guards** are unit-tested for exactness AND fail-open
  (`tests/test_lockout_guards.py`): `restart_service` refuses each platform's
  API-serving daemon and its aliases while ordinary services still restart;
  `apply_changes` / `reconfigure filter` refuse a staged rule that literally
  matches the management host+port, warn-and-proceed on alias / `any` /
  interface-group destinations, and treat an unreadable rule set as UNKNOWN
  rather than clean.

What it does **not** guarantee: that the concrete REST paths, field names, and
staged-vs-applied config semantics match a real OPNsense or pfSense build. In
particular, `pending_changes` reads the *staged rule state* from each platform's
rules API rather than a per-rule dirty flag (neither platform exposes one over
REST) — a live run must confirm that an edit staged in the web GUI really does
show up there before `apply_changes` commits it. The lockout guard is only as
good as that read. Those paths
are modelled from each project's public API documentation and are the **largest
verification debt in this repo**.

## Prerequisites for a live run

Both platforms are free and self-hostable, so a VM is enough:

- **OPNsense** — install the ISO in a VM; create an API key/secret pair under
  *System → Access → Users → API keys*. Give the API user the least privilege that
  still covers the rules/alias/diagnostics endpoints you intend to exercise.
- **pfSense CE** — install the ISO, then add the **pfSense-pkg-RESTAPI** package
  (REST API v2 is not built in); create an API key for a dedicated user.

Use a **lab firewall you can lock yourself out of and rebuild**. Never run this
checklist against the firewall protecting the network you are connected through: step 3
and step 5 both stage rule changes, and a mistake there is a self-inflicted outage.

```bash
uv tool install firewall-aiops
firewall-aiops init      # wizard: pick platform, store the secret encrypted
```

Record the platform and version you tested (e.g. "OPNsense 25.1", "pfSense CE 2.7.2") —
a tick is only meaningful with the build it was ticked against.

## Verification checklist

Tick every box. A box that cannot be ticked is a verification gap — record it, do not
silently pass.

### 1. Connectivity (the fastest live gate)
- [ ] `firewall-aiops doctor` → all green: config parsed, secret store unlocks, and a
      real firmware/version query returns from the box.
- [ ] `firewall-aiops doctor --skip-auth` → passes offline (config/secret checks only).
- [ ] Repeat both against a **second target on the other platform**, so the platform
      registry is proven on OPNsense *and* pfSense, not just one.

### 2. Reads return real, well-shaped data
- [ ] `firewall-aiops overview` → the real firmware version, the actual gateways and
      interfaces with their link state, and a rule count matching the web UI.
- [ ] `firewall-aiops rules list` → the real ruleset in evaluation order; uuids match
      what the UI shows. `firewall-aiops rules show <uuid>` returns that rule's detail.
- [ ] MCP `gateway_status` → loss % and RTT match the *Gateways* widget in the UI.
- [ ] MCP `nat_port_forwards`, `nat_outbound`, `nat_one_to_one` → match the NAT tabs;
      an empty table returns cleanly rather than erroring.
- [ ] MCP `list_aliases` + `alias_entries` → the real aliases and their members.
- [ ] MCP `wireguard_status`, `openvpn_sessions`, `ipsec_sas` → configured tunnels are
      listed; **unconfigured VPN types degrade gracefully** (empty result, not a crash).
- [ ] MCP `dhcp_leases` / `dhcp_static_mappings` → real leases and reservations.
- [ ] `firewall-aiops log --action block --limit 50` → real log lines, correctly
      filtered to blocks.
- [ ] MCP `states_table` / `top_talkers` → non-empty on a box carrying traffic.

### 3. The analyses are right, not just non-crashing
- [ ] `gateway_health_rca` → with a WAN deliberately degraded (unplug it, or add loss
      upstream), the RCA flags the right gateway, cites the loss/RTT the UI shows, and
      names a cause that matches what you actually broke.
- [ ] `rule_hit_and_shadow_analysis` → add a deliberately shadowed rule below a broad
      terminating rule; the analysis names both the shadowed and the covering uuid.
- [ ] `blocked_traffic_rca` → run an `nmap` scan at the WAN from another host; the
      scanner shows up as the top blocked source, classified as a scan.

### 4. A reversible write + its undo (governance closes the loop)
- [ ] `firewall-aiops rules toggle <uuid> --disable --dry-run` → prints the call,
      changes nothing on the box (confirm in the UI).
- [ ] `firewall-aiops rules toggle <uuid> --disable` → the rule shows disabled in the
      UI, the result carries an `_undo_id`, and a row lands in
      `~/.firewall-aiops/audit.db`.
- [ ] `firewall-aiops undo list` shows it; `firewall-aiops undo apply <id>` restores the
      **prior** enabled flag (proves undo captured the real before-state, not a guess) —
      verify against a rule that was already disabled, where a naive "flip it" undo
      would be wrong.
- [ ] MCP `add_alias_entry` then `undo apply` → the entry is gone and the alias's other
      members are untouched.

### 5. Staged vs live (the semantic most likely to differ from the mocks)
- [ ] After a `toggle_rule`, confirm the change is **staged** — the UI shows a pending
      "Apply changes" banner and live traffic is unaffected.
- [ ] MCP `apply_changes` → the staged change becomes live and the banner clears.
- [ ] Confirm `apply_changes` behaves the same on **both** platforms (pfSense's
      apply semantics differ from OPNsense's — this is a likely divergence point).
- [ ] `pending_changes` reflects an edit staged **in the web GUI** (not by this
      tool). If it does not, the `apply_changes` lockout guard is blind to exactly
      the edits it most needs to see — that would be a real finding.

### 6. Self-lockout guards (needs console access — do not skip the console part)
- [ ] `restart_service(service="nginx")` on OPNsense (`lighttpd` on pfSense) is
      **refused** with the teaching message, and the appliance stays up.
- [ ] `restart_service(service="unbound")` still works — the guard is exact, and
      over-blocking would be its own failure.
- [ ] Stage a rule that blocks the management address/port, then `apply_changes`
      → **refused**, and the firewall's UI still shows the change unapplied.
- [ ] Same rule, `override=True`, run **from the console** → it applies and you
      do lose API access. Restore from the console. This proves the guard was
      protecting something real, not shadow-boxing.
- [ ] Stage a rule whose destination is an **alias** covering the management host
      → `apply_changes` proceeds with an `ALIAS_DESTINATION` warning (fail-open).

### 7. Governance records (it does not gate)
- [ ] `apply_changes` / `reconfigure` / `reboot` run without any approver set — the
      tool does not authorize writes; the connecting account's permissions do. Each
      lands an audit row with its risk tier recorded as a descriptive label.
- [ ] With `FIREWALL_AUDIT_APPROVED_BY` and `FIREWALL_AUDIT_RATIONALE` set, the
      approver and rationale appear in the audit row (optional annotations, never
      required).
- [ ] A tight poll loop trips the runaway budget guard (`FIREWALL_RUNAWAY_MAX`) rather
      than hammering the firewall's API.
- [ ] A failed call (wrong uuid) is audited with `status=error` and records **no** undo.

### 8. Cleanup
- [ ] Re-enable every rule you disabled, remove every alias entry you added, and
      `apply_changes` once more.
- [ ] `firewall-aiops overview` matches the baseline you captured before starting.
- [ ] Skim `~/.firewall-aiops/audit.db` — every write you made in the session is there,
      with the right risk tier.

## Criteria to consider it live-verified

All of the following must hold:

1. Every box above is ticked against **both** platforms, with the exact builds recorded
   (e.g. "OPNsense 25.1 + pfSense CE 2.7.2").
2. Every REST-path or field-shape mismatch found during the run is **fixed and covered
   by a regression test**, so the mock suite would now catch it.
3. Section 5 (staged vs live) passed on both platforms — this is the semantic the mocks
   are least able to model.
4. The run is written up in the release notes / product-line memory with the date and
   the package version, matching how the line records its other live-verified tools.

Until then, this repo says only what is true: mock-validated, live-unverified. Claiming
otherwise would break that promise.

## Notes for maintainers

- `firewall-aiops doctor` is the single fastest live entry point; start there.
- Run the checklist against a **mixed** estate if you can. One config spanning an
  OPNsense and a pfSense target is the case the platform registry exists for, and it is
  the case mocks cover least convincingly.
- Add this tool's result to the product-line verification ledger once green, so the
  central "verification debt" list stays accurate.
