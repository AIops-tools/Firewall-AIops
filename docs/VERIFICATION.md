# Live verification — OPNsense / pfSense

`firewall-aiops` is exercised by a **mock-only** test suite (`uv run pytest`, no real
firewall). It has **not** yet been validated end-to-end against a live OPNsense or
pfSense box. This document says exactly what the mock suite already guarantees, and
what a live run has to prove before anyone may describe this tool as verified against
real hardware.

It is deliberately checklist-shaped so the result is reproducible and auditable — not
a subjective "seems fine".

## What the mock suite already guarantees

- Every module imports; the CLI builds; **all 34 MCP tools** carry the
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
  as rows, failures are recorded `status=error` and record no undo, and the
  secure-by-default approver gate refuses high-risk ops with no `rules.yaml`.

What it does **not** guarantee: that the concrete REST paths, field names, and
staged-vs-applied config semantics match a real OPNsense or pfSense build. Those paths
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

### 6. Governance actually gates
- [ ] With no `~/.firewall-aiops/rules.yaml`, `apply_changes` / `reconfigure` /
      `reboot` are **refused** unless `FIREWALL_AUDIT_APPROVED_BY` is set
      (secure-by-default); with it set plus `FIREWALL_AUDIT_RATIONALE`, the approver
      and rationale appear in the audit row.
- [ ] A tight poll loop trips the runaway budget guard (`FIREWALL_RUNAWAY_MAX`) rather
      than hammering the firewall's API.
- [ ] A failed call (wrong uuid) is audited with `status=error` and records **no** undo.

### 7. Cleanup
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
