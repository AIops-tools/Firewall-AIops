# Agent guardrails — running firewall-aiops with a smaller / local model

If you drive these tools with a local model (Llama, Qwen, Mistral … via Goose,
Ollama, LM Studio, or any OpenAI-compatible runtime), you will get noticeably
better results with a short system prompt. This page gives you one, and — more
importantly — tells you which guardrails you **no longer need to write**, because
the tool now enforces them itself.

The distinction matters. A guardrail in a prompt is a request. A guardrail in the
harness is a guarantee. Anything below that we could move into the harness, we did.

## What the tool now enforces — do not waste prompt budget on these

| You might be tempted to prompt | Why you don't need to |
|---|---|
| "Never restart the web GUI / lock yourself out" | **Already enforced.** `restart_service` refuses the daemon serving this appliance's own API (`nginx`, `lighttpd`, `configd`, `webgui`, ...), and `apply_changes` / `reconfigure` refuse a staged rule set that would provably cut management access. Both are exact and fail open — see `capabilities.md`. Do not spend prompt budget on it. |
| "Work read-only, never change a rule" | Set `FIREWALL_READ_ONLY=1`. The nine write tools (`toggle_rule`, `apply_changes`, `add_alias_entry`, `remove_alias_entry`, `kill_states`, `restart_service`, `reconfigure`, `reboot`, `undo_apply`) are then **not registered at all** — they never appear in the tool list, so the model cannot call one even if it tries. The `@governed_tool` harness independently refuses writes, so the CLI is covered too. |
| "Don't invent a value when a field is missing" | OPNsense and pfSense populate different keys for the same concept. A field neither platform returned comes back as `null`, never as `""`. Absent and empty are distinguishable in the payload. |
| "Tell me if the output was cut off" | `firewall_log`, `states_table` and `top_talkers` return `{"entries": [...], "returned": N, "limit": L, "truncated": true/false}`. Truncation is measured, not guessed from a length coincidence. |
| "Preserve the ordering / tell me what's most urgent" | The RCA tools (`gateway_health_rca`, `rule_hit_and_shadow_analysis`, `blocked_traffic_rca`) return findings with the measured numbers attached, worst-first. Priority is in the payload, not implied by list position. |
| "Confirm before anything destructive" | Write operations require a `--dry-run`-able preview plus double confirmation at the CLI, and a named approver (`FIREWALL_AUDIT_APPROVED_BY`) for high-risk tiers. |
| "Log what you did" | Every governed call is audited to `~/.firewall-aiops/audit.db` regardless of what the model says it did. |

## What still needs a prompt

These are model-behaviour problems the harness cannot fix from the outside.
Copy this into your agent's system prompt:

```text
You operate an OPNsense or pfSense firewall through the firewall-aiops MCP tools.

TOOL USE
- Before answering any question about the current firewall, you MUST call a
  tool. Never answer from memory or assumption.
- Actually invoke the tool. Do not describe the call you would make, and do not
  emit an example JSON response in place of calling it.
- If a tool call fails, report the real error verbatim. Never fill the gap with
  a plausible-sounding answer.

READING RESULTS
- Read the whole result before concluding. If a result contains a "truncated"
  field that is true, say so and re-run with a higher limit instead of treating
  the partial result as complete.
- A null field means neither platform returned that value. Report it as "not
  available" — never infer it. In particular, a rule with a null "interface" is
  not a rule on an interface named "none".
- Report values exactly as returned. Do not normalise, translate, or prettify
  rule actions, gateway statuses, or interface names.
- A gateway whose status is "none" is unmonitored, not down. A gateway with no
  status field at all is unknown — say so rather than calling it healthy.

SCOPE
- Separate observation from interpretation. State what the tools returned, then
  any interpretation, clearly marked as such.
- Do not assert that traffic is being blocked by a specific rule unless a log
  entry or the shadow analysis actually names that rule.
- Do not add generic firewall advice that does not follow from the tool output.
- Do not confuse a rule UUID with an alias name, an interface name (wan, lan,
  opt1) with its description, or a gateway name with its monitor IP.
- OPNsense and pfSense are different platforms with different API shapes. Do not
  suggest an OPNsense-only action on a pfSense target; the target's platform is
  reported in the overview.

CHANGES ARE TWO-STEP
- On OPNsense, editing a rule stages it; nothing takes effect until
  apply_changes is called. Never report a change as live before that.
```

## Recommended setup for a local model

```bash
# Read-only until you trust the setup — this is enforced, not advisory.
export FIREWALL_READ_ONLY=1
firewall-aiops doctor
```

Then, when you are ready to allow writes, unset it and set an approver so the
high-risk tier has an accountable name on it:

```bash
unset FIREWALL_READ_ONLY
export FIREWALL_AUDIT_APPROVED_BY="your.name@example.com"
export FIREWALL_AUDIT_RATIONALE="scheduled maintenance window 2026-07-20"
```

Read-only mode is a sensible default for a firewall specifically: a mistaken
`toggle_rule` or `reboot` on the box that carries your management session locks
you out of the thing you were trying to fix.

## If your model still struggles

Some behaviours are model-capacity limits rather than prompt problems:

- **Multi-tool workflows time out or drift.** Prefer the RCA tools
  (`gateway_health_rca`, `blocked_traffic_rca`,
  `rule_hit_and_shadow_analysis`) — they do the multi-step correlation inside
  one call, so the model does not have to chain reads and keep rule UUIDs
  straight.
- **The model ignores later tool results in a long context.** The firewall log
  and state table are the two big payloads here; ask narrower questions and use
  `--limit` / `top` deliberately rather than pulling the whole state table.
- **The model describes calls instead of making them.** This is usually a
  runtime/tool-calling-format mismatch, not a prompt problem — check that your
  client advertises the tools in the format your model was trained on.

Feedback on running this with a specific local model is genuinely useful —
open an issue at
[github.com/AIops-tools/Firewall-AIops](https://github.com/AIops-tools/Firewall-AIops/issues)
with the model, runtime, and what went wrong.
