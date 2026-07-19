# Release notes — firewall-aiops 0.4.0

Previous release: 0.3.0.

## Headline: read-only mode

```bash
export FIREWALL_READ_ONLY=1
```

With this set the **9 write tools are never registered** — an MCP
client lists **25 tools instead of 34**. The writes are not hidden
behind a flag and not merely refused on call: they are absent from the session,
so a model cannot invoke one and cannot be argued into one. For a reviewer this
is checkable rather than promised — connect, list the tools, and the writes are
not there.

Enforcement is two layers deep: the `@governed_tool` harness refuses every
non-read operation (covering the CLI and in-process callers too), and the MCP
server removes write tools from `list_tools()`. Changing entry point does not
get around it.

## BREAKING — return shapes changed

This release changes payloads that callers may be parsing. Both changes exist
to stop a result from misrepresenting itself:

1. **Absent fields are now `null`, not `""`.** A missing value and an empty value
   were previously indistinguishable, which invited consumers to invent the
   difference. Keys are still always present — only the value may be null.
2. **Anything with a `limit` now returns an envelope** —
   `{"<items>": [...], "returned": N, "limit": L, "truncated": bool}`. Truncation is
   *measured* (one extra row is fetched), never inferred from the page happening to
   be full. Where a genuine pre-cap total is knowable it is reported as `total`;
   where it isn't, `total` is deliberately omitted rather than echoing `returned`.

## Also in this release

- **`docs/VERIFICATION.md`** — what the mock suite actually guarantees, a live
  verification checklist, and the criteria for claiming this tool verified.
- **`skills/firewall-aiops/references/agent-guardrails.md`** — for driving this tool with a
  smaller / local model: which guardrails are now enforced for you, and a
  ready-made system prompt for the rest.
- Expanded operator playbooks in the skill documentation.
- The advertised tool count now matches what an MCP client actually lists
  (it includes `undo_list` / `undo_apply`), and a release gate keeps it honest.
- The `(preview)` label has been dropped. It never meant unreleased; verification
  status now lives in `docs/VERIFICATION.md` where it can be specific.
