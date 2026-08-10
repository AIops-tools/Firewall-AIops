"""Shared helpers for firewall-aiops CLI sub-modules."""

from __future__ import annotations

import functools
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.console import Console

console = Console()

# ─── Shared Option types ───────────────────────────────────────────────────

TargetOption = Annotated[
    str | None, typer.Option("--target", "-t", help="Target name from config")
]
DryRunOption = Annotated[
    bool, typer.Option("--dry-run", help="Print the API call without executing")
]


def _cli_error_types() -> tuple[type[BaseException], ...]:
    """Exceptions translated to a one-line teaching error instead of a traceback.

    ``PolicyDenied`` is kept here defensively even though it is not a ValueError:
    the harness no longer raises it in normal operation — there is no read-only
    switch or approval gate to refuse a call — but catching it means that if it
    ever surfaces it renders as a one-line message rather than a bare traceback,
    which would otherwise exit 1 printing NOTHING.
    """
    from firewall_aiops.connection import FirewallApiError
    from firewall_aiops.governance import PolicyDenied

    return (FirewallApiError, KeyError, OSError, ValueError, PolicyDenied)


def cli_errors(fn: Callable) -> Callable:
    """Translate known exceptions into one red line + exit code 1."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except (typer.Exit, typer.Abort):
            raise
        except _cli_error_types() as e:
            message = str(e)
            if isinstance(e, KeyError):
                message = f"Missing required key or environment variable: {message}"
            console.print(f"[red]Error: {message}[/]")
            raise typer.Exit(1) from e

    return wrapper


def get_connection(target: str | None, config_path: Path | None = None) -> tuple[Any, Any]:
    """Return a (conn, config) tuple for the given target."""
    from firewall_aiops.config import load_config
    from firewall_aiops.connection import ConnectionManager

    cfg = load_config(config_path)
    mgr = ConnectionManager(cfg)
    return mgr.connect(target), cfg


def dry_run_print(*, operation: str, api_call: str, parameters: dict | None = None) -> None:
    """Print a dry-run preview of the API call that would be made."""
    console.print("\n[bold magenta][DRY-RUN] No changes will be made.[/]")
    console.print(f"[magenta]  Operation: {operation}[/]")
    console.print(f"[magenta]  API Call:  {api_call}[/]")
    for k, v in (parameters or {}).items():
        console.print(f"[magenta]  Param:     {k} = {v}[/]")
    console.print("[magenta]  Run without --dry-run to execute.[/]\n")


#: Exit status for a write whose outcome could not be determined. Kept distinct
#: from 0 (confirmed) and 1 (failed) on purpose: a write whose response was lost
#: is not a failure, but it is emphatically not a success either, and a script
#: must be able to tell all three apart.
EXIT_UNDETERMINED = 2


def checked(result: Any) -> Any:
    """Return ``result``, or abort when it reports a failed/undetermined write.

    Every CLI command that calls a governed twin MUST pass the result through
    here before printing its success line.

    Governed twins are wrapped in ``@tool_errors``, which flattens any exception
    into ``{"error": ...}`` and **returns** it. The CLI therefore never sees the
    exception, so a command that prints its result unconditionally reports a
    refused or failed operation exactly like a successful one — and exits 0, so
    a script cannot tell either. The dry-run path already refused with a
    non-zero status, which made the asymmetry worse: the preview was stricter
    than the real call.

    ``outcomeUnknown`` (set by the harness when a write's response is lost) is
    neither success nor failure — the change may still have landed. It gets its
    own line and :data:`EXIT_UNDETERMINED`, never a silent success.
    """
    if not isinstance(result, dict):
        return result
    error = result.get("error")
    if error:
        console.print(f"[red]Error: {error}[/]")
        hint = result.get("hint")
        if hint:
            console.print(f"[dim]{hint}[/]")
        raise typer.Exit(1)
    if result.get("outcomeUnknown"):
        console.print(
            f"[yellow]Outcome undetermined: {result.get('note') or ''}[/]"
        )
        raise typer.Exit(EXIT_UNDETERMINED)
    return result


def dry_run_preview(
    preview: Any, *, operation: str, api_call: str, parameters: dict | None = None
) -> None:
    """Render a GOVERNED dry-run result as the human-readable DRY-RUN banner.

    ``preview`` must come from calling the governed tool with ``dry_run=True``,
    so every guard it carries has already run against the real target — the
    self-lockout checks in particular, which is the whole reason this firewall
    tool previews at all. A refusal arrives as ``{"error": ...}``
    (``tool_errors`` flattens the exception) and is printed like any other CLI
    error, exiting non-zero exactly as the real write would. Printing a green
    banner for a call that is about to be refused is the preview being wrong,
    not merely incomplete: the operator reads the refusal that follows as a
    transient failure and retries it.

    On the allowed path the banner is what it always was — routing through the
    governed call buys the guard and the audit row, not a new serialization.
    """
    if isinstance(preview, dict) and preview.get("error"):
        console.print(f"[red]Error: {preview['error']}[/]")
        raise typer.Exit(1)
    dry_run_print(operation=operation, api_call=api_call, parameters=parameters)


def double_confirm(action: str, resource: str) -> None:
    """Require two confirmations for a destructive operation."""
    console.print(f"[bold yellow]⚠️  About to: {action} '{resource}'[/]")
    typer.confirm(f"Confirm 1/2: {action} '{resource}'?", abort=True)
    typer.confirm(
        f"Confirm 2/2: really {action} '{resource}'? This may be irreversible.",
        abort=True,
    )
