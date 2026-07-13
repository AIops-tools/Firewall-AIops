"""Environment and connectivity diagnostics for Firewall AIops."""

from __future__ import annotations

from rich.console import Console

from firewall_aiops.config import CONFIG_FILE, ENV_FILE, load_config
from firewall_aiops.secretstore import SECRETS_FILE, check_permissions, has_store

_console = Console()


def run_doctor(skip_auth: bool = False) -> int:
    """Check config, secrets, and (optionally) connectivity.

    Returns a process exit code: 0 healthy, 1 problems found. Connectivity
    failures are reported as status, never raised as tracebacks (a doctor must
    survive the thing it diagnoses being unhealthy).
    """
    problems = 0

    if not CONFIG_FILE.exists():
        _console.print(f"[red]✗ Config file missing: {CONFIG_FILE}[/]")
        _console.print("[yellow]  Run 'firewall-aiops init' to set up your first target.[/]")
        return 1
    _console.print(f"[green]✓ Config file present: {CONFIG_FILE}[/]")

    try:
        config = load_config()
    except Exception as exc:  # noqa: BLE001 — report, do not crash
        _console.print(f"[red]✗ Config load failed: {exc}[/]")
        return 1

    if not config.targets:
        _console.print("[red]✗ No targets configured[/]")
        return 1
    _console.print(f"[green]✓ {len(config.targets)} target(s) configured[/]")

    if has_store():
        _console.print(f"[green]✓ Encrypted secret store present: {SECRETS_FILE}[/]")
        perm_warning = check_permissions()
        if perm_warning:
            _console.print(f"[yellow]! {perm_warning}[/]")
    elif ENV_FILE.exists():
        _console.print(
            f"[yellow]! Using legacy plaintext .env ({ENV_FILE}). Migrate with "
            f"'firewall-aiops secret migrate'.[/]"
        )
    else:
        _console.print(
            "[yellow]! No secret store yet. Run 'firewall-aiops init' to set up "
            "credentials (stored encrypted).[/]"
        )
        problems += 1

    for target in config.targets:
        try:
            _ = target.secret
            _console.print(
                f"[green]✓ Secret present for '{target.name}' ({target.platform})[/]"
            )
        except OSError as exc:
            _console.print(f"[red]✗ {exc}[/]")
            problems += 1

    if skip_auth:
        _console.print("[dim]Skipping connectivity check (--skip-auth).[/]")
        return 1 if problems else 0

    from firewall_aiops.connection import ConnectionManager

    mgr = ConnectionManager(config)
    for target in config.targets:
        try:
            conn = mgr.connect(target.name)
            # A cheap read that exists on both platforms: firmware/version.
            conn.get(conn.platform.path("firmware"))
            _console.print(
                f"[green]✓ Connected to '{target.name}' ({target.platform} "
                f"{target.host}) — firmware/version query OK[/]"
            )
        except Exception as exc:  # noqa: BLE001 — connectivity is a status, not a crash
            _console.print(f"[red]✗ Connect to '{target.name}' failed: {exc}[/]")
            problems += 1

    return 1 if problems else 0
