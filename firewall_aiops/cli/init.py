"""``firewall-aiops init`` — a friendly, interactive onboarding wizard.

Walks a new user through connecting their first firewall target: collects the
non-secret connection details into ``config.yaml`` and the API secret into the
*encrypted* store (never plaintext on disk). Designed to be run on a terminal;
everything it needs is prompted with sensible defaults.
"""

from __future__ import annotations

import getpass

import typer
import yaml

from firewall_aiops.cli._common import cli_errors, console
from firewall_aiops.config import CONFIG_DIR, CONFIG_FILE
from firewall_aiops.platform import OPNSENSE, PFSENSE, get_platform
from firewall_aiops.secretstore import SecretStore, resolve_master_password


def _load_existing_targets() -> list[dict]:
    if not CONFIG_FILE.exists():
        return []
    raw = yaml.safe_load(CONFIG_FILE.read_text("utf-8")) or {}
    return list(raw.get("targets", []))


def _write_targets(targets: list[dict]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass
    CONFIG_FILE.write_text(yaml.safe_dump({"targets": targets}, sort_keys=False), "utf-8")


@cli_errors
def init_cmd() -> None:
    """Interactively set up your first firewall connection."""
    console.print("[bold cyan]Firewall AIops — setup wizard[/]")
    console.print(
        "This collects OPNsense or pfSense connection details (saved to "
        "config.yaml) and your API secret (saved [bold]encrypted[/] to "
        "secrets.enc).\n"
    )

    console.print("[bold]Step 1 — master password[/]")
    console.print(
        "[dim]Encrypts secrets.enc. You'll set it via the "
        "FIREWALL_AIOPS_MASTER_PASSWORD env var for non-interactive/MCP use.[/]"
    )
    password = resolve_master_password(confirm_if_new=True)
    store = SecretStore.unlock(password)

    targets = _load_existing_targets()
    existing_names = {t.get("name") for t in targets}

    while True:
        console.print("\n[bold]Step 2 — add a target[/]")
        name = typer.prompt("Target name (e.g. fw1)").strip()
        if name in existing_names:
            if not typer.confirm(f"'{name}' already exists — overwrite?", default=False):
                continue
            targets = [t for t in targets if t.get("name") != name]

        platform = typer.prompt(
            f"Platform ({OPNSENSE} / {PFSENSE})", default=OPNSENSE
        ).strip().lower()
        if platform not in (OPNSENSE, PFSENSE):
            console.print("[red]Platform must be 'opnsense' or 'pfsense'.[/]")
            continue

        host = typer.prompt("Host (IP or FQDN)").strip()
        port = typer.prompt("HTTPS port", default=get_platform(platform).default_port, type=int)
        verify_ssl = typer.confirm(
            "Verify TLS certificate? (No for self-signed lab certs)", default=False
        )

        username = ""
        if platform == OPNSENSE:
            username = typer.prompt("OPNsense API key").strip()
            prompt = "OPNsense API secret"
        else:
            prompt = "pfSense API key"
        secret = getpass.getpass(f"{prompt} for '{name}' (hidden): ")
        store = store.set(name, secret)

        entry = {
            "name": name,
            "platform": platform,
            "host": host,
            "port": port,
            "username": username,
            "verify_ssl": verify_ssl,
        }
        targets.append(entry)
        existing_names.add(name)
        _write_targets(targets)
        console.print(f"[green]✓ Saved target '{name}' ({platform}, secret encrypted).[/]")

        if not typer.confirm("\nAdd another target?", default=False):
            break

    console.print(f"\n[green]✓ Setup complete.[/] Config: {CONFIG_FILE}")
    console.print(
        "[dim]Tip: export FIREWALL_AIOPS_MASTER_PASSWORD=... in your shell profile "
        "so the MCP server and CLI can unlock secrets non-interactively.[/]"
    )
    if typer.confirm("Run a connectivity check now (firewall-aiops doctor)?", default=True):
        from firewall_aiops.doctor import run_doctor

        raise typer.Exit(run_doctor())
