"""CLI package for firewall-aiops.

Re-exports ``app`` so the pyproject entry point
``firewall-aiops = "firewall_aiops.cli:app"`` works unchanged.
"""

from firewall_aiops.cli._root import app

__all__ = ["app"]
