"""firewall-aiops — governed OPNsense + pfSense firewall operations for AI agents.

Standalone and self-contained: the governance harness (audit, token budget,
undo-token recording, graduated risk tiers, prompt-injection sanitize) is
bundled under ``firewall_aiops.governance`` — this package has no external
skill-family dependency. Preview: not yet full-coverage.
"""

__version__ = "0.1.0"
