# agent_security/__init__.py
# ──────────────────────────────────────────────────────────────────────────────
# Pillar 1 – Input Privacy & Anti-Hijack Shield
# Re-export the public API so callers can do:
#   from agent_security import SecretVault, build_enveloped_prompt
# ──────────────────────────────────────────────────────────────────────────────
from agent_security.input_shield import SecretVault, build_enveloped_prompt  # noqa: F401

__all__ = ["SecretVault", "build_enveloped_prompt"]
