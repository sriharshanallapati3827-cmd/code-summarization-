# agent_security/__init__.py
# ──────────────────────────────────────────────────────────────────────────────
# Pillar 1 – Input Privacy & Anti-Hijack Shield
# Pillar 2 – DFA Agent Workflow Guard
# ──────────────────────────────────────────────────────────────────────────────
from agent_security.input_shield import SecretVault, build_enveloped_prompt  # noqa: F401
from agent_security.workflow_dfa import (  # noqa: F401
    WorkflowDFA,
    WorkflowViolation,
    DFAState,
    ACCEPTING_STATES,
    render_dot,
    render_table,
)

__all__ = [
    # Pillar 1
    "SecretVault",
    "build_enveloped_prompt",
    # Pillar 2
    "WorkflowDFA",
    "WorkflowViolation",
    "DFAState",
    "ACCEPTING_STATES",
    "render_dot",
    "render_table",
]

