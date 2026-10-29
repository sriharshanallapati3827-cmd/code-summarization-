# agent_security/__init__.py
# ──────────────────────────────────────────────────────────────────────────────
# Pillar 1 – Input Privacy & Anti-Hijack Shield
# Pillar 2 – DFA Agent Workflow Guard
# Pillar 3 – Agent Code Hardening & Sandbox
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
from agent_security.exec_guard import (  # noqa: F401
    ExecBlocked,
    ForbiddenNodeVisitor,
    check_exec_safety,
)
from agent_security.nesting_guard import (  # noqa: F401
    NestingTooDeep,
    check_nesting_depth,
    check_ast_depth,
)
from agent_security.optimizer_firewall import (  # noqa: F401
    OptimizerOutputTainted,
    audit_optimizer_output,
    SAFE_STDLIB_MODULES,
)
from agent_security.regex_timeout import (  # noqa: F401
    timed_search,
    timed_match,
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
    # Pillar 3
    "ExecBlocked",
    "ForbiddenNodeVisitor",
    "check_exec_safety",
    "NestingTooDeep",
    "check_nesting_depth",
    "check_ast_depth",
    "OptimizerOutputTainted",
    "audit_optimizer_output",
    "SAFE_STDLIB_MODULES",
    # Session B / Attack-5
    "timed_search",
    "timed_match",
]
