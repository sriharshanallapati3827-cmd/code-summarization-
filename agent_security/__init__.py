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
from agent_security.ast_gatekeeper import (  # noqa: F401
    scan,
    Violation,
    GatekeeperReport,
    FORBIDDEN_MODULES,
    FORBIDDEN_OS_ATTRS,
    FORBIDDEN_CALLS,
    FORBIDDEN_DUNDERS,
)
from agent_security.exec_guard import (  # noqa: F401
    ExecBlocked,
    ForbiddenNodeVisitor,
    check_exec_safety,
)
from agent_security.input_limits import (  # noqa: F401
    InputRejected,
    check_source,
    check_ast_depth,
    safe_parse,
)
from agent_security.nesting_guard import (  # noqa: F401
    NestingTooDeep,
    check_nesting_depth,
)
from agent_security.optimizer_firewall import (  # noqa: F401
    OptimizerOutputTainted,
    inspect_candidate,
    audit_optimizer_output,
    SAFE_STDLIB_MODULES,
)
from agent_security.safe_regex import (  # noqa: F401
    safe_search,
    timed_search,
)
from agent_security.regex_timeout import (  # noqa: F401
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
    "scan",
    "Violation",
    "GatekeeperReport",
    "FORBIDDEN_MODULES",
    "FORBIDDEN_OS_ATTRS",
    "FORBIDDEN_CALLS",
    "FORBIDDEN_DUNDERS",
    "ExecBlocked",
    "ForbiddenNodeVisitor",
    "check_exec_safety",
    "InputRejected",
    "check_source",
    "check_ast_depth",
    "safe_parse",
    "NestingTooDeep",
    "check_nesting_depth",
    "OptimizerOutputTainted",
    "inspect_candidate",
    "audit_optimizer_output",
    "SAFE_STDLIB_MODULES",
    # Pillar 4 / Session B
    "safe_search",
    "timed_search",
    "timed_match",
]
