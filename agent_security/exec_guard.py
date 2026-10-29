"""
agent_security/exec_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3A — Pre-Execution AST Gatekeeper Adapter.

Maintains backwards compatibility for callers expecting check_exec_safety(),
delegating directly to the iterative ast_gatekeeper.scan engine.
"""

from __future__ import annotations

import ast
from typing import List, Tuple

from agent_security.ast_gatekeeper import (
    scan,
    GatekeeperReport,
    Violation,
    FORBIDDEN_MODULES,
    FORBIDDEN_OS_ATTRS,
    FORBIDDEN_CALLS,
    FORBIDDEN_DUNDERS,
)


class ExecBlocked(Exception):
    """Raised when check_exec_safety() detects forbidden patterns."""

    def __init__(self, reasons: List[str]) -> None:
        self.reasons = reasons
        super().__init__(
            "ExecBlocked: dangerous code detected — " + "; ".join(reasons)
        )


class ForbiddenNodeVisitor(ast.NodeVisitor):
    """Adapter maintaining compatibility with legacy visitor queries."""

    def __init__(self) -> None:
        self.violations: List[str] = []

    def visit(self, node: ast.AST) -> None:
        # Generate source and scan via Gatekeeper
        try:
            src = ast.unparse(node)
            report = scan(src)
            self.violations = report.block_reasons
        except Exception:
            pass


def check_exec_safety(source: str) -> Tuple[bool, List[str]]:
    """
    Delegate AST safety check to the iterative ast_gatekeeper scanner.
    Returns (is_safe, reasons).
    """
    report = scan(source)
    return report.is_safe, report.block_reasons
