"""
agent_security/nesting_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3C — Syntactic Nesting Limiter Adapter.

Maintains backwards compatibility for callers expecting check_nesting_depth()
and check_ast_depth(), delegating to agent_security.input_limits.
"""

from __future__ import annotations

import ast
from typing import Tuple

from agent_security.config import MAX_NESTING_DEPTH, MAX_AST_DEPTH
from agent_security.input_limits import (
    check_source,
    check_ast_depth as _iterative_check_ast_depth,
    InputRejected,
)


class NestingTooDeep(Exception):
    """Raised when nesting depth exceeds the configured limit."""

    def __init__(self, actual_depth: int, limit: int, context: str = "") -> None:
        self.actual_depth = actual_depth
        self.limit = limit
        ctx = f" ({context})" if context else ""
        super().__init__(
            f"NestingTooDeep: depth {actual_depth} exceeds limit {limit}{ctx}"
        )


def check_nesting_depth(
    source: str,
    max_depth: int = MAX_NESTING_DEPTH,
) -> Tuple[bool, int]:
    """
    Scan source code and measure bracket nesting depth.
    Returns (is_safe, actual_depth).
    """
    if not source:
        return True, 0

    is_safe, reason = check_source(source)
    # Extract depth from reason if failed
    if not is_safe and "Bracket nesting depth" in reason:
        try:
            depth_str = reason.split("(")[1].split(")")[0]
            return False, int(depth_str)
        except Exception:
            return False, max_depth + 1

    # Measure observed depth
    depth = 0
    max_seen = 0
    OPEN = frozenset("([{")
    CLOSE = frozenset(")]}")
    in_str = False

    for ch in source:
        if ch in ('"', "'"):
            in_str = not in_str
        elif not in_str:
            if ch in OPEN:
                depth += 1
                if depth > max_seen:
                    max_seen = depth
            elif ch in CLOSE:
                depth = max(0, depth - 1)

    return max_seen <= max_depth, max_seen


def check_ast_depth(
    tree: ast.AST,
    max_depth: int = MAX_AST_DEPTH,
) -> Tuple[bool, int]:
    """
    Iterative AST depth calculation (no recursion).
    Delegates directly to input_limits.
    """
    return _iterative_check_ast_depth(tree, max_depth)
