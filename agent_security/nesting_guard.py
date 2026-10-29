"""
agent_security/nesting_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3C — Syntactic Nesting Limiter.

Protects ast.parse() callers from Recursion / Call-Stack Exhaustion
attacks caused by pathologically nested expressions such as:

    ((((((((((((((( 1 )))))))))))))))) * 2000
    f(f(f(f(f(f(f(f(f(f(f(f(f(1)))))))))))))

Two complementary checks are provided:

  check_nesting_depth(source)
      Pure character-scan: counts bracket/paren/brace depth per line
      without calling ast.parse().  Applied BEFORE parse to catch
      obvious depth bombs cheaply.

  check_ast_depth(tree)
      Walks an already-parsed AST and measures the actual node depth.
      Applied AFTER parse to guard recursive walks on valid-but-deep trees.

Public API
──────────
  NestingTooDeep(Exception)  – carries actual_depth and limit
  check_nesting_depth(source, max_depth) -> tuple[bool, int]
  check_ast_depth(tree, max_depth)       -> tuple[bool, int]
"""

from __future__ import annotations

import ast
from typing import Tuple

from agent_security.config import MAX_NESTING_DEPTH, MAX_AST_DEPTH


# ─────────────────────────────────────────────────────────────────────────────
# Exception
# ─────────────────────────────────────────────────────────────────────────────

class NestingTooDeep(Exception):
    """Raised when nesting depth exceeds the configured limit."""

    def __init__(self, actual_depth: int, limit: int, context: str = "") -> None:
        self.actual_depth = actual_depth
        self.limit = limit
        ctx = f" ({context})" if context else ""
        super().__init__(
            f"NestingTooDeep: depth {actual_depth} exceeds limit {limit}{ctx}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Syntactic (pre-parse) depth check
# ─────────────────────────────────────────────────────────────────────────────

def check_nesting_depth(
    source: str,
    max_depth: int = MAX_NESTING_DEPTH,
) -> Tuple[bool, int]:
    """
    Scan *source* character-by-character and track the maximum bracket/
    paren/brace nesting depth WITHOUT calling ast.parse().

    This is the first line of defence: it must be called before parse().

    Parameters
    ----------
    source : str
        Raw Python source code.
    max_depth : int
        Maximum allowed depth (default: ``MAX_NESTING_DEPTH`` from config).

    Returns
    -------
    (is_safe, max_observed_depth)
        ``is_safe`` is False when ``max_observed_depth >= max_depth``.

    Fail-closed
    -----------
    Any unexpected exception returns (False, -1).
    """
    if not source:
        return True, 0

    try:
        depth = 0
        max_seen = 0
        in_single_str = False
        in_double_str = False
        in_comment = False
        i = 0
        n = len(source)

        OPEN  = frozenset("([{")
        CLOSE = frozenset(")]}")

        while i < n:
            ch = source[i]

            # Comment: ignore until newline
            if in_comment:
                if ch == "\n":
                    in_comment = False
                i += 1
                continue

            # String escapes
            if (in_single_str or in_double_str) and ch == "\\":
                i += 2  # skip escaped char
                continue

            # Exit single-quoted string
            if in_single_str and ch == "'":
                in_single_str = False
                i += 1
                continue

            # Exit double-quoted string
            if in_double_str and ch == '"':
                in_double_str = False
                i += 1
                continue

            # Skip chars inside strings
            if in_single_str or in_double_str:
                i += 1
                continue

            # Enter string or comment
            if ch == "'":
                in_single_str = True
                i += 1
                continue
            if ch == '"':
                in_double_str = True
                i += 1
                continue
            if ch == "#":
                in_comment = True
                i += 1
                continue

            # Bracket tracking
            if ch in OPEN:
                depth += 1
                if depth > max_seen:
                    max_seen = depth
            elif ch in CLOSE:
                depth = max(0, depth - 1)

            i += 1

        is_safe = max_seen < max_depth
        return is_safe, max_seen

    except Exception:
        return False, -1  # fail closed


# ─────────────────────────────────────────────────────────────────────────────
# AST (post-parse) depth check
# ─────────────────────────────────────────────────────────────────────────────

def check_ast_depth(
    tree: ast.AST,
    max_depth: int = MAX_AST_DEPTH,
) -> Tuple[bool, int]:
    """
    Walk *tree* and measure the maximum AST node depth.

    Applied after ast.parse() has already succeeded, to guard downstream
    recursive visitors (e.g. ast.NodeVisitor subclasses) from stack overflow
    on pathologically deep trees.

    Parameters
    ----------
    tree : ast.AST
        Already-parsed AST root.
    max_depth : int
        Maximum allowed node depth (default: ``MAX_AST_DEPTH`` from config).

    Returns
    -------
    (is_safe, max_observed_depth)
        ``is_safe`` is False when ``max_observed_depth >= max_depth``.

    Fail-closed
    -----------
    Any unexpected exception returns (False, -1).
    """
    try:
        max_seen = _measure_depth(tree, current=0)
        is_safe = max_seen < max_depth
        return is_safe, max_seen
    except RecursionError:
        # The tree itself was too deep to walk without stack overflow.
        return False, -1
    except Exception:
        return False, -1


def _measure_depth(node: ast.AST, current: int) -> int:
    """Recursive helper; returns the maximum depth found in subtree."""
    child_max = current
    for child in ast.iter_child_nodes(node):
        d = _measure_depth(child, current + 1)
        if d > child_max:
            child_max = d
    return child_max
