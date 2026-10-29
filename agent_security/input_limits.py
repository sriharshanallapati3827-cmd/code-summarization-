"""
agent_security/input_limits.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3B — Pre-Parse Input Limits & Centralized Safe Parsing.

Defends against DoS attacks, memory allocation exhaustion, and recursive
call-stack crashes before untrusted code reaches ast.parse() or regex engines.

Checks enforced:
  1. Source size in bytes (MAX_SOURCE_BYTES: 200 KB)
  2. Null bytes (\\x00)
  3. Individual line lengths (MAX_LINE_LENGTH: 2,000 chars)
  4. Syntactic bracket nesting depth (MAX_NESTING_DEPTH: 40)
  5. Pathological operator chains (> 30 consecutive operators)
  6. Post-parse AST node depth using iterative stack traversal (MAX_AST_DEPTH: 100)

Public API:
  InputRejected(Exception)
  check_source(source: str) -> tuple[bool, str]
  check_ast_depth(tree: ast.AST, max_depth: int) -> tuple[bool, int]
  safe_parse(source: str) -> ast.AST
"""

from __future__ import annotations

import ast
from typing import Tuple

from agent_security.config import (
    MAX_SOURCE_BYTES,
    MAX_LINE_LENGTH,
    MAX_NESTING_DEPTH,
    MAX_AST_DEPTH,
)

MAX_OPERATOR_CHAIN: int = 30


# ─────────────────────────────────────────────────────────────────────────────
# Exception
# ─────────────────────────────────────────────────────────────────────────────

class InputRejected(Exception):
    """Raised when untrusted source code violates input limits or safety thresholds."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"InputRejected: {reason}")


# ─────────────────────────────────────────────────────────────────────────────
# Pre-Parse Source Code Inspection
# ─────────────────────────────────────────────────────────────────────────────

def check_source(source: str) -> Tuple[bool, str]:
    """
    Run pre-parse syntactic safety checks over raw source code string.

    Checks:
      - Byte size <= MAX_SOURCE_BYTES
      - No null bytes
      - Every line length <= MAX_LINE_LENGTH
      - Bracket nesting depth <= MAX_NESTING_DEPTH (single linear pass)
      - No consecutive operator chains > MAX_OPERATOR_CHAIN

    Returns:
      (is_safe: bool, reason: str)
    """
    if not source:
        return True, ""

    # 1. Total byte size
    byte_count = len(source.encode("utf-8", errors="replace"))
    if byte_count > MAX_SOURCE_BYTES:
        return False, f"Source size ({byte_count} bytes) exceeds limit ({MAX_SOURCE_BYTES} bytes)"

    # 2. Null byte detection
    if "\x00" in source:
        return False, "Null byte (\\x00) detected in source code"

    # 3. Line length & 4. Bracket nesting & 5. Operator chains (single linear pass)
    n = len(source)
    i = 0
    line_len = 0
    depth = 0
    max_depth = 0
    op_chain = 0
    max_op_chain = 0

    in_single_str = False
    in_double_str = False
    in_triple_single = False
    in_triple_double = False
    in_comment = False

    OPEN_BRACKETS = frozenset("([{")
    CLOSE_BRACKETS = frozenset(")]}")
    OPERATORS = frozenset("+-*/%&|^~<>!=@")

    while i < n:
        ch = source[i]

        # Newline handling
        if ch == "\n":
            if line_len > MAX_LINE_LENGTH:
                return False, f"Line length ({line_len} chars) exceeds limit ({MAX_LINE_LENGTH} chars)"
            line_len = 0
            in_comment = False
            op_chain = 0
            i += 1
            continue

        line_len += 1
        if line_len > MAX_LINE_LENGTH:
            return False, f"Line length exceeds limit ({MAX_LINE_LENGTH} chars)"

        # Comment handling
        if in_comment:
            i += 1
            continue

        # Triple quote checks
        if not in_single_str and not in_double_str:
            if not in_triple_single and source.startswith("'''", i):
                in_triple_single = True
                i += 3
                continue
            elif in_triple_single and source.startswith("'''", i):
                in_triple_single = False
                i += 3
                continue
            elif not in_triple_double and source.startswith('"""', i):
                in_triple_double = True
                i += 3
                continue
            elif in_triple_double and source.startswith('"""', i):
                in_triple_double = False
                i += 3
                continue

        if in_triple_single or in_triple_double:
            i += 1
            continue

        # Single / Double quote string handling with escape skip
        if (in_single_str or in_double_str) and ch == "\\":
            i += 2
            continue

        if in_single_str:
            if ch == "'":
                in_single_str = False
            i += 1
            continue

        if in_double_str:
            if ch == '"':
                in_double_str = False
            i += 1
            continue

        # Not in any string: check delimiters
        if ch == "'":
            in_single_str = True
            op_chain = 0
            i += 1
            continue
        if ch == '"':
            in_double_str = True
            op_chain = 0
            i += 1
            continue
        if ch == "#":
            in_comment = True
            op_chain = 0
            i += 1
            continue

        # Bracket tracking
        if ch in OPEN_BRACKETS:
            depth += 1
            if depth > max_depth:
                max_depth = depth
                if max_depth > MAX_NESTING_DEPTH:
                    return False, f"Bracket nesting depth ({max_depth}) exceeds limit ({MAX_NESTING_DEPTH})"
        elif ch in CLOSE_BRACKETS:
            depth = max(0, depth - 1)

        # Operator chain tracking
        if ch in OPERATORS:
            op_chain += 1
            if op_chain > max_op_chain:
                max_op_chain = op_chain
                if max_op_chain > MAX_OPERATOR_CHAIN:
                    return False, f"Operator chain length ({max_op_chain}) exceeds limit ({MAX_OPERATOR_CHAIN})"
        elif not ch.isspace():
            op_chain = 0

        i += 1

    return True, ""


# ─────────────────────────────────────────────────────────────────────────────
# Post-Parse Iterative AST Depth Inspection (Stack-Based, No Recursion)
# ─────────────────────────────────────────────────────────────────────────────

def check_ast_depth(tree: ast.AST, max_depth: int = MAX_AST_DEPTH) -> Tuple[bool, int]:
    """
    Measure the maximum AST depth using an ITERATIVE stack traversal.
    Completely avoids recursion / call-stack exhaustion.

    Returns:
      (is_safe: bool, max_depth_observed: int)
    """
    if not tree:
        return True, 0

    max_seen = 0
    # Stack stores (node, depth)
    stack = [(tree, 1)]

    while stack:
        node, depth = stack.pop()
        if depth > max_seen:
            max_seen = depth
            if max_seen > max_depth:
                return False, max_seen

        # Add children to stack
        for child in ast.iter_child_nodes(node):
            stack.append((child, depth + 1))

    return max_seen <= max_depth, max_seen


# ─────────────────────────────────────────────────────────────────────────────
# Centralized Safe Parse
# ─────────────────────────────────────────────────────────────────────────────

def safe_parse(source_code: str) -> ast.AST:
    """
    Safely parse Python source code into an AST.

    Enforces:
      1. Pre-parse check_source() input limits.
      2. ast.parse() inside a protected try-block.
      3. Post-parse iterative check_ast_depth() limits.

    Raises:
      InputRejected: if any limit or safety boundary is violated.
      SyntaxError: if the Python code has syntax errors.
    """
    is_safe, reason = check_source(source_code)
    if not is_safe:
        raise InputRejected(reason)

    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        raise
    except RecursionError:
        raise InputRejected("Source code triggered RecursionError during parse")
    except MemoryError:
        raise InputRejected("Source code triggered MemoryError during parse")
    except Exception as exc:
        raise InputRejected(f"AST parse failed: {exc}")

    ast_safe, ast_depth = check_ast_depth(tree, MAX_AST_DEPTH)
    if not ast_safe:
        raise InputRejected(f"AST depth ({ast_depth}) exceeds safety limit ({MAX_AST_DEPTH})")

    return tree
