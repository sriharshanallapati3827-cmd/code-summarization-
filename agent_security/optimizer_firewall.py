"""
agent_security/optimizer_firewall.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3F — Compiler-Level AST Firewall for Optimizer Output.

When the LLM Optimizer Agent proposes refactored code, this module
inspects the output AST before it is accepted, verifying that:

  1. No new dangerous module imports were introduced (beyond a safe
     whitelist of standard-library modules).
  2. No forbidden call patterns (os.system, exec, eval, subprocess, etc.)
     appear in the generated code.

If the generated code passes the firewall, the pipeline returns it.
If it fails, the pipeline falls back to the deterministic rule-based
transformer — the LLM output is silently discarded, never executed.

Public API
──────────
  OptimizerOutputTainted(Exception)  – carries violations list
  audit_optimizer_output(source: str) -> tuple[bool, list[str]]
      Returns (True, []) when clean, (False, [violation, ...]) when tainted.
      FAILS CLOSED: any unexpected error returns (False, [reason]).

Safe stdlib whitelist
─────────────────────
  The optimizer is expected to produce code that only imports from a
  bounded set of standard-library modules.  Any import not in this list
  is flagged as a violation.
"""

from __future__ import annotations

import ast
from typing import List, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Safe module whitelist — the optimizer may only introduce these imports
# ─────────────────────────────────────────────────────────────────────────────

SAFE_STDLIB_MODULES: frozenset = frozenset({
    # Built-ins & core
    "ast", "builtins", "abc", "copy", "collections", "dataclasses",
    "enum", "functools", "itertools", "operator", "typing",
    # Math / data
    "math", "cmath", "decimal", "fractions", "statistics", "random",
    "heapq", "bisect", "array",
    # String / text
    "string", "re", "textwrap", "unicodedata", "difflib",
    # IO / file (read-only patterns expected)
    "io", "pathlib",
    # Date / time
    "datetime", "time", "calendar",
    # Serialization
    "json", "csv",
    # Logging & warnings
    "logging", "warnings",
    # Inspection
    "inspect", "dis",
    # OS path utilities (NOT os.system; checked separately)
    "os.path", "os",
    # Standard optimisation helpers
    "lru_cache",
})

# ─────────────────────────────────────────────────────────────────────────────
# Dangerous call patterns that must NEVER appear in optimizer output
# ─────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_CALLS = frozenset({
    # Arbitrary code execution
    "eval", "exec", "compile",
    # Shell access
    "system", "popen",
    # Dynamic import
    "__import__",
})

_FORBIDDEN_MODULES = frozenset({
    "subprocess", "shutil", "socket", "ctypes", "pty", "telnetlib",
    "ftplib", "smtplib", "http.server", "xmlrpc",
})


# ─────────────────────────────────────────────────────────────────────────────
# Exception
# ─────────────────────────────────────────────────────────────────────────────

class OptimizerOutputTainted(Exception):
    """Raised when LLM optimizer output contains forbidden patterns."""

    def __init__(self, violations: List[str]) -> None:
        self.violations = violations
        super().__init__(
            "OptimizerOutputTainted: " + "; ".join(violations)
        )


# ─────────────────────────────────────────────────────────────────────────────
# Firewall visitor
# ─────────────────────────────────────────────────────────────────────────────

class _FirewallVisitor(ast.NodeVisitor):
    """Visits optimizer output AST and collects policy violations."""

    def __init__(self, original_imports: Set[str]) -> None:
        # Imports that were already present in the ORIGINAL code are allowed;
        # we only flag NEW modules introduced by the optimizer.
        self._original_imports = original_imports
        self.violations: List[str] = []

    def _lineno(self, node: ast.AST) -> str:
        return f"line {getattr(node, 'lineno', '?')}"

    # ── Import checks ─────────────────────────────────────────────────────────
    def _check_module(self, module_name: str, node: ast.AST) -> None:
        root = module_name.split(".")[0]
        if root in _FORBIDDEN_MODULES:
            self.violations.append(
                f"{self._lineno(node)}: forbidden module '{root}' imported by optimizer"
            )
        elif root not in {m.split(".")[0] for m in SAFE_STDLIB_MODULES}:
            if root not in self._original_imports:
                self.violations.append(
                    f"{self._lineno(node)}: optimizer introduced unknown module '{root}'"
                )

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._check_module(alias.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self._check_module(node.module, node)
        self.generic_visit(node)

    # ── Call checks ───────────────────────────────────────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # Bare forbidden calls: eval(), exec(), __import__()
        if isinstance(func, ast.Name) and func.id in _FORBIDDEN_CALLS:
            self.violations.append(
                f"{self._lineno(node)}: forbidden call '{func.id}()' in optimizer output"
            )
        # Attribute calls: os.system(), subprocess.run()
        elif isinstance(func, ast.Attribute):
            obj = func.value
            attr = func.attr
            if attr in _FORBIDDEN_CALLS:
                self.violations.append(
                    f"{self._lineno(node)}: forbidden attribute call '*.{attr}()' in optimizer output"
                )
            if isinstance(obj, ast.Name) and obj.id in _FORBIDDEN_MODULES:
                self.violations.append(
                    f"{self._lineno(node)}: call on forbidden module '{obj.id}.{attr}()'"
                )
        self.generic_visit(node)


# ─────────────────────────────────────────────────────────────────────────────
# Helper: extract the set of top-level module names imported by source
# ─────────────────────────────────────────────────────────────────────────────

def _collect_imports(source: str) -> Set[str]:
    """Return the set of root module names imported in *source*."""
    try:
        tree = ast.parse(source)
    except Exception:
        return set()
    names: Set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def audit_optimizer_output(
    optimized_source: str,
    original_source: str = "",
) -> Tuple[bool, List[str]]:
    """
    Inspect LLM-generated *optimized_source* for forbidden patterns.

    Parameters
    ----------
    optimized_source : str
        The code produced by the LLM optimizer.
    original_source : str, optional
        The original user code.  Modules already imported in the original
        are not flagged as new introductions by the optimizer.

    Returns
    -------
    (is_clean, violations)
        ``is_clean`` is True when the output is safe to use.
        ``violations`` is empty when clean.

    Fail-closed
    -----------
    Any unexpected error returns (False, [reason]).
    """
    if not optimized_source or not optimized_source.strip():
        return False, ["optimizer produced empty output"]

    try:
        tree = ast.parse(optimized_source)
    except SyntaxError as exc:
        return False, [f"optimizer output has syntax error: {exc}"]
    except Exception as exc:
        return False, [f"firewall parse failed: {exc}"]

    try:
        original_imports = _collect_imports(original_source) if original_source else set()
        visitor = _FirewallVisitor(original_imports=original_imports)
        visitor.visit(tree)
        violations = visitor.violations
    except Exception as exc:
        return False, [f"firewall AST walk failed: {exc}"]

    if violations:
        return False, violations
    return True, []
