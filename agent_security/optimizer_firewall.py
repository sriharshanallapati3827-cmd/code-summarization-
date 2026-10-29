"""
agent_security/optimizer_firewall.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3C — Compiler-Level AST Firewall for Optimizer Output.

Inspects candidate code produced by either the LLM optimizer or the deterministic
fallback transformer before it is accepted, verifying that:
  1. Candidate parses cleanly without syntax errors.
  2. No NEW unapproved module imports were introduced beyond SAFE_STDLIB_MODULES
     (unless already present in original_code).
  3. No NEW blocklisted calls appear (reusing ast_gatekeeper blocklists).
  4. No NEW dangerous dunder accesses (__subclasses__, __globals__, etc.).
  5. No NEW external URL or IP address literals were injected.

Public API:
  OptimizerOutputTainted(Exception)
  inspect_candidate(candidate_code: str, original_code: str = "") -> tuple[bool, list[str]]
  audit_optimizer_output(candidate_code: str, original_code: str = "") -> tuple[bool, list[str]]
  SAFE_STDLIB_MODULES
"""

from __future__ import annotations

import ast
import re
from typing import List, Set, Tuple

# Reuse constants directly from ast_gatekeeper
from agent_security.ast_gatekeeper import (
    FORBIDDEN_MODULES,
    FORBIDDEN_OS_ATTRS,
    FORBIDDEN_CALLS,
    FORBIDDEN_DUNDERS,
)

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

_IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
_URL_REGEX = re.compile(r"\b(?:https?|ftp|tcp|udp)://[^\s'\"\\]+", re.IGNORECASE)


# ─────────────────────────────────────────────────────────────────────────────
# Exception
# ─────────────────────────────────────────────────────────────────────────────

class OptimizerOutputTainted(Exception):
    """Raised when optimizer candidate output contains forbidden patterns."""

    def __init__(self, violations: List[str]) -> None:
        self.violations = violations
        super().__init__("OptimizerOutputTainted: " + "; ".join(violations))


# ─────────────────────────────────────────────────────────────────────────────
# Firewall Visitor
# ─────────────────────────────────────────────────────────────────────────────

class _FirewallVisitor(ast.NodeVisitor):
    """Visits optimizer candidate AST and collects policy violations."""

    def __init__(
        self,
        original_imports: Set[str],
        original_dunders: Set[str],
        original_strings: Set[str],
    ) -> None:
        self._orig_imports = original_imports
        self._orig_dunders = original_dunders
        self._orig_strings = original_strings
        self.violations: List[str] = []

    def _lineno(self, node: ast.AST) -> str:
        return f"line {getattr(node, 'lineno', '?')}"

    # 1. Imports
    def _check_module(self, module_name: str, node: ast.AST) -> None:
        root = module_name.split(".")[0]
        if root in FORBIDDEN_MODULES:
            self.violations.append(
                f"{self._lineno(node)}: forbidden module '{root}' imported by optimizer"
            )
        elif root not in {m.split(".")[0] for m in SAFE_STDLIB_MODULES}:
            if root not in self._orig_imports:
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
            root = node.module.split(".")[0]
            if root == "os":
                for alias in node.names:
                    if alias.name in FORBIDDEN_OS_ATTRS:
                        self.violations.append(
                            f"{self._lineno(node)}: forbidden import 'os.{alias.name}' in candidate"
                        )
        self.generic_visit(node)

    # 2. Calls
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        # Bare forbidden calls: eval(), exec(), compile(), __import__()
        if isinstance(func, ast.Name) and func.id in FORBIDDEN_CALLS:
            self.violations.append(
                f"{self._lineno(node)}: forbidden call '{func.id}()' in candidate"
            )
        # Attribute calls: os.system(), subprocess.run(), etc.
        elif isinstance(func, ast.Attribute):
            obj = func.value
            attr = func.attr
            if attr in FORBIDDEN_CALLS or attr in FORBIDDEN_OS_ATTRS:
                self.violations.append(
                    f"{self._lineno(node)}: forbidden call '*.{attr}()' in candidate"
                )
            if isinstance(obj, ast.Name) and obj.id in FORBIDDEN_MODULES:
                self.violations.append(
                    f"{self._lineno(node)}: call on forbidden module '{obj.id}.{attr}()'"
                )
        self.generic_visit(node)

    # 3. Dunders
    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr in FORBIDDEN_DUNDERS:
            if node.attr not in self._orig_dunders:
                self.violations.append(
                    f"{self._lineno(node)}: new dangerous dunder access '.{node.attr}' in candidate"
                )
        self.generic_visit(node)

    # 4. String literals (URL / IP injection check)
    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            val = node.value
            if val not in self._orig_strings:
                if _URL_REGEX.search(val):
                    self.violations.append(
                        f"{self._lineno(node)}: new URL literal '{val[:40]}' injected in candidate"
                    )
                elif _IP_REGEX.search(val):
                    self.violations.append(
                        f"{self._lineno(node)}: new IP literal '{val[:20]}' injected in candidate"
                    )
        self.generic_visit(node)


# ─────────────────────────────────────────────────────────────────────────────
# Extraction Helpers for Original Code Baseline
# ─────────────────────────────────────────────────────────────────────────────

def _collect_original_metadata(source: str) -> Tuple[Set[str], Set[str], Set[str]]:
    """Collect imports, dunders, and string literals already in original source."""
    if not source:
        return set(), set(), set()

    imports: Set[str] = set()
    dunders: Set[str] = set()
    strings: Set[str] = set()

    # Extract URLs and IPs appearing anywhere in original source
    for url in _URL_REGEX.findall(source):
        strings.add(url)
    for ip in _IP_REGEX.findall(source):
        strings.add(ip)

    try:
        tree = ast.parse(source)
    except Exception:
        return imports, dunders, strings

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            dunders.add(node.attr)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            strings.add(node.value)

    return imports, dunders, strings


# ─────────────────────────────────────────────────────────────────────────────
# Public Functions
# ─────────────────────────────────────────────────────────────────────────────

def inspect_candidate(
    candidate_code: str,
    original_code: str = "",
    original_source: str = "",
) -> Tuple[bool, List[str]]:
    """
    Inspect candidate code (from LLM or fallback) for security violations.

    Parameters:
      candidate_code: The code to inspect.
      original_code: Original code for baseline diff comparison.
      original_source: Alias for original_code.

    Returns:
      (is_clean: bool, violations: list[str])
    """
    effective_original = original_source or original_code
    if not candidate_code or not candidate_code.strip():
        return False, ["Candidate code is empty"]

    try:
        tree = ast.parse(candidate_code)
    except SyntaxError as exc:
        return False, [f"Candidate code has syntax error: {exc}"]
    except Exception as exc:
        return False, [f"Candidate AST parse failed: {exc}"]

    try:
        orig_imports, orig_dunders, orig_strings = _collect_original_metadata(effective_original)
        visitor = _FirewallVisitor(
            original_imports=orig_imports,
            original_dunders=orig_dunders,
            original_strings=orig_strings,
        )
        visitor.visit(tree)
        violations = visitor.violations
    except Exception as exc:
        return False, [f"Firewall inspection failed: {exc}"]

    if violations:
        return False, violations
    return True, []


# Backward compatibility alias
audit_optimizer_output = inspect_candidate
