"""
agent_security/exec_guard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3A — Pre-Execution AST Gatekeeper.

Walks the AST of any code BEFORE it is compiled or exec()'d and rejects
it if it contains calls to dangerous system-level functions.

Forbidden call patterns
───────────────────────
  • os.system / os.popen / os.execv* / os.spawn*
  • subprocess.* (any attribute access on subprocess)
  • shutil.*     (any attribute access on shutil)
  • socket.*     (any attribute access on socket)
  • ctypes.*     (any attribute access on ctypes)
  • __import__() as a bare call
  • builtins.__import__
  • open()  in write/append modes ('w','a','wb','ab','x','xb')

Public API
──────────
  ExecBlocked(Exception)   – raised when forbidden code is detected
  check_exec_safety(source: str) -> tuple[bool, list[str]]
      Returns (True, []) when safe, (False, [reason, ...]) when blocked.
      FAILS CLOSED: any parse error returns (False, [reason]).
"""

from __future__ import annotations

import ast
from typing import List, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Forbidden module names (any attribute access on these is banned)
# ─────────────────────────────────────────────────────────────────────────────
_FORBIDDEN_MODULES = frozenset({
    "subprocess", "shutil", "socket", "ctypes",
})

# Forbidden attribute names on the `os` module
_FORBIDDEN_OS_ATTRS = frozenset({
    "system", "popen", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe",
    "spawnv", "spawnve", "spawnvp", "spawnvpe",
    "popen2", "popen3", "popen4",
})

# Open-mode characters that imply write / create
_WRITE_MODES = frozenset({"w", "a", "x", "wb", "ab", "xb", "wt", "at", "xt"})


# ─────────────────────────────────────────────────────────────────────────────
# Exception
# ─────────────────────────────────────────────────────────────────────────────

class ExecBlocked(Exception):
    """Raised when check_exec_safety() detects forbidden patterns."""

    def __init__(self, reasons: List[str]) -> None:
        self.reasons = reasons
        super().__init__(
            "ExecBlocked: dangerous code detected — " + "; ".join(reasons)
        )


# ─────────────────────────────────────────────────────────────────────────────
# AST visitor
# ─────────────────────────────────────────────────────────────────────────────

class ForbiddenNodeVisitor(ast.NodeVisitor):
    """Walks an AST and collects descriptions of forbidden constructs."""

    def __init__(self) -> None:
        self.violations: List[str] = []

    # ── Helper ────────────────────────────────────────────────────────────────
    def _lineno(self, node: ast.AST) -> str:
        ln = getattr(node, "lineno", "?")
        return f"line {ln}"

    # ── Import checks ─────────────────────────────────────────────────────────
    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            root = alias.name.split(".")[0]
            if root in _FORBIDDEN_MODULES or root == "os":
                # os itself is allowed; we'll catch os.system at call sites.
                if root in _FORBIDDEN_MODULES:
                    self.violations.append(
                        f"{self._lineno(node)}: import of forbidden module '{root}'"
                    )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        root = module.split(".")[0]
        if root in _FORBIDDEN_MODULES:
            self.violations.append(
                f"{self._lineno(node)}: from-import of forbidden module '{root}'"
            )
        # from os import system  etc.
        if root == "os":
            for alias in node.names:
                if alias.name in _FORBIDDEN_OS_ATTRS:
                    self.violations.append(
                        f"{self._lineno(node)}: forbidden import 'os.{alias.name}'"
                    )
        self.generic_visit(node)

    # ── Call checks ───────────────────────────────────────────────────────────
    def visit_Call(self, node: ast.Call) -> None:
        func = node.func

        # __import__("subprocess") bare call
        if isinstance(func, ast.Name) and func.id == "__import__":
            self.violations.append(
                f"{self._lineno(node)}: bare __import__() call is forbidden"
            )

        # Attribute calls: os.system(...), subprocess.run(...), etc.
        elif isinstance(func, ast.Attribute):
            obj = func.value
            attr = func.attr

            # os.<dangerous_attr>(...)
            if isinstance(obj, ast.Name) and obj.id == "os":
                if attr in _FORBIDDEN_OS_ATTRS:
                    self.violations.append(
                        f"{self._lineno(node)}: forbidden call 'os.{attr}()'"
                    )

            # builtins.__import__(...)
            elif isinstance(obj, ast.Name) and obj.id == "builtins" and attr == "__import__":
                self.violations.append(
                    f"{self._lineno(node)}: forbidden call 'builtins.__import__()'"
                )

            # <forbidden_module>.<anything>(...)
            elif isinstance(obj, ast.Name) and obj.id in _FORBIDDEN_MODULES:
                self.violations.append(
                    f"{self._lineno(node)}: forbidden call '{obj.id}.{attr}()'"
                )

            # open(..., 'w') / open(..., mode='w') write-mode detection
            elif isinstance(func, ast.Attribute) and func.attr == "open":
                self._check_open_mode(node)
            elif isinstance(func, ast.Name) and getattr(func, "id", "") == "open":
                self._check_open_mode(node)

        # open(...) as Name call
        elif isinstance(func, ast.Name) and func.id == "open":
            self._check_open_mode(node)

        self.generic_visit(node)

    def _check_open_mode(self, node: ast.Call) -> None:
        """Detect open() called with a write/append/create mode."""
        # Positional arg[1] or keyword mode=
        mode_val: str | None = None
        if len(node.args) >= 2:
            arg = node.args[1]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                mode_val = arg.value
        for kw in node.keywords:
            if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                mode_val = str(kw.value.value)
        if mode_val and any(m in mode_val for m in ("w", "a", "x")):
            self.violations.append(
                f"{self._lineno(node)}: open() called with write/create mode '{mode_val}'"
            )


# ─────────────────────────────────────────────────────────────────────────────
# Public function
# ─────────────────────────────────────────────────────────────────────────────

def check_exec_safety(source: str) -> Tuple[bool, List[str]]:
    """
    Statically analyse *source* with an AST visitor and determine whether
    it is safe to execute.

    Parameters
    ----------
    source : str
        Python source code to inspect.

    Returns
    -------
    (is_safe, reasons)
        ``is_safe`` is True only when no forbidden patterns were found.
        ``reasons`` is an empty list when safe; otherwise a list of human-
        readable violation descriptions.

    Fail-closed
    -----------
    Any error during parsing or analysis is treated as a violation, so the
    caller must explicitly receive ``True`` to proceed with execution.
    """
    if not source or not source.strip():
        return False, ["empty source code cannot be executed"]

    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return False, [f"source code has syntax error: {exc}"]
    except Exception as exc:
        return False, [f"AST parse failed: {exc}"]

    try:
        visitor = ForbiddenNodeVisitor()
        visitor.visit(tree)
        violations = visitor.violations
    except Exception as exc:
        return False, [f"AST inspection failed: {exc}"]

    if violations:
        return False, violations
    return True, []
