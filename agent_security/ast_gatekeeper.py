"""
agent_security/ast_gatekeeper.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3A — Pre-Execution AST Gatekeeper.

Performs static analysis using an explicit ITERATIVE traversal of the AST
before any execution occurs. Resolves import aliases, identifies forbidden
calls, modules, dangerous os attributes, write operations, and dunder access.

Public API:
  Violation(rule_id, description, lineno)
  GatekeeperReport(is_safe, violations, block_reasons)
  scan(source_code: str) -> GatekeeperReport
"""

from __future__ import annotations

import ast
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# Blocklists
# ─────────────────────────────────────────────────────────────────────────────

FORBIDDEN_MODULES: frozenset = frozenset({
    "subprocess",
    "shutil",
    "socket",
    "ctypes",
    "pty",
    "telnetlib",
    "ftplib",
    "smtplib",
    "http.server",
    "xmlrpc",
    "multiprocessing",
    "_posixsubprocess",
})

FORBIDDEN_OS_ATTRS: frozenset = frozenset({
    "system",
    "popen",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "spawnl",
    "spawnle",
    "spawnlp",
    "spawnlpe",
    "spawnv",
    "spawnve",
    "spawnvp",
    "spawnvpe",
    "popen2",
    "popen3",
    "popen4",
    "kill",
    "killpg",
    "remove",
    "unlink",
    "rmdir",
    "removedirs",
})

FORBIDDEN_CALLS: frozenset = frozenset({
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
})

FORBIDDEN_DUNDERS: frozenset = frozenset({
    "__subclasses__",
    "__bases__",
    "__class__",
    "__globals__",
    "__code__",
    "__reduce__",
    "__reduce_ex__",
    "__builtins__",
    "__import__",
})

_WRITE_MODES: frozenset = frozenset({
    "w", "a", "x", "wb", "ab", "xb", "wt", "at", "xt",
    "w+", "a+", "x+", "w+b", "a+b", "x+b", "r+", "r+b"
})


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Violation:
    rule_id: str
    description: str
    lineno: int = 0


@dataclass
class GatekeeperReport:
    is_safe: bool
    violations: List[Violation] = field(default_factory=list)
    block_reasons: List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Iterative Scanner
# ─────────────────────────────────────────────────────────────────────────────

def scan(source_code: str) -> GatekeeperReport:
    """
    Statically inspect *source_code* using an iterative traversal over its AST.
    Resolves import aliases and checks for all forbidden modules, calls,
    os attributes, dunders, and dangerous file operations.

    Returns a GatekeeperReport carrying `is_safe`, `violations`, and `block_reasons`.
    Fails closed on empty source or parsing errors.
    """
    if not source_code or not source_code.strip():
        v = Violation(
            rule_id="GATE-EMPTY",
            description="Empty source code cannot be verified",
            lineno=0,
        )
        return GatekeeperReport(is_safe=False, violations=[v], block_reasons=[v.description])

    try:
        tree = ast.parse(source_code)
    except SyntaxError as exc:
        v = Violation(
            rule_id="GATE-SYNTAX",
            description=f"Source code has syntax error: {exc}",
            lineno=getattr(exc, "lineno", 0) or 0,
        )
        return GatekeeperReport(is_safe=False, violations=[v], block_reasons=[v.description])
    except Exception as exc:
        v = Violation(
            rule_id="GATE-PARSE-FAIL",
            description=f"AST parse failed: {exc}",
            lineno=0,
        )
        return GatekeeperReport(is_safe=False, violations=[v], block_reasons=[v.description])

    # Alias tracking:
    # module_aliases: local_name -> canonical_module_name (e.g. 'my_os' -> 'os')
    module_aliases: Dict[str, str] = {}
    # func_aliases: local_name -> (canonical_module_name, func_name) (e.g. 'sys_call' -> ('os', 'system'))
    func_aliases: Dict[str, Tuple[str, str]] = {}

    violations: List[Violation] = []

    # Iterative BFS traversal using collections.deque (no recursion)
    queue: deque = deque([tree])

    while queue:
        node = queue.popleft()
        lineno = getattr(node, "lineno", 0)

        # 1. Imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                real_name = alias.name
                as_name = alias.asname or real_name
                root_pkg = real_name.split(".")[0]
                module_aliases[as_name] = real_name

                if root_pkg in FORBIDDEN_MODULES:
                    violations.append(Violation(
                        rule_id="GATE-FORBIDDEN-MODULE",
                        description=f"line {lineno}: import of forbidden module '{real_name}'",
                        lineno=lineno,
                    ))

        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            root_pkg = module_name.split(".")[0]

            if root_pkg in FORBIDDEN_MODULES:
                violations.append(Violation(
                    rule_id="GATE-FORBIDDEN-MODULE",
                    description=f"line {lineno}: from-import of forbidden module '{module_name}'",
                    lineno=lineno,
                ))

            for alias in node.names:
                fn_name = alias.name
                as_name = alias.asname or fn_name
                func_aliases[as_name] = (module_name, fn_name)

                # Check if importing forbidden attribute from os
                if root_pkg == "os" and fn_name in FORBIDDEN_OS_ATTRS:
                    violations.append(Violation(
                        rule_id="GATE-FORBIDDEN-OS-ATTR",
                        description=f"line {lineno}: forbidden import of 'os.{fn_name}'",
                        lineno=lineno,
                    ))

        # 2. Calls
        elif isinstance(node, ast.Call):
            func = node.func

            # Direct call by Name
            if isinstance(func, ast.Name):
                fn_id = func.id

                # Forbidden direct call: eval(), exec(), compile(), __import__()
                if fn_id in FORBIDDEN_CALLS:
                    violations.append(Violation(
                        rule_id="GATE-FORBIDDEN-CALL",
                        description=f"line {lineno}: forbidden call '{fn_id}()'",
                        lineno=lineno,
                    ))

                # Check aliased function call: sys_call("...")
                if fn_id in func_aliases:
                    mod_target, fn_target = func_aliases[fn_id]
                    if mod_target.split(".")[0] == "os" and fn_target in FORBIDDEN_OS_ATTRS:
                        violations.append(Violation(
                            rule_id="GATE-FORBIDDEN-OS-ATTR",
                            description=f"line {lineno}: forbidden call '{fn_id}()' resolving to 'os.{fn_target}()'",
                            lineno=lineno,
                        ))
                    elif mod_target.split(".")[0] in FORBIDDEN_MODULES:
                        violations.append(Violation(
                            rule_id="GATE-FORBIDDEN-MODULE",
                            description=f"line {lineno}: forbidden call '{fn_id}()' resolving to '{mod_target}.{fn_target}()'",
                            lineno=lineno,
                        ))

                # Check open() calls for write mode
                if fn_id == "open":
                    _check_open_call(node, lineno, violations)

            # Attribute call: obj.attr()
            elif isinstance(func, ast.Attribute):
                attr_name = func.attr

                # Check dunder call: obj.__subclasses__()
                if attr_name in FORBIDDEN_DUNDERS:
                    violations.append(Violation(
                        rule_id="GATE-FORBIDDEN-DUNDER",
                        description=f"line {lineno}: forbidden dunder call '.{attr_name}()'",
                        lineno=lineno,
                    ))

                # Check calls on modules/aliases: os.system(), my_os.system()
                if isinstance(func.value, ast.Name):
                    target_name = func.value.id
                    canonical_mod = module_aliases.get(target_name, target_name)
                    root_mod = canonical_mod.split(".")[0]

                    if root_mod == "os" and attr_name in FORBIDDEN_OS_ATTRS:
                        violations.append(Violation(
                            rule_id="GATE-FORBIDDEN-OS-ATTR",
                            description=f"line {lineno}: forbidden call '{target_name}.{attr_name}()' on module 'os'",
                            lineno=lineno,
                        ))
                    elif root_mod in FORBIDDEN_MODULES:
                        violations.append(Violation(
                            rule_id="GATE-FORBIDDEN-MODULE",
                            description=f"line {lineno}: forbidden call on module '{canonical_mod}.{attr_name}()'",
                            lineno=lineno,
                        ))
                    elif root_mod == "builtins" and attr_name in FORBIDDEN_CALLS:
                        violations.append(Violation(
                            rule_id="GATE-FORBIDDEN-CALL",
                            description=f"line {lineno}: forbidden call 'builtins.{attr_name}()'",
                            lineno=lineno,
                        ))

                # Check open calls via attribute (e.g. io.open or file.open)
                if attr_name == "open":
                    _check_open_call(node, lineno, violations)

        # 3. Attribute accesses (catching dunder access even without direct call, e.g. obj.__class__.__bases__)
        elif isinstance(node, ast.Attribute):
            if node.attr in FORBIDDEN_DUNDERS:
                violations.append(Violation(
                    rule_id="GATE-FORBIDDEN-DUNDER",
                    description=f"line {lineno}: forbidden dunder access '.{node.attr}'",
                    lineno=lineno,
                ))

        # Enqueue child nodes for iterative exploration
        for child in ast.iter_child_nodes(node):
            queue.append(child)

    reasons = [v.description for v in violations]
    return GatekeeperReport(
        is_safe=len(violations) == 0,
        violations=violations,
        block_reasons=reasons,
    )


def _check_open_call(node: ast.Call, lineno: int, violations: List[Violation]) -> None:
    """Helper to detect open() with write or append modes."""
    mode_val: str | None = None
    if len(node.args) >= 2:
        arg = node.args[1]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            mode_val = arg.value
    for kw in node.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode_val = str(kw.value.value)

    if mode_val and any(m in mode_val for m in ("w", "a", "x", "+")):
        violations.append(Violation(
            rule_id="GATE-FILE-WRITE",
            description=f"line {lineno}: open() called with write/create mode '{mode_val}'",
            lineno=lineno,
        ))
