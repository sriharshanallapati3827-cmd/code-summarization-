"""
Pillar-3 self-tests for agent_security code hardening & sandbox.
Covers:
  - 3A: exec_guard (check_exec_safety, ForbiddenNodeVisitor, ExecBlocked)
  - 3B: hardware_profiler hook (AST gatekeeper, timeout, memory ceiling)
  - 3C: nesting_guard (check_nesting_depth, check_ast_depth, NestingTooDeep)
  - 3D: ast_extractor hook (pre-parse nesting check)
  - 3E: self_healing hook (pre-parse nesting check)
  - 3F: optimizer_firewall (audit_optimizer_output, SAFE_STDLIB_MODULES)
  - 3G: optimizer_agent hook (candidate rejection & fallback on tainted code)

Run from project root:
    python agent_security/tests/test_pillar3.py
"""
import sys
import os
import ast

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from agent_security.exec_guard import check_exec_safety, ForbiddenNodeVisitor, ExecBlocked
from agent_security.nesting_guard import check_nesting_depth, check_ast_depth, NestingTooDeep
from agent_security.optimizer_firewall import audit_optimizer_output, SAFE_STDLIB_MODULES, OptimizerOutputTainted
from hardware_profiler import HardwareProfiler
from ast_extractor import extract_ast_context
from self_healing import SelfHealingAgent
from optimizer_agent import GreenSecureOptimizer

PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
errors = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        print(f"{PASS}  {name}")
    else:
        msg = f"{FAIL}  {name}" + (f" | {detail}" if detail else "")
        print(msg)
        errors.append(name)


print("=" * 65)
print("  agent_security Pillar-3 — Code Hardening & Sandbox Tests")
print("=" * 65)

# ── 3A: exec_guard tests ───────────────────────────────────────────────────────
print("\n[3A] exec_guard: AST static safety gatekeeper")
safe_code = "def add(a, b):\n    return a + b\nresult = add(2, 3)\n"
is_safe, reasons = check_exec_safety(safe_code)
check("3A.1 safe code passes", is_safe and len(reasons) == 0)

is_safe, reasons = check_exec_safety("import os\nos.system('echo hi')")
check("3A.2 os.system blocked", not is_safe and any("os.system" in r for r in reasons))

is_safe, reasons = check_exec_safety("from os import system\nsystem('echo hi')")
check("3A.3 from os import system blocked", not is_safe and any("system" in r for r in reasons))

is_safe, reasons = check_exec_safety("import subprocess\nsubprocess.run(['ls'])")
check("3A.4 subprocess import blocked", not is_safe and any("subprocess" in r for r in reasons))

is_safe, reasons = check_exec_safety("import shutil\nshutil.rmtree('/tmp')")
check("3A.5 shutil blocked", not is_safe and any("shutil" in r for r in reasons))

is_safe, reasons = check_exec_safety("import socket\ns = socket.socket()")
check("3A.6 socket blocked", not is_safe and any("socket" in r for r in reasons))

is_safe, reasons = check_exec_safety("import ctypes\nctypes.CDLL(None)")
check("3A.7 ctypes blocked", not is_safe and any("ctypes" in r for r in reasons))

is_safe, reasons = check_exec_safety("mod = __import__('os')")
check("3A.8 bare __import__ blocked", not is_safe and any("__import__" in r for r in reasons))

is_safe, reasons = check_exec_safety("import builtins\nbuiltins.__import__('os')")
check("3A.9 builtins.__import__ blocked", not is_safe and any("builtins.__import__" in r for r in reasons))

is_safe, reasons = check_exec_safety("f = open('test.txt', 'w')")
check("3A.10 open with write mode blocked", not is_safe and any("open" in r for r in reasons))

is_safe, reasons = check_exec_safety("f = open('test.txt', mode='a')")
check("3A.11 open with keyword mode='a' blocked", not is_safe and any("open" in r for r in reasons))

is_safe, reasons = check_exec_safety("f = open('test.txt', 'r')")
check("3A.12 open with read mode allowed", is_safe and len(reasons) == 0)

is_safe, reasons = check_exec_safety("def broken(: pass")
check("3A.13 syntax error fails closed", not is_safe and any("syntax error" in r.lower() for r in reasons))


# ── 3B: hardware_profiler hook tests ──────────────────────────────────────────
print("\n[3B] hardware_profiler: AST gatekeeper, timeout & memory watchdog")
profiler = HardwareProfiler()

# AST Gatekeeper in profiler
p_res = profiler.profile_code_snippet("import os\nos.system('echo test')")
check("3B.1 malicious code blocked before exec", p_res.get('status') == 'blocked')
check("3B.2 backend indicates AST gatekeeper", p_res.get('profiler_backend') == 'blocked-by-ast-gatekeeper')

# Safe snippet execution
p_safe = profiler.profile_code_snippet("total = sum(i for i in range(1000))")
check("3B.3 safe snippet succeeds", p_safe.get('status') == 'ok' and p_safe.get('error') is None)

# Watchdog timeout test (long running code should timeout at PROFILER_TIMEOUT_SECONDS)
p_timeout = profiler.profile_code_snippet("import time\ntime.sleep(2.5)")
check("3B.4 long running execution caught by timeout watchdog", p_timeout.get('status') == 'timeout')

# Memory watchdog test (allocating > 50MB should flag memory_exceeded)
p_mem = profiler.profile_code_snippet("buf = bytearray(55 * 1024 * 1024)")
check("3B.5 large memory allocation caught by memory ceiling", p_mem.get('status') == 'memory_exceeded')


# ── 3C: nesting_guard tests ───────────────────────────────────────────────────
print("\n[3C] nesting_guard: Syntactic & AST depth limiters")
safe_code = "a = (1 + (2 * (3 + 4)))"
is_safe, depth = check_nesting_depth(safe_code, max_depth=40)
check("3C.1 moderate nesting safe", is_safe and depth == 3)

bomb_code = "(" * 50 + "1" + ")" * 50
is_safe, depth = check_nesting_depth(bomb_code, max_depth=40)
check("3C.2 bracket bomb detected", not is_safe and depth >= 40)

# Check AST depth
tree_safe = ast.parse("x = 1 + 2")
is_safe, ast_depth = check_ast_depth(tree_safe, max_depth=100)
check("3C.3 normal AST depth safe", is_safe and ast_depth < 100)

tree_nested = ast.parse("x = " + "+".join(f"({i})" for i in range(120)))
is_safe, ast_depth = check_ast_depth(tree_nested, max_depth=50)
check("3C.4 deep AST detected", not is_safe and ast_depth >= 50)


# ── 3D: ast_extractor hook tests ──────────────────────────────────────────────
print("\n[3D] ast_extractor hook: Pre-parse nesting check")
normal_code = "def hello():\n    return 'world'"
normal_ctx = extract_ast_context(normal_code)
check("3D.1 normal code extracted", "Functions" in normal_ctx or "hello" in normal_ctx)

bomb_code = "x = " + "(" * 60 + "42" + ")" * 60
bomb_ctx = extract_ast_context(bomb_code)
check("3D.2 bomb input rejected before parse", "AST parsing rejected: nesting depth" in bomb_ctx)


# ── 3E: self_healing hook tests ───────────────────────────────────────────────
print("\n[3E] self_healing hook: Pre-parse nesting check")
healer = SelfHealingAgent()
heal_res = healer.heal(bomb_code)
check("3E.1 bomb input blocked by self healer", heal_res.get('status') == 'blocked')
check("3E.2 diagnosis contains NestingTooDeep", any(e.get('type') == 'NestingTooDeep' for e in heal_res.get('errors_diagnosed', [])))

normal_repair = healer.heal("def foo():\n    print('ok')")
check("3E.3 normal code accepted by self healer", normal_repair.get('status') == 'valid')


# ── 3F: optimizer_firewall tests ──────────────────────────────────────────────
print("\n[3F] optimizer_firewall: AST firewall for optimizer output")
clean_opt = """
import math
from collections import deque

def calc(numbers):
    d = deque(numbers)
    return [math.sqrt(x) for x in d]
"""
is_clean, violations = audit_optimizer_output(clean_opt)
check("3F.1 clean optimizer output accepted", is_clean and len(violations) == 0)

tainted_opt = """
import os

def calc(numbers):
    os.system('cat /etc/passwd')
    return numbers
"""
is_clean, violations = audit_optimizer_output(tainted_opt)
check("3F.2 tainted optimizer output with os.system rejected", not is_clean and len(violations) > 0)

tainted_eval = """
def run(code_str):
    return eval(code_str)
"""
is_clean, violations = audit_optimizer_output(tainted_eval)
check("3F.3 eval in optimizer output rejected", not is_clean and any("eval" in v for v in violations))

unapproved_module = """
import urllib.request

def fetch():
    return urllib.request.urlopen('http://example.com')
"""
is_clean, violations = audit_optimizer_output(unapproved_module)
check("3F.4 unapproved new module rejected", not is_clean and any("urllib" in v for v in violations))

# If module and URL were already in original code, they should be allowed
is_clean_orig, _ = audit_optimizer_output(unapproved_module, original_source="import urllib.request\n# existing http://example.com")
check("3F.5 module already in original source is allowed", is_clean_orig)


# ── 3G: optimizer_agent hook tests ────────────────────────────────────────────
print("\n[3G] optimizer_agent hook: Candidate rejection and fallback on tainted LLM code")
opt_agent = GreenSecureOptimizer()
opt_agent.api_key = "mock_key"

original_input = "def compute():\n    x = []\n    for i in range(10):\n        x.append(i)\n    return x\n"

# Mock _call_llm to return tainted code containing os.system
opt_agent._call_llm = lambda prompt, system_prompt=None: "```python\nimport os\ndef compute():\n    os.system('id')\n    return []\n```"

candidate = opt_agent._generate_candidate_code(original_input, {}, {})
# Since LLM output was tainted, candidate must NOT contain os.system; it should fall back to deterministic rules
check("3G.1 tainted LLM output rejected by optimizer agent", "os.system" not in candidate)

# Mock _call_llm to return clean optimized code
opt_agent._call_llm = lambda prompt, system_prompt=None: "```python\ndef compute():\n    return list(range(10))\n```"
clean_candidate = opt_agent._generate_candidate_code(original_input, {}, {})
check("3G.2 clean LLM output accepted by optimizer agent", "return list(range(10))" in clean_candidate)


# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "=" * 65)
if not errors:
    print(f"  {PASS} ALL PILLAR-3 TESTS PASSED")
else:
    print(f"  {FAIL} {len(errors)} TEST(S) FAILED:")
    for err in errors:
        print(f"    - {err}")
print("=" * 65)

if errors:
    sys.exit(1)
