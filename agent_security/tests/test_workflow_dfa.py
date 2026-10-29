"""
agent_security/tests/test_workflow_dfa.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar-2 self-tests for WorkflowDFA.
Run from the project root:
    python agent_security/tests/test_workflow_dfa.py
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Force UTF-8 output so Unicode symbols (arrows, box-drawing) work on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from agent_security.workflow_dfa import (
    WorkflowDFA, WorkflowViolation, DFAState,
    ACCEPTING_STATES, render_dot, render_table,
)

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
print("  agent_security Pillar-2 — WorkflowDFA self-tests")
print("=" * 65)

# ── Test 1: Initial state ─────────────────────────────────────────────────────
print("\n[1] Initial state")
dfa = WorkflowDFA()
check("1a initial state is START", dfa.state is DFAState.START)
check("1b not trapped initially", not dfa.is_trapped)
check("1c not accepted initially", not dfa.is_accepted)
check("1d history is empty",       len(dfa.history) == 0)

# ── Test 2: Full happy-path walk ──────────────────────────────────────────────
print("\n[2] Full happy-path: validate->parse->graph->green_audit->audit->profile->summarize")
dfa2 = WorkflowDFA()
steps = [
    ("validate",    DFAState.HEALED),
    ("parse",       DFAState.AST_VERIFIED),
    ("graph",       DFAState.PDG_BUILT),
    ("green_audit", DFAState.PDG_BUILT),     # self-loop
    ("audit",       DFAState.SECURITY_AUDITED),
    ("profile",     DFAState.SECURITY_AUDITED),  # self-loop
    ("summarize",   DFAState.SECURITY_AUDITED),  # self-loop
]
for ev, expected in steps:
    got = dfa2.step(ev)
    check(f"2 step({ev!r}) → {expected.value}", got is expected, f"got {got.value}")

check("2 is_accepted after happy path", dfa2.is_accepted)
check("2 not trapped after happy path", not dfa2.is_trapped)
check("2 history length correct",       len(dfa2.history) == len(steps),
      f"len={len(dfa2.history)}")

# ── Test 3: optimize transitions to OPTIMIZED ─────────────────────────────────
print("\n[3] optimize event from SECURITY_AUDITED → OPTIMIZED")
dfa3 = WorkflowDFA()
for ev in ["validate", "parse", "graph", "audit"]:
    dfa3.step(ev)
result = dfa3.step("optimize")
check("3a OPTIMIZED state reached", result is DFAState.OPTIMIZED)
check("3b is_accepted",             dfa3.is_accepted)

# ── Test 4: out-of-order → TRAP ───────────────────────────────────────────────
print("\n[4] Out-of-order event: audit before parse → TRAP")
dfa4 = WorkflowDFA()
dfa4.step("validate")   # HEALED
result = dfa4.step("audit")  # skipped parse/graph — must go to TRAP
check("4a result is TRAP",  result is DFAState.TRAP)
check("4b is_trapped",      dfa4.is_trapped)
check("4c not is_accepted", not dfa4.is_accepted)

# ── Test 5: TRAP is absorbing ─────────────────────────────────────────────────
print("\n[5] TRAP is absorbing: every subsequent event stays in TRAP")
dfa5 = WorkflowDFA()
dfa5.step("audit")  # illegal from START → TRAP
for ev in ["validate", "parse", "graph", "audit", "summarize"]:
    state = dfa5.step(ev)
    check(f"5 TRAP absorbs '{ev}'", state is DFAState.TRAP)

# ── Test 6: require() is a dry-check — state unchanged ───────────────────────
print("\n[6] require() dry-check: state unchanged on violation")
dfa6 = WorkflowDFA()
dfa6.step("validate")   # HEALED
try:
    dfa6.require("summarize")   # illegal from HEALED
    check("6a WorkflowViolation raised", False, "no exception raised")
except WorkflowViolation as exc:
    check("6a WorkflowViolation raised",    True)
    check("6b exc.from_state is HEALED",    exc.from_state is DFAState.HEALED,
          f"from_state={exc.from_state}")
    check("6c exc.event is 'summarize'",    exc.event == "summarize",
          f"event={exc.event!r}")
check("6d state unchanged after require()", dfa6.state is DFAState.HEALED,
      f"state={dfa6.state}")

# ── Test 7: require() passes silently on legal event ─────────────────────────
print("\n[7] require() is silent when event is legal")
dfa7 = WorkflowDFA()
dfa7.step("validate")
try:
    dfa7.require("parse")    # legal next step
    check("7a no exception on legal require()", True)
except WorkflowViolation:
    check("7a no exception on legal require()", False)
check("7b state unchanged after legal require()", dfa7.state is DFAState.HEALED)

# ── Test 8: require() raises on TRAP ─────────────────────────────────────────
print("\n[8] require() raises WorkflowViolation when already in TRAP")
dfa8 = WorkflowDFA()
dfa8.step("audit")  # → TRAP
try:
    dfa8.require("validate")
    check("8a WorkflowViolation raised from TRAP", False)
except WorkflowViolation:
    check("8a WorkflowViolation raised from TRAP", True)

# ── Test 9: reset() restores state and clears history ────────────────────────
print("\n[9] reset()")
dfa9 = WorkflowDFA()
dfa9.step("validate")
dfa9.step("audit")   # → TRAP
dfa9.reset()
check("9a state is START after reset()", dfa9.state is DFAState.START)
check("9b history cleared after reset()", len(dfa9.history) == 0)
check("9c not trapped after reset()",    not dfa9.is_trapped)

# ── Test 10: render_dot() and render_table() produce non-empty strings ────────
print("\n[10] render_dot() and render_table()")
dot = render_dot()
table = render_table()
check("10a render_dot() non-empty",          len(dot) > 100)
check("10b render_dot() contains digraph",   "digraph" in dot)
check("10c render_dot() contains TRAP",      "TRAP" in dot)
check("10d render_dot() has accepting node", "doublecircle" in dot)
check("10e render_table() non-empty",        len(table) > 50)
check("10f render_table() has TRAP row",     "TRAP" in table)
check("10g render_table() has all events",   all(ev in table for ev in
      ["validate","parse","graph","green_audit","audit","summarize","profile","optimize"]))

# ── Test 11: unknown event → TRAP ────────────────────────────────────────────
print("\n[11] Unknown event from START → TRAP")
dfa11 = WorkflowDFA()
result = dfa11.step("totally_unknown_event")
check("11a unknown event goes to TRAP", result is DFAState.TRAP)

# ── Test 12: history records all transitions ──────────────────────────────────
print("\n[12] History integrity")
dfa12 = WorkflowDFA()
dfa12.step("validate")   # (START, validate, HEALED)
dfa12.step("parse")      # (HEALED, parse, AST_VERIFIED)
h = dfa12.history
check("12a history has 2 entries", len(h) == 2, f"len={len(h)}")
check("12b first entry from_state is START",       h[0][0] is DFAState.START)
check("12c first entry event is 'validate'",       h[0][1] == "validate")
check("12d first entry to_state is HEALED",        h[0][2] is DFAState.HEALED)
check("12e second entry from_state is HEALED",     h[1][0] is DFAState.HEALED)
check("12f history is a copy (not internal list)", h is not dfa12.history)

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("=" * 65)
if errors:
    print(f"  {len(errors)} TEST(S) FAILED: {errors}")
    sys.exit(1)
else:
    print("  ALL TESTS PASSED")
print("=" * 65)
