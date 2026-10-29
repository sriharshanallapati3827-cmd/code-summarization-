# Agent Security — Implementation Roadmap & Progress Tracker
<!-- Update status emojis as work completes:
     ✅ Done  🔄 In Progress  ⬜ Not Started  -->

---

## Pillar 1 — Input Privacy & Anti-Hijack Shield  ✅ COMPLETE
**Files created:** `agent_security/__init__.py`, `agent_security/config.py`, `agent_security/input_shield.py`
**Files modified:** `model_pipeline.py`, `optimizer_agent.py`
**Tests:** `agent_security/tests/test_input_shield.py` — 10/10 PASS

| Sub-task | Status |
|---|---|
| `SecretVault` — 4 masking categories, stable placeholders, `unmask()` | ✅ |
| `build_enveloped_prompt()` — nonce, XML envelope, anti-injection system prompt | ✅ |
| Hook: `model_pipeline.py` `generate_summary()` masks before LLM | ✅ |
| Hook: `optimizer_agent.py` `_generate_candidate_code()` masks; `unmask()` on returned code | ✅ |

---

## Pillar 2 — Automata DFA Agent Workflow Guard  ✅ COMPLETE
**Files created:** `agent_security/workflow_dfa.py`
**Files modified:** `agent_controller.py`, `optimizer_agent.py`, `agent_security/__init__.py`
**Tests:** `agent_security/tests/test_workflow_dfa.py` — 12/12 PASS

| Sub-task | Status |
|---|---|
| `WorkflowDFA` — 7 states, 8 events, exact transition table, absorbing TRAP | ✅ |
| `WorkflowViolation` exception carrying `from_state` + `event` | ✅ |
| `render_dot()` and `render_table()` | ✅ |
| Hook: `agent_controller.py` — one DFA per `run_workflow()`, step before each agent | ✅ |
| Hook: `optimizer_agent.py` `optimize(dfa=None)` — `require` + `step` | ✅ |
| `AgentContext.workflow_dfa` + `dfa_trapped` fields (default-safe) | ✅ |

---

## Pillar 3 — Agent Code Hardening & Sandbox  ✅ COMPLETE
**Files created:** `agent_security/exec_guard.py`, `agent_security/nesting_guard.py`, `agent_security/optimizer_firewall.py`, `agent_security/regex_timeout.py`
**Files modified:** `hardware_profiler.py`, `ast_extractor.py`, `self_healing.py`, `optimizer_agent.py`, `security_scanner.py`, `agent_security/__init__.py`
**Tests:** `agent_security/tests/test_pillar3.py`

### What was BUILT

#### 3A — `agent_security/exec_guard.py`  ✅
New file. AST-based static analysis before any `exec()` call.

| Item | Detail |
|---|---|
| `class ForbiddenNodeVisitor(ast.NodeVisitor)` | Walks AST, flags: `os.system`, `subprocess.*`, `shutil.*`, `socket.*`, `ctypes.*`, `builtins.__import__`, `__import__`, `open` in write mode |
| `def check_exec_safety(source: str) -> tuple[bool, list[str]]` | Returns `(is_safe, reasons)`. Fails closed on any parse error. |
| `class ExecBlocked(Exception)` | Carries `reasons` list |

#### 3B — Hook: `hardware_profiler.py` → `profile_code_snippet()`  ✅
Hardening before execution:
- Calls `check_exec_safety(source_code)` before `compile()`
- If unsafe → returns safe blocked metrics dict
- Wraps execution in daemon thread watchdog with `PROFILER_TIMEOUT_SECONDS` (2.0s)
- Adds peak RAM check against `PROFILER_MEMORY_LIMIT_MB` (50MB)

#### 3C — `agent_security/nesting_guard.py`  ✅
New file. Prevents recursion/call-stack exhaustion.

| Item | Detail |
|---|---|
| `def check_nesting_depth(source: str, max_depth: int = MAX_NESTING_DEPTH) -> tuple[bool, int]` | Counts max bracket nesting depth in source string (per-line, no regex). Returns `(is_safe, actual_depth)`. |
| `def check_ast_depth(tree: ast.AST, max_depth: int = MAX_AST_DEPTH) -> tuple[bool, int]` | Walks parsed AST recursively counting depth. Returns `(is_safe, actual_depth)`. |
| `class NestingTooDeep(Exception)` | Carries `actual_depth` |

#### 3D — Hook: `ast_extractor.py` → `extract_ast_context()`  ✅
Change before `ast.parse()`:
- Calls `check_nesting_depth(source_code)` first
- If fails → returns safe error string, no parse attempt

#### 3E — Hook: `self_healing.py` → `heal()`  ✅
Change before `ast.parse()` calls:
- Same `check_nesting_depth` guard returning structured diagnostic error without crash

#### 3F — `agent_security/optimizer_firewall.py`  ✅
New file. AST firewall for LLM-generated optimizer output.

| Item | Detail |
|---|---|
| `SAFE_STDLIB_MODULES` | Whitelist of modules the optimizer is allowed to import |
| `def audit_optimizer_output(source: str) -> tuple[bool, list[str]]` | Parses output AST, checks for new dangerous imports/calls not in whitelist, returns `(is_clean, violations)` |
| `class OptimizerOutputTainted(Exception)` | Carries `violations` list |

#### 3G — Hook: `optimizer_agent.py` → `_generate_candidate_code()`  ✅
Change after `extracted = self._extract_code_block(response_text)`:
- Calls `audit_optimizer_output(extracted, original_source=source_code)` before `self._can_parse()`
- If tainted → falls through to deterministic fallback (never return tainted code)

---

## Session B — Regex Timeout / ReDoS Guard  ✅ COMPLETE
**Files created:** `agent_security/regex_timeout.py`
**Files modified:** `security_scanner.py`, `agent_security/__init__.py`

| Item | Detail | Status |
|---|---|---|
| `agent_security/regex_timeout.py` | Thread-based `timed_search()` and `timed_match()` wrappers with `REGEX_TIMEOUT_SECONDS` (0.5s) | ✅ |
| Hook: `security_scanner.py` | Replaces bare `re.search(pattern, line)` with `timed_search(pattern, line)` | ✅ |


---

## Pillar 4 — Red-Team Test Suite  ✅ COMPLETE

**File created:** `test_agent_security.py` (project root)

| Attack | Target | Defence | Status |
|---|---|---|---|
| 1. Host Command Injection (`os.system("rm -rf /")`) | `hardware_profiler.py` `profile_code_snippet()` | AST Gatekeeper (3B) | ✅ |
| 2. Indirect Prompt Injection in docstring | `optimizer_agent.py` LLM call | XML Envelope (Pillar 1) | ✅ |
| 3. Recursion Depth Bomb (`((((1))))*2000`) | `ast_extractor.py` `extract_ast_context()` | Nesting Limiter (3C/3D) | ✅ |
| 4. Memory Allocation Bomb (`x = [0]*10**9`) | `hardware_profiler.py` `profile_code_snippet()` | RAM + Timeout Watchdog (3B) | ✅ |
| 5. ReDoS Backtracking String | `security_scanner.py` | Regex Timeout Guard (Session B) | ✅ |

---

## Execution Order (token-efficient, each session is one self-contained task)

```
SESSION A  →  Build Pillar 3 (exec_guard + nesting_guard + optimizer_firewall + 4 hooks)
SESSION B  →  Build Attack-5 regex guard (regex_timeout.py + hook in security_scanner.py)
SESSION C  →  Build Pillar 4 test suite (test_agent_security.py, all 5 attacks)
SESSION D  →  Final regression run + git push
```

---

## Git Log

| Commit | Description |
|---|---|
| `5fdbab9` | feat(security): Pillar 1 – Input Privacy & Anti-Hijack Shield |
| `3d7cf1a` | feat(security): Pillar 2 – DFA Agent Workflow Guard |
| `b740722` | feat(security): Pillar 3 & 4 – Agent Hardening, ReDoS Guard, and Red-Team Test Suite |
