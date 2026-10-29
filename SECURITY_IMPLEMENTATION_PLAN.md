# Agent Security Hardening — Implementation Plan & Progress Tracker
<!--
  Status indicators:
  [x] COMPLETE
  [/] IN PROGRESS / PARTIAL
  [ ] NOT STARTED / MISSING
-->

Comprehensive tracking document for closing all remaining gaps identified in the 44-point security audit.

---

## Executive Summary & Audit Baseline
- **Audit Date:** October 29, 2026
- **Current Score:** **44 DONE / 0 PARTIAL / 0 MISSING** (out of 44 requirements — 100% COMPLETE)
- **Goal:** Full sandbox isolation, comprehensive input limits, 0 in-process code execution, Red-Team test suite, and complete architectural documentation.

---

## Master Checklist (44 Items)

### A. Package and Config
- [x] **#1** `agent_security/` package directory exists with `__init__.py`
- [x] **#2** `config.py` defines all 7 constants (`MAX_SOURCE_BYTES`, `MAX_LINE_LENGTH`, `MAX_NESTING_DEPTH`, `MAX_AST_DEPTH`, `PROFILER_TIMEOUT_SECONDS`, `PROFILER_MEMORY_LIMIT_MB`, `REGEX_TIMEOUT_SECONDS`)

### B. Pillar 1: Input Shield
- [x] **#3** `SecretVault` has `mask()`, `unmask()`, `count`, `skipped_lines`
- [x] **#4** Secret detection covers: named variables, API tokens (`gsk_`, `hf_`, `sk-`, `AKIA`, `ghp_`), JWTs, PEM blocks, URL credentials
- [x] **#5** `build_enveloped_prompt()` generates random nonce tag attribute AND neutralizes fake closing tags inside code
- [x] **#6** System prompt explicitly instructs the LLM that enveloped code is untrusted data, never instructions
- [x] **#7** HOOK: `model_pipeline.py` masks source code and uses XML prompt envelope
- [x] **#8** HOOK: `optimizer_agent.py` `_generate_candidate_code()` masks input, envelopes prompt, and unmasks returned candidate
- [x] **#9** Zero leakage of real secrets or placeholders to thought traces, stdout, or logs

### C. Pillar 2: DFA Workflow Guard
- [x] **#10** 7 DFA states defined (`START`, `HEALED`, `AST_VERIFIED`, `PDG_BUILT`, `SECURITY_AUDITED`, `OPTIMIZED`, `TRAP`)
- [x] **#11** Exact transition table: `validate`, `parse`, `graph`, `green_audit` (self-loop), `audit`, `summarize` (self-loop), `profile` (self-loop), `optimize`; unlisted transitions lead to absorbing `TRAP`
- [x] **#12** `WorkflowDFA` API complete (`state`, `step()`, `require()`, `is_trapped`, `history`, `reset()`, `WorkflowViolation`, `render_dot()`, `render_table()`)
- [x] **#13** HOOK: `agent_controller.py` attaches DFA to `AgentContext`, steps DFA before each agent, logs thought-trace events on violation
- [x] **#14** HOOK: `optimizer_agent.optimize()` accepts `dfa=None` and invokes `dfa.require("optimize")` and `dfa.step("optimize")`
- [x] **#15** HOOK: `main.py` and `gui_app.py` pass the DFA instance to `optimize_code()`

### D. Pillar 3a: AST Gatekeeper & Sandboxed Profiler
- [x] **#16** `agent_security/ast_gatekeeper.py` exists with `scan()`, `Violation`, and `GatekeeperReport`
- [x] **#17** Gatekeeper uses iterative traversal, resolves import aliases, enforces module, os attribute, dangerous call, and dunder blocklists
- [x] **#18** `hardware_profiler.py` completely eliminates `exec()` in the host process (0 in-process `exec()` calls)
- [x] **#19** `hardware_profiler.py` invokes `scan()` before execution and returns `blocked` (bool) and `block_reasons` (list)
- [x] **#20** Code snippet executes in an isolated subprocess (`shell=False`, `python -I`, minimal env without API keys, temporary clean directory)
- [x] **#21** Subprocess timeout enforced via process-tree termination (`kill()`) and returns `timed_out` (bool)
- [x] **#22** Subprocess memory limit enforced (`RLIMIT_AS` on POSIX and continuous `psutil` watchdog), returning `memory_exceeded` (bool)
- [x] **#23** All 4 keys (`blocked`, `block_reasons`, `timed_out`, `memory_exceeded`) present across every return path of public profiler functions

### E. Pillar 3b: Input Limits & Safe Parsing
- [x] **#24** `agent_security/input_limits.py` exists with `InputRejected`, `check_source`, `check_ast_depth`, and `safe_parse`
- [x] **#25** `check_source()` verifies: file size, null bytes, line length, bracket nesting, operator-chain count
- [x] **#26** `check_ast_depth()` implemented using iterative traversal (no recursion)
- [x] **#27** HOOK: `self_healing.heal()` calls `check_source()` before any regex execution
- [x] **#28** HOOK: `safe_parse()` replaces all raw `ast.parse()` calls across extractors (`ast_extractor`, `pdg_extractor`, `green_computing`, `model_pipeline`, `self_healing`, `optimizer_agent`, `agent_controller`)
- [x] **#29** HOOK: `agent_controller.run_workflow()` catches `InputRejected`, `RecursionError`, `MemoryError`, logs `"INPUT REJECTED"`, and sets error flag

### F. Pillar 3c: Optimizer Firewall
- [x] **#30** `inspect_candidate()` exists, reuses gatekeeper constants, detects new imports, blocklisted calls, new URL/IP literals, dunders, and syntax errors
- [x] **#31** HOOK: `optimize()` audits both the LLM candidate and deterministic fallback with `inspect_candidate()`, returning original code if both fail
- [x] **#32** `OptimizationResult` includes `firewall_passed` (bool) and `firewall_violations` (list); logs `"FIREWALL: blocked candidate"` thought-trace event
- [x] **#33** Optimized code is never automatically applied to disk by CLI or GUI

### G. Pillar 4a: Safe Regex & ReDoS Guard
- [x] **#34** `requirements.txt` contains `regex==2024.11.6`
- [x] **#35** `agent_security/safe_regex.py` provides `safe_search()` with line truncation, timeout, and compiled-pattern LRU cache
- [x] **#36** HOOK: `security_scanner.py` uses `safe_search()` and emits `"Scan degraded"` finding on timeout
- [x] **#37** Verified zero existing scanner patterns contain catastrophic nested quantifiers like `(a+)+`

### H. Pillar 4b: Red-Team Test Suite & Documentation
- [x] **#38** `test_agent_security.py` exists in project root
- [x] **#39** Red-team test suite includes Attacks 1–5, Control baseline test, and DFA sequence test
- [x] **#40** `test_agent_security.py` passes 100% on execution (7/7 tests pass)
- [x] **#41** `docs/AGENT_SECURITY.md` authored with DFA state diagram, threat model matrix, and known limitations

### I. Regression & UI Hardening
- [x] **#42** Full regression test `python main.py --file input_codes/code_1_nested_loops.py --optimize` passes cleanly
- [x] **#43** XSS & HTML escaping: remediated unescaped inline `</script>` interpolation and node label injection in `graph_visualizer.py`
- [x] **#44** Verified API keys from `.env` never leak to logs, UI, or serialized payloads

---

## Phased Execution Roadmap: 100% Complete

```
PHASE 1 (Critical) ──► Subprocess Profiler Sandbox & AST Gatekeeper (#16-#23)    [COMPLETED]
         │
PHASE 2 (High)     ──► Input Limits & Centralized Safe Parsing (#24-#29)          [COMPLETED]
         │
PHASE 3 (Medium)   ──► Optimizer Firewall Hardening & DFA Hooking (#15, #30-#32)  [COMPLETED]
         │
PHASE 4 (Medium)   ──► Safe Regex Engine & Scanner Hardening (#34-#36, #43)       [COMPLETED]
         │
PHASE 5 (Low)      ──► Red-Team Test Expansion & Documentation (#39, #41)         [COMPLETED]
         │
PHASE 6 (Final)    ──► Full Regression Run & Git Commit                           [COMPLETED]
```
