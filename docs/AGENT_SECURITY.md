# Autonomous Agent Pipeline Security Architecture

This document describes the multi-layered security architecture protecting the Autonomous Code Summarization & Optimization Agent pipeline against hostile source code, prompt injection, arbitrary code execution, denial-of-service, and LLM-assisted supply-chain poisoning.

---

## Architecture Overview: The Four Pillars

```
                      [ Untrusted Source Code ]
                                  │
                                  ▼
      ┌────────────────────────────────────────────────────────┐
      │  Pillar 1: Input Privacy & Anti-Hijack Shield          │
      │  • SecretVault: mask() API keys, JWTs, PEM certs       │
      │  • Nonce Enveloping: <user_code nonce="...">...</...>   │
      └───────────────────────────┬────────────────────────────┘
                                  │
                                  ▼
      ┌────────────────────────────────────────────────────────┐
      │  Pillar 2: Automata DFA Agent Workflow Guard           │
      │  • 7-state deterministic finite state machine          │
      │  • Enforces sequential lifecycle; TRAP is absorbing    │
      └───────────────────────────┬────────────────────────────┘
                                  │
                                  ▼
      ┌────────────────────────────────────────────────────────┐
      │  Pillar 3: AST Gatekeeper, Subprocess Sandbox & Limits │
      │  • 3A/3B: Subprocess isolation (`python -I`), BFS AST  │
      │  • 3C: Input limits (500KB, nesting depth, op chains)  │
      │  • 3D: Optimizer Firewall: diff auditing on candidates │
      └───────────────────────────┬────────────────────────────┘
                                  │
                                  ▼
      ┌────────────────────────────────────────────────────────┐
      │  Pillar 4: ReDoS Guard & Security Scanner Hardening    │
      │  • LRU regex pattern cache, native C timeout, max len  │
      │  • CWE-1333 graceful degradation findings              │
      │  • vis.js script-tag escaping and HTML sanitization    │
      └────────────────────────────────────────────────────────┘
```

---

## Pillar 1: Input Privacy & Anti-Hijack Shield (`agent_security/input_shield.py`)

1. **`SecretVault`**:
   - Detects and masks credentials (AWS keys `AKIA...`, OpenAI tokens `sk-...`, Groq tokens `gsk_...`, HuggingFace `hf_...`, GitHub tokens `ghp_...`, JWTs, PEM private keys, URL passwords, and variable assignments).
   - Replaces secrets with stable placeholders: `__REDACTED_SECRET_{UUID}__`.
   - Post-generation `unmask()` restores original secrets strictly on final output while keeping telemetry, thought traces, and LLM prompts free of credentials.

2. **Nonce-Enveloping (`build_enveloped_prompt`)**:
   - Packages user code inside XML envelopes with cryptographically random 16-hex nonces:
     `<untrusted_source_code nonce="{nonce}">...</untrusted_source_code>`
   - Neutralizes fake closing tags inside user docstrings or comments by escaping them to `&lt;/untrusted_source_code&gt;`.
   - Explicitly instructs system prompt that enveloped data is untrusted user content and must never override execution rules or role parameters.

---

## Pillar 2: Automata DFA Agent Workflow Guard (`agent_security/workflow_dfa.py`)

The pipeline execution flow is strictly constrained by a 7-state Deterministic Finite Automaton (DFA) that prevents agent skipping, step re-ordering, and unauthorized execution.

### DFA State Transition Table

| Current State | Event (`action`) | Next State | Notes |
|:---|:---|:---|:---|
| `START` | `validate` | `HEALED` | Code verified and syntax-healed |
| `HEALED` | `parse` | `AST_VERIFIED` | AST parsed via `safe_parse` |
| `AST_VERIFIED` | `graph` | `PDG_BUILT` | Program Dependence Graph built |
| `PDG_BUILT` | `green_audit` | `PDG_BUILT` | Self-loop: Green eco metrics computed |
| `PDG_BUILT` | `audit` | `SECURITY_AUDITED` | Static security audit executed |
| `SECURITY_AUDITED` | `summarize` | `SECURITY_AUDITED` | Self-loop: Summary generated |
| `SECURITY_AUDITED` | `profile` | `SECURITY_AUDITED` | Self-loop: Hardware profiler executed |
| `SECURITY_AUDITED` | `optimize` | `OPTIMIZED` | Optimizer refactors verified code |
| *Any State* | *Unregistered Event* | `TRAP` | Illegal step immediately trapped |
| `TRAP` | *Any Event* | `TRAP` | Absorbing error state; cannot exit |

- **`require(event)`**: Pre-checks whether firing `event` from current state leads to `TRAP`. Raises `WorkflowViolation` before state change.
- **`step(event)`**: Executes transition and logs to history.
- **Accepting States**: `SECURITY_AUDITED`, `OPTIMIZED`.

---

## Pillar 3: Sandboxing, AST Gatekeeper & Limits

### 3A. Subprocess Profiler Sandbox (`hardware_profiler.py`)
- Host `exec()` and `eval()` on user code are **completely eradicated**.
- Snippets run inside an isolated subprocess:
  ```bash
  python -I harness.py
  ```
- Subprocess runs with:
  - Isolated temporary working directory (`tempfile.TemporaryDirectory`).
  - Scrubbed environment variables (stripping `KEY`, `SECRET`, `TOKEN`, `AUTH`, `PASS`).
  - `shell=False`.
- Enforcement:
  - **Timeout Ceiling** (`PROFILER_TIMEOUT_SECONDS = 2.0s`): Enforced by parent watchdog killing the entire process tree via `psutil`.
  - **Memory Ceiling** (`PROFILER_MEMORY_LIMIT_MB = 50MB`): Enforced via POSIX `setrlimit(RLIMIT_AS)` and background `psutil` RSS polling thread.
  - Return schema guarantees four safety keys on all paths: `blocked`, `block_reasons`, `timed_out`, `memory_exceeded`.

### 3B. AST Gatekeeper (`agent_security/ast_gatekeeper.py`)
- Pre-screens code prior to execution using iterative breadth-first AST traversal (`collections.deque`), avoiding CPython call-stack recursion limits.
- Resolves import aliases (e.g. `import os as o; o.system(...)`).
- Blocks:
  - Dangerous modules: `os`, `sys`, `subprocess`, `socket`, `shutil`, `ctypes`, `builtins`, `importlib`, etc.
  - Dangerous builtins: `eval`, `exec`, `compile`, `breakpoint`, `__import__`.
  - Write-mode operations: `open(..., 'w')`, `open(..., 'a')`.
  - Dunder attacks: `__subclasses__`, `__globals__`, `__code__`, `__builtins__`.

### 3C. Input Limits Guard (`agent_security/input_limits.py`)
- `check_source()` verifies:
  - `MAX_SOURCE_BYTES = 500_000` (500 KB limit).
  - Null-byte injection (`\0`).
  - `MAX_LINE_LENGTH = 2_000` chars.
  - Linear bracket/parentheses/brace nesting depth check (`MAX_NESTING_DEPTH = 50`), skipping comments and string literals without regex.
  - Consecutive binary operator chains (`MAX_OPERATOR_CHAIN = 40`).
- `check_ast_depth()` verifies maximum AST tree depth iteratively (`MAX_AST_DEPTH = 60`).
- `safe_parse()` encapsulates `ast.parse` across the repository, raising structured `InputRejected` exceptions.

### 3D. Optimizer Firewall (`agent_security/optimizer_firewall.py`)
- Audits LLM-generated refactored code against original source code before acceptance:
  - Flags **new** unapproved imports not present in the original code.
  - Flags **new** network IP addresses / URLs not present in original comments/source.
  - Flags **new** dunder or reflective access calls.
  - Flags syntax errors or unparseable code.
- If the LLM candidate is flagged, the agent evaluates the deterministic fallback. If both fail, original source code is preserved intact.

---

## Pillar 4: ReDoS Guard & Security Scanner Hardening

### 4A. Safe Regex Search (`agent_security/safe_regex.py`)
- Wraps pattern evaluation with LRU pattern caching (`@lru_cache(maxsize=512)`).
- Truncates input lines to `MAX_LINE_LENGTH` before pattern evaluation.
- Pre-screens against catastrophic nested quantifiers (`(a+)+`, `(.*)*`).
- Invokes native C `regex` library with millisecond timeout deadline (`REGEX_TIMEOUT_SECONDS = 0.5s`), falling back to daemon thread isolation.
- `security_scanner.py` intercepts timeouts and emits `[CWE-1333] Scan degraded: regex match timed out` findings without crashing.

### 4B. XSS Remediation (`graph_visualizer.py`)
- HTML template script escapes `</script>` tag breaks in JSON payloads (`safe_nodes_json`, `safe_edges_json`).
- Dynamic vis.js node labels and inspector popups escape HTML entities (`&`, `<`, `>`, `"`, `'`) via `escapeHtml()`.

---

## Threat Model Matrix

| Threat ID | Threat Vector | Target Component | Mitigating Defence | Pillar |
|:---|:---|:---|:---|:---|
| **THREAT-01** | Arbitrary Code Execution / Host Compromise | `hardware_profiler.py` | Isolated Subprocess (`python -I`), AST Gatekeeper BFS blocklist | 3A, 3B |
| **THREAT-02** | Credential Exfiltration / LLM Memory Leak | `model_pipeline.py`, `optimizer_agent.py` | `SecretVault` masking & unmasking, sanitized logs | 1 |
| **THREAT-03** | Indirect Prompt Injection in Docstrings | LLM Prompts | Cryptographic Nonce Enveloping, Neutralized XML tags | 1 |
| **THREAT-04** | Agent Workflow Hijacking / Step Skipping | `agent_controller.py` | `WorkflowDFA` 7-state finite state machine with absorbing `TRAP` | 2 |
| **THREAT-05** | AST Parser Stack Overflow (Bracket Bombs) | `ast.parse` in healing/profiling | Iterative `check_source`, `safe_parse` depth limits | 3C |
| **THREAT-06** | Memory Exhaustion / CPU Infinite Loops | `hardware_profiler.py` | `psutil` process-tree kill watchdog, POSIX `RLIMIT_AS` | 3A |
| **THREAT-07** | ReDoS Catastrophic Backtracking | `security_scanner.py` | `safe_regex` LRU cache, line truncation, native timeout | 4A |
| **THREAT-08** | LLM Hallucinated Malicious Imports/URLs | `optimizer_agent.py` | Compiler-level `inspect_candidate` Optimizer Firewall | 3D |
| **THREAT-09** | Stored XSS in Graph Visualizations | `graph_visualizer.py` | HTML entity escaping, JSON `</script>` neutralization | 4B |

---

## Known Limitations

1. **Non-POSIX Resource Ceilings on Windows**:
   - `resource.setrlimit` is a POSIX-only C extension and is unavailable on Windows. On Windows platforms, memory limits are enforced via parent-watchdog `psutil.Process.memory_info().rss` polling intervals (~50ms). A sudden allocation faster than the polling frequency may allocate system memory momentarily before being terminated.
2. **Third-Party C Extension Regex Timeout**:
   - Standard library `re` (`_sre` engine) does not release the Python GIL during catastrophic backtracking. The `regex` library (C-level timeout) is required for hard interruption; otherwise, fallback thread termination relies on daemon thread abandonment.
3. **Dynamic Reflection Obfuscation**:
   - Advanced string-based dynamic execution tricks (e.g. `getattr(__builtins__, "ex" + "ec")`) that do not appear as literal AST names are restricted by profiler subprocess environment isolation rather than static AST gatekeeper rejection alone.
