# Polyglot Expansion: Python & C++ Dual-Language Architecture
<!--
  Tracking Document & Architecture Roadmap
  Goal: Extend Autonomous Code Intelligence Pipeline from Python-only to Polyglot (Python + C++)
-->

## Executive Summary
This document outlines the phased expansion of the Code Summarization & Optimization Agent pipeline from a single-language (Python) architecture to a dual-language polyglot engine supporting **Python** and **C++** using **Tree-sitter**.

The core objective is to preserve the existing **5-Agent workflow**, **4-Pillar security architecture**, and **Streamlit dashboard** while abstracting language-specific parsing, graph generation, security auditing, and compilation behind unified interfaces.

---

## Architecture Blueprint: Polyglot Adapter Layer

```
                        [ User Code Input (Python / C++) ]
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │          Language Auto-Detector           │
                  │   (File extension, syntax fingerprint)    │
                  └─────────────────────┬─────────────────────┘
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                       ▼
        ┌───────────────────────┐               ┌───────────────────────┐
        │     Python Driver     │               │      C++ Driver       │
        │ • ast / tree-sitter   │               │ • tree-sitter-cpp     │
        │ • Python colon healer │               │ • C++ ; & {} healer   │
        │ • Python CWE rules    │               │ • C++ Memory & Buffer │
        │ • python -I sandbox   │               │ • g++ compiler/static │
        └───────────┬───────────┘               └───────────┬───────────┘
                    │                                       │
                    └───────────────────┬───────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │       Unified Graph & Context Model       │
                  │   • Common AST Tree representation        │
                  │   • Normalized PDG (Control + Data Flow)  │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │        5-Agent Polyglot Pipeline          │
                  │   Agent 0: Universal Syntax Healer        │
                  │   Agent 1: Multi-Language PDG Inspector   │
                  │   Agent 2: Green & Complexity Auditor     │
                  │   Agent 3: CWE Threat Hunter (Polyglot)   │
                  │   Agent 4: Multi-Level Doc Generator      │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │   Interactive UI (Streamlit Dashboard)    │
                  │   • Language Selector: [Python | C++]     │
                  │   • Side-by-Side vis.js PDG Visualizer    │
                  │   • Polyglot CWE Security & Health Score  │
                  └───────────────────────────────────────────┘
```

---

## Phased Implementation Roadmap

### Phase 1: Environment & Grammar Setup
- [x] Install Tree-sitter packages: `tree-sitter`, `tree-sitter-cpp`, `tree-sitter-python`.
- [x] Create `polyglot/` core package module with `language_detector.py`.
- [x] Implement `ParserFactory` providing uniform AST node access across Python and C++.
- [x] Add unit verification test checking that sample C++ code parses into concrete Tree-sitter syntax nodes.

### Phase 2: C++ Program Dependence Graph (PDG) Builder
- [x] Build `polyglot/cpp_pdg_extractor.py` targeting Tree-sitter C++ grammar:
  - **Control Flow:** `for_statement`, `while_statement`, `if_statement`, `switch_statement`.
  - **Data Flow:** Variable declarations (`declaration`), assignments (`assignment_expression`), and returns.
- [x] Normalize C++ PDG into existing NetworkX format matching vis.js frontend schema.
- [x] Verify interactive graph generation for C++ nested loops and DSA algorithms.

### Phase 3: Polyglot Security Threat Hunter (C++ CWE Suite)
- [x] Build `polyglot/cpp_security_auditor.py` with AST query rules:
  - **CWE-120:** Buffer Overflow (`strcpy`, `strcat`, `gets`, `sprintf`).
  - **CWE-416:** Use-After-Free / Raw Pointer Deletion.
  - **CWE-119:** Out-of-Bounds Memory Access / Unbounded Array Indexing.
  - **CWE-78:** Shell Injection (`system()`, `popen()`).
- [x] Standardize finding dictionary matching existing Python scanner format (`rule_id`, `cwe`, `severity`, `line`, `message`, `snippet`).

### Phase 4: C++ Self-Healing Agent Extension
- [x] Extend `self_healing.py` with C++ healing strategies:
  - Diagnose Tree-sitter `ERROR` nodes.
  - Auto-append missing semicolons `;` on statement lines.
  - Auto-close unclosed braces `{}` and parentheses `()`.
  - Auto-detect missing foundational headers (`#include <iostream>`, `#include <vector>`).
- [x] Emit structured `repair_details` before/after records for C++ syntax repairs in the UI.

### Phase 5: C++ Execution & Profiler Engine
- [ ] Update `hardware_profiler.py` with dual-mode C++ handling:
  - **Execution Mode (Compiler Present):** Check if `g++` or `clang++` is available on system `PATH`. If present, compile with safety flags (`-O2 -Wall`) into temp directory and run in sandboxed subprocess with memory/time watchdog.
  - **Graceful Static Degradation (No Compiler):** If compiler is not installed, estimate algorithmic complexity, loop depth, and theoretical eco-score directly from the C++ PDG without execution errors.

### Phase 6: UI & Dashboard Integration
- [ ] Add Language toggle selector (`Python` / `C++`) in Streamlit sidebar.
- [ ] Add C++ benchmark samples to sidebar presets:
  - *C++ Buffer Overflow & Insecure `system()` Demo*
  - *C++ Broken Syntax / Missing Semicolons (Self-Healing Demo)*
  - *C++ O(N²) Nested Loop Complexity Demo*
- [ ] Ensure docstring generator outputs Doxygen / Javadoc style comments (`/** ... */`) for C++.
- [ ] Run full polyglot regression tests.

---

## Progress Checklist

| Phase | Milestone | Status | Key Deliverables |
|:---:|:---|:---:|:---|
| **1** | Tree-sitter Grammar Integration | ✅ Complete | `tree-sitter`, `tree-sitter-cpp`, `ParserFactory` |
| **2** | C++ PDG & Data Flow Extractor | ✅ Complete | `cpp_pdg_extractor.py`, vis.js normalization |
| **3** | C++ Security Auditor (CWEs) | ✅ Complete | AST/Tree-sitter queries for CWE-120, CWE-119, CWE-78 |
| **4** | C++ Syntax Self-Healer | ✅ Complete | Semicolon `;` and brace `{}` autonomous repair |
| **5** | C++ Profiler & Sandbox | ⬜ Not Started | `g++` compilation harness + static complexity fallback |
| **6** | UI & Polyglot Presets | ⬜ Not Started | Streamlit language toggle, C++ benchmarks |

---

## Technical Constraints & Guardrails
1. **Zero Python Regressions:** Existing Python parsing, 4-pillar security layer, and unit tests must remain 100% functional.
2. **Graceful Degradation:** The pipeline must never crash if `g++` is absent on the user's PC; it should transparently fallback to AST static complexity analysis.
3. **Unified Schema:** Graph nodes, security audit findings, and docstring objects must share identical dictionary schemas across both languages.
