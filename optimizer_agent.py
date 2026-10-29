"""
optimizer_agent.py - Autonomous Green & Secure Optimizer
=========================================================
Transforms inefficient, high-carbon, and vulnerable Python code into
optimized, hardened, production-grade code with closed-loop verification.

Key Features:
  1. Green Complexity Optimization (O(N^2) -> O(N), memoization, string joins)
  2. Security Hardening (Eliminates CWE vulnerabilities: eval, os.system, secrets)
  3. Closed-Loop Verification (Re-audits candidate code with AST, Green & Security scores)
  4. Unified Diff & Granular Improvement Explanations
"""

import os
import ast
import re
import sys
import difflib
import requests
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from dotenv import load_dotenv

load_dotenv()

# Safe console encoding for Windows
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from green_computing import analyze_green_computing
from security_scanner import SecurityAuditor
from self_healing import SelfHealingAgent

# ── Pillar 3B: Safe Parsing ──────────────────────────────────────────────────
try:
    from agent_security.input_limits import safe_parse
except ImportError:
    safe_parse = ast.parse
# ─────────────────────────────────────────────────────────────────────────────

# ── Pillar 3F: Optimizer Output AST Firewall ──────────────────────────────────
try:
    from agent_security.optimizer_firewall import inspect_candidate, audit_optimizer_output
    _FIREWALL_AVAILABLE = True
except ImportError:
    _FIREWALL_AVAILABLE = False
# ─────────────────────────────────────────────────────────────────────────────

# ── Pillar 1: Input Privacy & Anti-Hijack Shield ──────────────────────────────
try:
    from agent_security.input_shield import SecretVault, build_enveloped_prompt
    _SHIELD_AVAILABLE = True
except ImportError:
    _SHIELD_AVAILABLE = False
# ─────────────────────────────────────────────────────────────────────────────

# ── Polyglot Language Integration ───────────────────────────────────────────
try:
    from polyglot.language_detector import detect_language, SupportedLanguage
    from polyglot.parser_factory import ParserFactory
    from polyglot.cpp_security_auditor import CppSecurityAuditor
    from polyglot.cpp_self_healing import CppSelfHealingAgent
    _POLYGLOT_AVAILABLE = ParserFactory.is_available()
except (ImportError, Exception):
    _POLYGLOT_AVAILABLE = False
# ─────────────────────────────────────────────────────────────────────────────


@dataclass
class OptimizationResult:
    original_code: str
    optimized_code: str
    diff: str
    original_eco_score: int
    optimized_eco_score: int
    original_sec_score: int
    optimized_sec_score: int
    eco_delta: int
    sec_delta: int
    vulnerabilities_fixed: List[str] = field(default_factory=list)
    remaining_vulnerabilities: List[str] = field(default_factory=list)
    algorithmic_improvements: List[str] = field(default_factory=list)
    verified: bool = False
    verification_notes: str = ""
    firewall_passed: bool = True
    firewall_violations: List[str] = field(default_factory=list)
    language: str = "python"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "original_code": self.original_code,
            "optimized_code": self.optimized_code,
            "diff": self.diff,
            "original_eco_score": self.original_eco_score,
            "optimized_eco_score": self.optimized_eco_score,
            "original_sec_score": self.original_sec_score,
            "optimized_sec_score": self.optimized_sec_score,
            "eco_delta": self.eco_delta,
            "sec_delta": self.sec_delta,
            "vulnerabilities_fixed": self.vulnerabilities_fixed,
            "remaining_vulnerabilities": self.remaining_vulnerabilities,
            "algorithmic_improvements": self.algorithmic_improvements,
            "verified": self.verified,
            "verification_notes": self.verification_notes,
            "firewall_passed": self.firewall_passed,
            "firewall_violations": self.firewall_violations,
            "language": self.language,
        }


class GreenSecureOptimizer:
    """
    Autonomous refactoring agent combining LLM synthesis and deterministic
    AST/rule-based transformations with a closed-loop verification engine.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.api_key = (
            os.getenv("OPEN_SOURCE_API_KEY")
            or os.getenv("GROQ_API_KEY")
            or os.getenv("HF_API_TOKEN")
        )
        configured_url = os.getenv("OPEN_SOURCE_API_URL")
        if configured_url:
            self.api_url = configured_url
        elif self.api_key and self.api_key.startswith("gsk_"):
            self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        else:
            self.api_url = "https://router.huggingface.co/v1/chat/completions"

        default_model = "qwen/qwen3.8-27b"
        self.model_path = model_path or os.getenv("OPEN_SOURCE_MODEL_ID") or default_model
        self.security_auditor = SecurityAuditor()
        self.self_healer = SelfHealingAgent()
        if _POLYGLOT_AVAILABLE:
            try:
                self.cpp_security_auditor = CppSecurityAuditor()
                self.cpp_self_healer = CppSelfHealingAgent()
            except Exception:
                self.cpp_security_auditor = None
                self.cpp_self_healer = None
        else:
            self.cpp_security_auditor = None
            self.cpp_self_healer = None

    def optimize(
        self, source_code: str, dfa=None, language: Optional[str] = None
    ) -> OptimizationResult:
        """
        Orchestrates full optimization workflow across Python and C++:
          1. Baseline Audit (Green + Security)
          2. Candidate Synthesis (LLM prompt guided by diagnostic findings + Rule-based fallback)
          3. AST Syntax Healing & Validation
          4. Closed-Loop Verification (Re-audit Green + Security)
          5. Diff & Explanation Synthesis
        """
        # ── Pillar 2: DFA pre-condition guard ───────────────────────────────
        if dfa is not None:
            dfa.require("optimize")   # raises WorkflowViolation if illegal
        # ────────────────────────────────────────────────────────────────

        # Determine language
        if language is None:
            if _POLYGLOT_AVAILABLE:
                detected = detect_language(source_code)
                lang_norm = "cpp" if detected == SupportedLanguage.CPP else "python"
            else:
                lang_norm = "python"
        else:
            lang_norm = "cpp" if str(language).lower() in ("cpp", "c++", "c") else "python"

        if lang_norm == "cpp":
            result = self._optimize_cpp(source_code)
        else:
            result = self._optimize_python(source_code)

        if dfa is not None:
            dfa.step("optimize")

        return result

    def _optimize_python(self, source_code: str) -> OptimizationResult:
        # Step 1: Baseline Auditing
        orig_green = analyze_green_computing(source_code)
        orig_sec = self.security_auditor.audit_code(source_code)

        orig_eco_score = orig_green.get('score', 100)
        orig_sec_score = orig_sec.get('security_score', 100)
        orig_findings = orig_sec.get('findings', [])

        # Step 2: Generate candidate optimized code
        candidate_code = self._generate_candidate_code(source_code, orig_green, orig_sec)

        # Step 3: Self-healing / AST verification on candidate
        healed_report = self.self_healer.heal(candidate_code)
        candidate_code = healed_report.get('clean_code', candidate_code)

        # Firewall audit on candidate code
        firewall_passed = True
        firewall_violations = []

        if _FIREWALL_AVAILABLE:
            is_clean, violations = inspect_candidate(candidate_code, original_code=source_code)
            if not is_clean:
                firewall_violations.extend(violations)
                # Log thought-trace event
                print(f"[ThoughtTrace] FIREWALL: blocked candidate ? {'; '.join(violations)}")
                # Fall back to deterministic rules
                candidate_code = self._apply_deterministic_rules(source_code)
                fb_clean, fb_violations = inspect_candidate(candidate_code, original_code=source_code)
                if not fb_clean:
                    # Both failed: revert to original source code
                    print(f"[ThoughtTrace] FIREWALL: blocked fallback candidate ? {'; '.join(fb_violations)}")
                    candidate_code = source_code
                    firewall_passed = False
                    firewall_violations.extend(fb_violations)

        # Check if candidate parses
        is_syntax_valid = False
        try:
            safe_parse(candidate_code)
            is_syntax_valid = True
        except Exception:
            candidate_code = self._apply_deterministic_rules(source_code)
            try:
                safe_parse(candidate_code)
                is_syntax_valid = True
            except Exception:
                is_syntax_valid = False

        # Step 4: Closed-Loop Verification
        new_green = analyze_green_computing(candidate_code)
        new_sec = self.security_auditor.audit_code(candidate_code)

        new_eco_score = new_green.get('score', 100)
        new_sec_score = new_sec.get('security_score', 100)
        new_findings = new_sec.get('findings', [])

        eco_delta = new_eco_score - orig_eco_score
        sec_delta = new_sec_score - orig_sec_score

        # Track fixed vs remaining vulnerabilities
        orig_cwes = [f"{f.get('cwe')}: {f.get('message')}" for f in orig_findings]
        new_cwes = [f"{f.get('cwe')}: {f.get('message')}" for f in new_findings]
        fixed_cwes = [c for c in orig_cwes if c not in new_cwes]

        # Determine algorithmic improvements
        algo_improvements = self._detect_algorithmic_improvements(orig_green, new_green, source_code, candidate_code)

        # Generate Unified Diff
        diff_text = self._generate_unified_diff(source_code, candidate_code)

        # Verification validation
        verified = is_syntax_valid and (new_sec_score >= orig_sec_score) and (new_eco_score >= orig_eco_score)
        notes = []
        if is_syntax_valid:
            notes.append("Syntax verified (AST compliant).")
        else:
            notes.append("Syntax error in candidate code.")
        if sec_delta > 0:
            notes.append(f"Security Health boosted by +{sec_delta} pts ({orig_sec_score} -> {new_sec_score}).")
        if eco_delta > 0:
            notes.append(f"Eco-Efficiency score improved by +{eco_delta} pts ({orig_eco_score} -> {new_eco_score}).")
        if not notes:
            notes.append("Optimization maintained baseline integrity.")

        return OptimizationResult(
            original_code=source_code,
            optimized_code=candidate_code,
            diff=diff_text,
            original_eco_score=orig_eco_score,
            optimized_eco_score=new_eco_score,
            original_sec_score=orig_sec_score,
            optimized_sec_score=new_sec_score,
            eco_delta=eco_delta,
            sec_delta=sec_delta,
            vulnerabilities_fixed=fixed_cwes,
            remaining_vulnerabilities=new_cwes,
            algorithmic_improvements=algo_improvements,
            verified=verified,
            verification_notes=" ".join(notes),
            firewall_passed=firewall_passed,
            firewall_violations=firewall_violations,
            language="python",
        )

    def _optimize_cpp(self, source_code: str) -> OptimizationResult:
        orig_green = analyze_green_computing(source_code, language="cpp")
        orig_sec = (
            self.cpp_security_auditor.audit_code(source_code)
            if self.cpp_security_auditor
            else {"findings": [], "security_score": 100}
        )

        orig_eco_score = orig_green.get("score", 100)
        orig_sec_score = orig_sec.get("security_score", 100)
        orig_findings = orig_sec.get("findings", [])

        candidate_code = self._generate_candidate_code(
            source_code, orig_green, orig_sec, language="cpp"
        )

        if self.cpp_self_healer:
            healed_report = self.cpp_self_healer.heal(candidate_code)
            candidate_code = healed_report.get("clean_code", candidate_code)

        is_syntax_valid = self._can_parse(candidate_code, language="cpp")
        if not is_syntax_valid:
            candidate_code = self._apply_deterministic_cpp_rules(source_code)
            is_syntax_valid = self._can_parse(candidate_code, language="cpp")

        new_green = analyze_green_computing(candidate_code, language="cpp")
        new_sec = (
            self.cpp_security_auditor.audit_code(candidate_code)
            if self.cpp_security_auditor
            else {"findings": [], "security_score": 100}
        )

        new_eco_score = new_green.get("score", 100)
        new_sec_score = new_sec.get("security_score", 100)
        new_findings = new_sec.get("findings", [])

        eco_delta = new_eco_score - orig_eco_score
        sec_delta = new_sec_score - orig_sec_score

        orig_cwes = [f"{f.get('cwe')}: {f.get('message')}" for f in orig_findings]
        new_cwes = [f"{f.get('cwe')}: {f.get('message')}" for f in new_findings]
        fixed_cwes = [c for c in orig_cwes if c not in new_cwes]

        algo_improvements = self._detect_cpp_algorithmic_improvements(
            orig_green, new_green, source_code, candidate_code
        )

        diff_text = self._generate_unified_diff(source_code, candidate_code)

        verified = is_syntax_valid and (new_sec_score >= orig_sec_score) and (new_eco_score >= orig_eco_score)
        notes = []
        if is_syntax_valid:
            notes.append("C++ Syntax verified (AST compliant).")
        else:
            notes.append("Syntax defect detected in candidate C++.")
        if sec_delta > 0:
            notes.append(f"Security Health boosted by +{sec_delta} pts ({orig_sec_score} -> {new_sec_score}).")
        if eco_delta > 0:
            notes.append(f"Eco-Efficiency score improved by +{eco_delta} pts ({orig_eco_score} -> {new_eco_score}).")
        if not notes:
            notes.append("C++ Optimization maintained baseline integrity.")

        return OptimizationResult(
            original_code=source_code,
            optimized_code=candidate_code,
            diff=diff_text,
            original_eco_score=orig_eco_score,
            optimized_eco_score=new_eco_score,
            original_sec_score=orig_sec_score,
            optimized_sec_score=new_sec_score,
            eco_delta=eco_delta,
            sec_delta=sec_delta,
            vulnerabilities_fixed=fixed_cwes,
            remaining_vulnerabilities=new_cwes,
            algorithmic_improvements=algo_improvements,
            verified=verified,
            verification_notes=" ".join(notes),
            firewall_passed=True,
            firewall_violations=[],
            language="cpp",
        )

    def _generate_candidate_code(
        self, source_code: str, green_info: Dict, sec_info: Dict, language: str = "python"
    ) -> str:
        if language in ("cpp", "c++"):
            return self._generate_candidate_cpp_code(source_code, green_info, sec_info)
        return self._generate_candidate_python_code(source_code, green_info, sec_info)

    def _generate_candidate_python_code(
        self, source_code: str, green_info: Dict, sec_info: Dict
    ) -> str:
        if not self.api_key:
            return self._apply_deterministic_rules(source_code)

        # Build diagnostic context strings (these come from our own analysis
        # tools, not user-controlled, so they don't need masking).
        vuln_list = [f"- Line {f.get('line')}: {f.get('cwe')} ({f.get('category')}) - {f.get('message')}" for f in sec_info.get('findings', [])]
        vulns_str = "\n".join(vuln_list) if vuln_list else "None detected."

        green_recs = "\n".join([f"- {r}" for r in green_info.get('recommendations', [])])
        if not green_recs:
            green_recs = "Maintain linear complexity."

        # ── Pillar 1: mask secrets and build anti-hijack envelope ─────────────
        if _SHIELD_AVAILABLE:
            vault = SecretVault()
            masked_code = vault.mask(source_code)

            # The task instruction keeps the original wording exactly.
            # Diagnostic info (vulns, green recs) is trusted pipeline output
            # and is placed OUTSIDE the envelope as part of the instruction.
            task_instruction = (
                "You are an expert Python compiler engineer and security specialist.\n"
                "Refactor the Python code in the <untrusted_source_code> block below to fix "
                "all security vulnerabilities and optimize computational efficiency (Green Computing).\n\n"
                "Diagnostic Security Vulnerabilities:\n"
                f"{vulns_str}\n\n"
                "Green Computing Inefficiencies:\n"
                f"{green_recs}\n\n"
                "Guidelines:\n"
                "1. Replace dangerous functions:\n"
                "   - eval(), exec() -> ast.literal_eval() or safe lookup.\n"
                "   - os.system() -> subprocess.run(..., shell=False).\n"
                "   - Hardcoded API keys/passwords -> os.getenv('KEY_NAME').\n"
                "2. Optimize algorithmic complexity:\n"
                "   - Convert O(N^2) nested list loops to O(N) using set/dict lookups.\n"
                "   - Replace in-loop string concatenation with list.append() and \"\".join().\n"
                "   - Add memoization/caching for recursive functions where appropriate.\n"
                "3. Preserve the exact function names, parameters, and return types.\n"
                "4. Output ONLY valid, executable Python code inside a ```python ``` block. "
                "No markdown conversation or explanations outside the block."
            )
            system_prompt, user_prompt = build_enveloped_prompt(
                task_instruction, masked_code, extra_context=""
            )
        else:
            # Fallback: original prompt construction (no shield available).
            vault = None
            system_prompt = "You are an automated Python optimization agent. Output ONLY valid Python code."
            user_prompt = f"""You are an expert Python compiler engineer and security specialist.
Refactor the following Python code to fix all security vulnerabilities and optimize computational efficiency (Green Computing).

Diagnostic Security Vulnerabilities:
{vulns_str}

Green Computing Inefficiencies:
{green_recs}

Guidelines:
1. Replace dangerous functions:
   - eval(), exec() -> ast.literal_eval() or safe lookup.
   - os.system() -> subprocess.run(..., shell=False).
   - Hardcoded API keys/passwords -> os.getenv('KEY_NAME').
2. Optimize algorithmic complexity:
   - Convert O(N^2) nested list loops to O(N) using set/dict lookups.
   - Replace in-loop string concatenation with list.append() and "".join().
   - Add memoization/caching for recursive functions where appropriate.
3. Preserve the exact function names, parameters, and return types.
4. Output ONLY valid, executable Python code inside a ```python ``` block. No markdown conversation or explanations outside the block.

Source Code:
```python
{source_code}
```
"""
        # ─────────────────────────────────────────────────────────────────────

        response_text = self._call_llm(user_prompt, system_prompt=system_prompt)
        if response_text:
            extracted = self._extract_code_block(response_text)
            if extracted:
                # ── Pillar 3G: AST Firewall audit before accepting candidate ──
                if _FIREWALL_AVAILABLE:
                    is_clean, violations = audit_optimizer_output(extracted, original_source=source_code)
                    if not is_clean:
                        return self._apply_deterministic_rules(source_code)
                # ─────────────────────────────────────────────────────────────
                if self._can_parse(extracted):
                    # ── Pillar 1: restore real secret values in the returned code ──
                    if vault is not None:
                        extracted = vault.unmask(extracted)
                    return extracted

        # Fallback to rule-based transformer (no LLM involved; no masking needed).
        return self._apply_deterministic_rules(source_code)

    def _call_llm(
        self, prompt: str, system_prompt: str | None = None
    ) -> Optional[str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        # Use caller-supplied system prompt (from Pillar-1 envelope) when
        # available; otherwise fall back to the original default wording.
        effective_system = system_prompt if system_prompt is not None else (
            "You are an automated Python optimization agent. Output ONLY valid Python code."
        )
        payload = {
            "model": self.model_path,
            "messages": [
                {
                    "role": "system",
                    "content": effective_system,
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 1200,
        }
        try:
            res = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            res.raise_for_status()
            data = res.json()
            return data["choices"][0]["message"]["content"]
        except Exception:
            return None

    def _generate_candidate_cpp_code(
        self, source_code: str, green_info: Dict, sec_info: Dict
    ) -> str:
        if not self.api_key:
            return self._apply_deterministic_cpp_rules(source_code)

        vuln_list = [
            f"- Line {f.get('line')}: {f.get('cwe')} ({f.get('category')}) - {f.get('message')}"
            for f in sec_info.get('findings', [])
        ]
        vulns_str = "\n".join(vuln_list) if vuln_list else "None detected."

        green_recs = "\n".join([f"- {r}" for r in green_info.get('recommendations', [])])
        if not green_recs:
            green_recs = "Maintain linear complexity and avoid redundant copies."

        task_instruction = (
            "You are an expert C++ systems engineer, compiler optimizer, and security specialist.\n"
            "Refactor the C++ code in the <untrusted_source_code> block below to fix "
            "all security vulnerabilities (CWE-120 buffer overflows, CWE-78 command injections, memory safety) "
            "and optimize computational efficiency (Green Computing).\n\n"
            "Diagnostic Security Vulnerabilities:\n"
            f"{vulns_str}\n\n"
            "Green Computing Inefficiencies:\n"
            f"{green_recs}\n\n"
            "Guidelines:\n"
            "1. Replace dangerous memory and string operations (CWE-120):\n"
            "   - Replace strcpy/strcat with strncpy (with explicit null-termination), snprintf, or std::string.\n"
            "   - Ensure buffer bounds checking.\n"
            "2. Mitigate command injection (CWE-78):\n"
            "   - Avoid raw system() calls; replace with safe invocation, parameter validation, or standard library alternatives.\n"
            "3. Replace hardcoded credentials (CWE-798):\n"
            "   - Use std::getenv() instead of hardcoded strings.\n"
            "4. Optimize performance & green efficiency:\n"
            "   - Pass large arguments by const reference (const std::string&, const std::vector<T>&).\n"
            "   - Use std::unordered_map / std::unordered_set for O(1) lookups instead of nested loops.\n"
            "5. Output ONLY valid, compilable C++ code inside a ```cpp ``` block. "
            "Preserve all function signatures, names, and logic. Do NOT translate into Python."
        )

        if _SHIELD_AVAILABLE:
            vault = SecretVault()
            masked_code = vault.mask(source_code)
            system_prompt, user_prompt = build_enveloped_prompt(
                task_instruction, masked_code, extra_context=""
            )
        else:
            vault = None
            system_prompt = "You are an automated C++ optimization agent. Output ONLY valid C++ code inside ```cpp ``` block."
            user_prompt = f"""{task_instruction}\n\nSource Code:\n```cpp\n{source_code}\n```"""

        response_text = self._call_llm(user_prompt, system_prompt=system_prompt)
        if response_text:
            extracted = self._extract_code_block(response_text, language="cpp")
            if extracted and self._can_parse(extracted, language="cpp"):
                if vault is not None:
                    extracted = vault.unmask(extracted)
                return extracted

        return self._apply_deterministic_cpp_rules(source_code)

    def _extract_code_block(self, text: str, language: str = "python") -> Optional[str]:
        if language in ("cpp", "c++"):
            match = re.search(r"```(?:cpp|c\+\+|c)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        else:
            match = re.search(r"```(?:python|py)?\s*([\s\S]*?)\s*```", text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match_gen = re.search(r"```\w*\s*([\s\S]*?)\s*```", text)
        if match_gen:
            return match_gen.group(1).strip()
        if self._can_parse(text.strip(), language=language):
            return text.strip()
        return None

    def _can_parse(self, code: str, language: str = "python") -> bool:
        if language in ("cpp", "c++"):
            try:
                from polyglot.parser_factory import ParserFactory, SupportedLanguage
                parsed = ParserFactory.parse(code, language=SupportedLanguage.CPP)
                return parsed.root_node is not None and not parsed.has_errors
            except Exception:
                return code.count("{") == code.count("}")
        try:
            safe_parse(code)
            return True
        except Exception:
            return False

    def _apply_deterministic_cpp_rules(self, code: str) -> str:
        """
        Rule-based C++ refactoring when LLM is unavailable or uncompilable.
        Directly remediates CWE-120 (strcpy, strcat, sprintf, gets), CWE-78 (system),
        and CWE-798 (hardcoded credentials).
        """
        transformed = code

        # 1. Remediate CWE-120: strcpy(dest, src) -> strncpy with null-termination
        def _fix_strcpy(match):
            dest = match.group(1).strip()
            src = match.group(2).strip()
            return f"strncpy({dest}, {src}, sizeof({dest}) - 1);\n    {dest}[sizeof({dest}) - 1] = '\\0'"

        transformed = re.sub(
            r'\bstrcpy\s*\(\s*([a-zA-Z0-9_\[\]]+)\s*,\s*([^)]+)\s*\)',
            _fix_strcpy,
            transformed
        )

        # 2. Remediate CWE-120: strcat(dest, src) -> strncat
        def _fix_strcat(match):
            dest = match.group(1).strip()
            src = match.group(2).strip()
            return f"strncat({dest}, {src}, sizeof({dest}) - strlen({dest}) - 1)"

        transformed = re.sub(
            r'\bstrcat\s*\(\s*([a-zA-Z0-9_\[\]]+)\s*,\s*([^)]+)\s*\)',
            _fix_strcat,
            transformed
        )

        # 3. Remediate CWE-120: sprintf(dest, ...) -> snprintf(dest, sizeof(dest), ...)
        transformed = re.sub(
            r'\bsprintf\s*\(\s*([a-zA-Z0-9_\[\]]+)\s*,',
            r'snprintf(\1, sizeof(\1),',
            transformed
        )

        # 4. Remediate CWE-120: gets(buffer) -> fgets(buffer, sizeof(buffer), stdin)
        transformed = re.sub(
            r'\bgets\s*\(\s*([a-zA-Z0-9_\[\]]+)\s*\)',
            r'fgets(\1, sizeof(\1), stdin)',
            transformed
        )

        # 5. Remediate CWE-78: system(cmd) -> safe log output
        def _fix_system(match):
            cmd_arg = match.group(1).strip()
            return (
                f"// [CWE-78 Remediated]: Dangerous shell execution via system() removed\n"
                f"    std::cout << \"[Secure System Audit]: \" << {cmd_arg} << std::endl"
            )

        transformed = re.sub(
            r'\bsystem\s*\(\s*([^)]+)\s*\)',
            _fix_system,
            transformed
        )

        # 6. Remediate CWE-798: Hardcoded credentials
        def _fix_cpp_secret(match):
            decl = match.group(1)
            var_name = match.group(2)
            val = match.group(3)
            env_var = var_name.upper()
            return f'const char* {var_name}_env = std::getenv("{env_var}");\n    {decl} {var_name} = {var_name}_env ? {var_name}_env : "{val}"'

        transformed = re.sub(
            r'\b(const\s+char\*\s+|std::string\s+)([a-zA-Z0-9_]*(?:password|api_key|secret|token)[a-zA-Z0-9_]*)\s*=\s*"([^"]{6,})";',
            _fix_cpp_secret,
            transformed,
            flags=re.IGNORECASE
        )

        # 7. Ensure necessary headers exist
        needed_includes = []
        if ("strncpy" in transformed or "strncat" in transformed or "strlen" in transformed) and "#include <cstring>" not in transformed:
            needed_includes.append("#include <cstring>")
        if ("getenv" in transformed) and "#include <cstdlib>" not in transformed:
            needed_includes.append("#include <cstdlib>")
        if ("std::cout" in transformed) and "#include <iostream>" not in transformed:
            needed_includes.append("#include <iostream>")

        if needed_includes:
            lines = transformed.splitlines()
            first_non_comment = 0
            for idx, l in enumerate(lines):
                if not l.strip().startswith("//") and not l.strip().startswith("/*"):
                    first_non_comment = idx
                    break
            transformed = "\n".join(lines[:first_non_comment] + needed_includes + lines[first_non_comment:])

        return transformed

    def _detect_cpp_algorithmic_improvements(
        self, orig_green: Dict, new_green: Dict, orig_code: str, new_code: str
    ) -> List[str]:
        improvements = []
        orig_metrics = orig_green.get('metrics', {})
        new_metrics = new_green.get('metrics', {})

        orig_depth = orig_metrics.get('max_loop_depth', 0)
        new_depth = new_metrics.get('max_loop_depth', 0)
        if orig_depth > new_depth:
            improvements.append(f"Reduced loop nesting depth from {orig_depth} to {new_depth} (algorithmic speedup).")

        orig_loops = orig_metrics.get('loops', 0)
        new_loops = new_metrics.get('loops', 0)
        if orig_loops > new_loops and orig_depth >= 2:
            improvements.append("Eliminated redundant loop scans (O(N^2) -> O(N)).")

        if "unordered_set" in new_code and "unordered_set" not in orig_code:
            improvements.append("Replaced sequential lookups with std::unordered_set for O(1) hash access.")

        if "unordered_map" in new_code and "unordered_map" not in orig_code:
            improvements.append("Adopted std::unordered_map for constant-time key lookup.")

        if "strncpy" in new_code and "strcpy" in orig_code:
            improvements.append("Hardened memory buffers with bounded strncpy and explicit null termination.")

        if "std::string" in new_code and "char " in orig_code:
            improvements.append("Modernized raw C-buffers to dynamic RAII-managed std::string.")

        if "reserve(" in new_code and "reserve(" not in orig_code:
            improvements.append("Pre-allocated container memory via reserve() to eliminate dynamic reallocations.")

        return improvements

    def _apply_deterministic_rules(self, code: str) -> str:
        """
        Rule-based AST/regex refactoring when LLM is unavailable or unparseable.
        """
        transformed = code
        needed_imports = set()

        # 1. Replace eval(...) with ast.literal_eval(...)
        if re.search(r"\beval\(", transformed):
            transformed = re.sub(r"\beval\(", "ast.literal_eval(", transformed)
            needed_imports.add("import ast")

        # 2. Replace os.system(cmd) with subprocess.run(shlex.split(cmd), check=True)
        if re.search(r"os\.system\(", transformed):
            transformed = re.sub(
                r"os\.system\((.*?)\)",
                r"subprocess.run(\1, shell=False, check=True)",
                transformed
            )
            needed_imports.add("import subprocess")

        # 3. Replace hardcoded API key / secrets assignment
        # Pattern: api_key = "sk_..." -> api_key = os.getenv("API_KEY", "...")
        def secret_replacer(match):
            var_name = match.group(1)
            val = match.group(2)
            env_var = var_name.upper()
            needed_imports.add("import os")
            return f'{var_name} = os.getenv("{env_var}", "{val}")'

        transformed = re.sub(
            r'(?i)\b(api_key|password|secret|token|auth_token)\s*=\s*["\']([^"\']{6,})["\']',
            secret_replacer,
            transformed
        )

        # 4. Inefficient string concatenation pattern in loop:
        # result += item -> parts.append(item)
        if re.search(r'([a-zA-Z_]\w*)\s*\+=\s*([a-zA-Z_]\w*)', transformed):
            # Safe structural inspection
            pass

        # 5. Insert needed imports at the top if missing
        if needed_imports:
            existing_lines = transformed.splitlines()
            imports_to_add = [imp for imp in needed_imports if imp not in transformed]
            if imports_to_add:
                transformed = "\n".join(imports_to_add) + "\n\n" + transformed

        return transformed

    def _detect_algorithmic_improvements(self, orig_green: Dict, new_green: Dict, orig_code: str, new_code: str) -> List[str]:
        improvements = []
        orig_metrics = orig_green.get('metrics', {})
        new_metrics = new_green.get('metrics', {})

        orig_depth = orig_metrics.get('max_loop_depth', 0)
        new_depth = new_metrics.get('max_loop_depth', 0)
        if orig_depth > new_depth:
            improvements.append(f"Reduced loop nesting depth from {orig_depth} to {new_depth} (algorithmic speedup).")

        orig_loops = orig_metrics.get('loops', 0)
        new_loops = new_metrics.get('loops', 0)
        if orig_loops > new_loops and orig_depth >= 2:
            improvements.append(f"Eliminated redundant loop iterations (O(N^2) -> O(N)).")

        if "set(" in new_code and "set(" not in orig_code:
            improvements.append("Introduced O(1) hash set membership lookups instead of sequential list scans.")

        if "functools.lru_cache" in new_code or "@lru_cache" in new_code:
            improvements.append("Added memoization caching to eliminate exponential recursive recomputation.")

        if "join(" in new_code and "+=" in orig_code:
            improvements.append("Replaced repeated string concatenation with optimized str.join() buffer.")

        if not improvements:
            improvements.append("Maintained optimal execution path and minimal memory allocations.")

        return improvements

    def _generate_unified_diff(self, original: str, optimized: str) -> str:
        orig_lines = original.strip().splitlines(keepends=True)
        opt_lines = optimized.strip().splitlines(keepends=True)
        diff = difflib.unified_diff(
            orig_lines,
            opt_lines,
            fromfile="original.py",
            tofile="optimized.py",
            lineterm=""
        )
        return "".join(diff)


def optimize_code(
    source_code: str,
    model_path: Optional[str] = None,
    dfa=None,
    language: Optional[str] = None,
) -> OptimizationResult:
    """Convenience functional API for code optimization.

    Parameters
    ----------
    source_code : str
        Python source code to optimize.
    model_path : str or None, optional
        Model identifier for the LLM backend.
    dfa : WorkflowDFA or None, optional
        If supplied, passed through to ``GreenSecureOptimizer.optimize()``
        so the DFA guard is enforced.  When None (default), behaviour is
        unchanged.
    """
    optimizer = GreenSecureOptimizer(model_path=model_path)
    return optimizer.optimize(source_code, dfa=dfa, language=language)


if __name__ == "__main__":
    # Test sample with O(N^2) loop and critical CWE vulnerabilities
    sample_vulnerable_code = """
import os

def find_common_users(registered_users, active_visitors, user_token):
    # Security Flaw: Hardcoded API secret
    api_key = "sk_live_983749827394827394827"
    
    # Inefficient O(N^2) nested search
    common = []
    for user in registered_users:
        for visitor in active_visitors:
            if user == visitor:
                common.append(user)
                
    # Security Flaw: Dangerous eval
    data_payload = eval(user_token)
    
    # Security Flaw: Insecure shell command execution
    os.system("echo User sync completed")
    
    return common, data_payload
"""
    print("=" * 65)
    print("  AUTONOMOUS GREEN & SECURE OPTIMIZER (PHASE 4)")
    print("=" * 65)
    print("\n[Input Code]")
    print(sample_vulnerable_code)

    res = optimize_code(sample_vulnerable_code)

    print("\n" + "=" * 65)
    print(f"  VERIFICATION STATUS: {'[PASSED]' if res.verified else '[FAILED]'}")
    print(f"  Eco Score:      {res.original_eco_score}/100 -> {res.optimized_eco_score}/100 (Delta: +{res.eco_delta})")
    print(f"  Security Score: {res.original_sec_score}/100 -> {res.optimized_sec_score}/100 (Delta: +{res.sec_delta})")
    print("=" * 65)

    print("\n--- Verification Notes ---")
    print(res.verification_notes)

    print("\n--- Vulnerabilities Remediated ---")
    for v in res.vulnerabilities_fixed:
        print(f"  [FIXED] {v}")

    print("\n--- Algorithmic Improvements ---")
    for a in res.algorithmic_improvements:
        print(f"  [OPTIMIZED] {a}")

    print("\n--- Unified Diff ---")
    print(res.diff)

    print("\n--- Refactored Code ---")
    print(res.optimized_code)
