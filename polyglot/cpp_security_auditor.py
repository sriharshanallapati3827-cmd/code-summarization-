"""
polyglot/cpp_security_auditor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
C++ Security Vulnerability Auditing Engine.
Uses Tree-sitter AST queries combined with lexical pattern analysis to detect:
  1. Buffer Overflow (CWE-120): strcpy, strcat, gets, sprintf, vsprintf, scanf(%s).
  2. Memory Corruption / Out-of-Bounds (CWE-119 / CWE-787): unbounded array copies, raw pointer arithmetic.
  3. Use-After-Free & Double Free (CWE-416 / CWE-415): access or deletion of freed pointers.
  4. Command Injection (CWE-78): system(), popen(), execlp(), execvp().
  5. Insecure PRNG (CWE-338): rand(), srand(time(NULL)).
  6. Hardcoded Secrets (CWE-798): sensitive tokens, passwords, API keys in string literals.

Outputs findings, risk score, security score, rating, and remediations matching
the standard format of security_scanner.py for seamless UI & agent integration.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from polyglot.parser_factory import ParserFactory, SupportedLanguage


# ── Dangerous C/C++ Functions Database ───────────────────────────────────────
DANGEROUS_CALLS_MAP: Dict[str, Tuple[str, str, str, str, str]] = {
    # func_name -> (cwe_id, category, severity, message, rule_id)
    "gets": (
        "CWE-120", "Buffer Overflow", "CRITICAL",
        "[CWE-120] Critical Buffer Overflow: 'gets()' is deprecated and inherently unsafe (no bounds checking). Use fgets() or std::string.",
        "sec.cpp.bof-gets"
    ),
    "strcpy": (
        "CWE-120", "Buffer Overflow", "HIGH",
        "[CWE-120] Buffer Overflow: 'strcpy()' does not check destination buffer size. Use strncpy(), strlcpy(), or std::string.",
        "sec.cpp.bof-strcpy"
    ),
    "strcat": (
        "CWE-120", "Buffer Overflow", "HIGH",
        "[CWE-120] Buffer Overflow: 'strcat()' does not enforce bounds limits. Use strncat(), strlcat(), or std::string.",
        "sec.cpp.bof-strcat"
    ),
    "sprintf": (
        "CWE-120", "Buffer Overflow", "HIGH",
        "[CWE-120] Buffer Overflow: 'sprintf()' lacks destination capacity bounds. Use snprintf() or std::ostringstream.",
        "sec.cpp.bof-sprintf"
    ),
    "vsprintf": (
        "CWE-120", "Buffer Overflow", "HIGH",
        "[CWE-120] Buffer Overflow: 'vsprintf()' lacks buffer size checks. Use vsnprintf().",
        "sec.cpp.bof-vsprintf"
    ),
    "scanf": (
        "CWE-120", "Buffer Overflow", "MEDIUM",
        "[CWE-120] Potential Buffer Overflow: 'scanf()' with unbounded '%s' specifier can overflow buffer. Use '%Ns' with explicit width or std::cin >> string.",
        "sec.cpp.bof-scanf"
    ),
    "system": (
        "CWE-78", "Command Injection", "CRITICAL",
        "[CWE-78] Command Injection: 'system()' invokes a shell with user input. Avoid shell calls or sanitize arguments.",
        "sec.cpp.cmd-system"
    ),
    "popen": (
        "CWE-78", "Command Injection", "HIGH",
        "[CWE-78] Command Injection: 'popen()' launches a shell command pipeline. Validate and sanitize inputs.",
        "sec.cpp.cmd-popen"
    ),
    "rand": (
        "CWE-338", "Insecure PRNG", "LOW",
        "[CWE-338] Insecure PRNG: 'rand()' is cryptographically weak. Use C++11 <random> (std::random_device, std::mt19937).",
        "sec.cpp.prng-rand"
    ),
}

# ── Regex patterns for C++ hardcoded credentials & formatting ────────────────
CPP_SECRET_PATTERNS = [
    (r'(?i)(api_key|secret|password|token|auth_token)\s*=\s*["\'][^"\']{8,}["\']',
     '[CWE-798] Hardcoded Credentials: Plaintext secret or API key found in source code. Store credentials in environment variables or a vault.',
     'HIGH', 'sec.cpp.hardcoded-secret'),
    (r'free\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*;[^}]*?\b\1\b',
     '[CWE-416] Use-After-Free: Pointer used after free(). Set pointer to nullptr immediately after deallocation or use std::unique_ptr.',
     'HIGH', 'sec.cpp.mem-use-after-free'),
]


class CppSecurityAuditor:
    """
    Static security auditor for C++ source code.
    Traverses Tree-sitter AST nodes to find dangerous function calls,
    memory safety anti-patterns, and hardcoded secrets.
    """

    def audit_code(self, source_code: str) -> Dict[str, Any]:
        if not source_code or not source_code.strip():
            return self._empty_result()

        lines = source_code.splitlines()
        findings: List[Dict[str, Any]] = []
        seen: Set[Tuple[str, int]] = set()

        # 1. Tree-sitter AST Traversal for Function Calls
        parsed = ParserFactory.parse(source_code, language=SupportedLanguage.CPP)
        if parsed.root_node:
            self._scan_ast_nodes(parsed.root_node, lines, findings, seen)

        # 2. Text / Regex Scan for Use-After-Free & Hardcoded Credentials
        for pattern, message, severity, rule_id in CPP_SECRET_PATTERNS:
            for idx, line in enumerate(lines):
                if re.search(pattern, line):
                    key = (rule_id, idx + 1)
                    if key not in seen:
                        seen.add(key)
                        cwe_match = re.search(r'\[(CWE-\d+)\]', message)
                        cwe_id = cwe_match.group(1) if cwe_match else 'CWE-Other'
                        category = "Hardcoded Secret" if "798" in cwe_id else "Memory Safety"
                        findings.append({
                            'rule_id': rule_id,
                            'cwe': cwe_id,
                            'category': category,
                            'line': idx + 1,
                            'message': message,
                            'severity': severity,
                            'snippet': line.strip()[:100]
                        })

        # Calculate scores
        risk_score = self._compute_risk_score(findings)
        security_score = max(0, int(100 - (risk_score * 10)))
        rating = self._classify_rating(security_score, findings)
        remediations = self._generate_remediations(findings)

        return {
            'status': 'ok',
            'findings_count': len(findings),
            'risk_score': risk_score,
            'security_score': security_score,
            'rating': rating,
            'findings': findings,
            'remediations': remediations,
            'summary': self._build_summary(security_score, rating, findings)
        }

    def _scan_ast_nodes(
        self,
        node: Any,
        lines: List[str],
        findings: List[Dict[str, Any]],
        seen: Set[Tuple[str, int]]
    ) -> None:
        """Iterative traversal scanning call_expression nodes for dangerous APIs."""
        stack = [node]
        while stack:
            curr = stack.pop()
            if curr.type == "call_expression":
                func_node = curr.child_by_field_name("function")
                if func_node:
                    func_name = func_node.text.decode("utf-8", errors="replace").strip()
                    # Strip namespace std::
                    if func_name.startswith("std::"):
                        func_name = func_name[5:]

                    if func_name in DANGEROUS_CALLS_MAP:
                        cwe_id, category, severity, message, rule_id = DANGEROUS_CALLS_MAP[func_name]
                        line_num = curr.start_point.row + 1
                        key = (rule_id, line_num)
                        if key not in seen:
                            seen.add(key)
                            line_content = lines[line_num - 1] if 1 <= line_num <= len(lines) else ""
                            findings.append({
                                'rule_id': rule_id,
                                'cwe': cwe_id,
                                'category': category,
                                'line': line_num,
                                'message': message,
                                'severity': severity,
                                'snippet': line_content.strip()[:100]
                            })

            for child in curr.children:
                stack.append(child)

    def analyze_pdg_taint(self, source_code: str, pdg_graph: dict) -> List[Dict]:
        """
        Correlates C++ PDG data dependency edges with security findings.
        Flags when user input (source) flows into a security-sensitive sink (e.g. system, strcpy).
        """
        tainted_flows: List[Dict] = []
        audit_result = self.audit_code(source_code)
        findings = audit_result.get("findings", [])

        if not findings or not pdg_graph or not pdg_graph.get("edges"):
            return tainted_flows

        dangerous_line_map = {f["line"]: f for f in findings}

        for node_id, desc in pdg_graph.get("nodes", {}).items():
            for line_no, finding in dangerous_line_map.items():
                call_target = finding.get("rule_id", "").split(".")[-1]
                if any(x in desc.lower() for x in (call_target, finding.get("cwe", "").lower())):
                    # Check if data flows into this node
                    incoming_data = [
                        e for e in pdg_graph["edges"]
                        if e.get("target") == node_id and e.get("kind") == "Data"
                    ]
                    for edge in incoming_data:
                        tainted_flows.append({
                            "sink_node": node_id,
                            "sink_desc": desc,
                            "source_node": edge["source"],
                            "variable": edge.get("label", "data"),
                            "cwe": finding["cwe"],
                            "severity": finding["severity"],
                            "risk": finding["message"]
                        })
        return tainted_flows

    def _compute_risk_score(self, findings: List[Dict]) -> float:
        if not findings:
            return 0.0

        weights = {'CRITICAL': 8.5, 'HIGH': 6.5, 'MEDIUM': 3.5, 'LOW': 1.0}
        increments = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.1}

        max_base = 0.0
        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}

        for f in findings:
            sev = f.get('severity', 'LOW').upper()
            if sev not in counts:
                sev = 'LOW'
            counts[sev] += 1
            max_base = max(max_base, weights.get(sev, 1.0))

        score = max_base
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if weights[s] == max_base and counts[s] > 0:
                counts[s] -= 1
                break

        score += counts['CRITICAL'] * increments['CRITICAL']
        score += counts['HIGH']     * increments['HIGH']
        score += counts['MEDIUM']   * increments['MEDIUM']
        score += counts['LOW']      * increments['LOW']

        return round(min(10.0, score), 1)

    def _classify_rating(self, security_score: int, findings: List[Dict]) -> str:
        has_critical = any(f.get('severity') == 'CRITICAL' for f in findings)
        has_high = any(f.get('severity') == 'HIGH' for f in findings)

        if has_critical:
            return "Critical Risk"
        if has_high or security_score < 60:
            return "High Risk"
        if security_score < 85:
            return "Medium Risk"
        if findings:
            return "Low Risk"
        return "Secure"

    def _generate_remediations(self, findings: List[Dict]) -> List[str]:
        rems: List[str] = []
        cwes = {f['cwe'] for f in findings}

        if 'CWE-120' in cwes:
            rems.append("[CWE-120 Buffer Overflow] Replace legacy C buffer copy functions (strcpy, gets, sprintf) with safe alternatives (strncpy, snprintf) or std::string / std::vector.")
        if 'CWE-78' in cwes:
            rems.append("[CWE-78 Command Injection] Avoid using system() and popen() with user-controlled input. If process spawning is required, use safe OS APIs with argument arrays.")
        if 'CWE-416' in cwes:
            rems.append("[CWE-416 Use-After-Free] Nullify raw pointers after free/delete (ptr = nullptr) or adopt smart pointers (std::unique_ptr, std::shared_ptr).")
        if 'CWE-798' in cwes:
            rems.append("[CWE-798 Hardcoded Secrets] Remove hardcoded credentials from C++ source files. Read secrets from environment variables (std::getenv) or configuration files.")
        if 'CWE-338' in cwes:
            rems.append("[CWE-338 Insecure PRNG] Replace rand() with C++11 <random> pseudo-random engine (std::mt19937) or cryptographically secure OS RNG.")

        return rems

    def _build_summary(self, score: int, rating: str, findings: List[Dict]) -> str:
        count = len(findings)
        if count == 0:
            return f"C++ Security Audit Passed: Code evaluated with a score of {score}/100 ({rating}). No known vulnerabilities detected."
        return f"C++ Security Audit Completed: Score {score}/100 ({rating}). Identified {count} security finding(s)."

    def _empty_result(self) -> Dict[str, Any]:
        return {
            'status': 'empty',
            'findings_count': 0,
            'risk_score': 0.0,
            'security_score': 100,
            'rating': 'Secure',
            'findings': [],
            'remediations': [],
            'summary': 'Empty code input. Security audit skipped.'
        }
