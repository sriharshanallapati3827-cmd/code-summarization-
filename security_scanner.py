"""
security_scanner.py - Security Vulnerability Auditing Engine
============================================================
Adapted from the static analysis engine in NLP-based-Code-Summarizer-with-Security-Audits.
Provides:
  - 40+ CWE pattern checks across Injection, Secrets, Cryptography, Deserialization, SSRF, XXE, Path Traversal
  - Severity-first Risk Scoring (0.0 - 10.0) and Security Health Score (0 - 100)
  - Integration with PDG for Taint Tracking (sources flowing to dangerous sinks)
"""

import ast
import re
from typing import List, Dict, Tuple, Optional


CWE_CATEGORY_MAP = {
    'CWE-89':   'SQL Injection',
    'CWE-78':   'Command Injection',
    'CWE-94':   'Code Injection',
    'CWE-502':  'Unsafe Deserialization',
    'CWE-79':   'Cross-Site Scripting (XSS)',
    'CWE-327':  'Broken/Weak Cryptography',
    'CWE-338':  'Insecure PRNG / Predictable Random',
    'CWE-336':  'Predictable Seed',
    'CWE-798':  'Hardcoded Secrets / Credentials',
    'CWE-259':  'Hardcoded Password',
    'CWE-321':  'Hardcoded Cryptographic Key',
    'CWE-22':   'Path Traversal',
    'CWE-29':   'Path Traversal via Archive (Zip Slip)',
    'CWE-918':  'Server-Side Request Forgery (SSRF)',
    'CWE-611':  'XML External Entity (XXE)',
    'CWE-120':  'Buffer Overflow',
    'CWE-295':  'Improper Certificate Validation',
    'CWE-352':  'Cross-Site Request Forgery (CSRF)',
    'CWE-601':  'Open Redirect',
    'CWE-209':  'Information Exposure Through Error Message',
    'CWE-532':  'Sensitive Info Exposure in Logs',
    'CWE-117':  'Log Injection / Output Neutralization in Logs',
    'CWE-90':   'LDAP Injection',
    'CWE-643':  'XPath Injection',
    'CWE-943':  'NoSQL Injection',
    'CWE-377':  'Insecure Temporary File Creation',
    'CWE-732':  'Incorrect Permission Assignment',
    'CWE-703':  'Improper Check of Exceptional Conditions (Assert in Security)',
    'CWE-1333': 'Inefficient Regular Expression Complexity (ReDoS)',
    'CWE-489':  'Active Debug Flag in Production',
    'CWE-319':  'Cleartext Transmission of Sensitive Information',
}

PYTHON_SECURITY_PATTERNS = [
    # ── SQL Injection (CWE-89) ──
    (r'\.execute\s*\(\s*f["\']',
     '[CWE-89] SQL Injection: Dynamic f-string inside execute(). Use parameterized queries instead.',
     'HIGH', 'sec.py.sqli-fstring'),
    (r'\.execute\s*\([^)]*["\'].*\s*%\s*',
     '[CWE-89] SQL Injection: %-formatting in SQL execute(). Use parameterized queries.',
     'HIGH', 'sec.py.sqli-format'),
    (r'\.execute\s*\(\s*\w[^"\'()\n]*\+',
     '[CWE-89] SQL Injection: String concatenation in execute(). Use parameterized queries.',
     'HIGH', 'sec.py.sqli-concat'),
    (r'\.executemany\s*\(\s*\w[^"\'()\n]*\+',
     '[CWE-89] SQL Injection: String concatenation in executemany().',
     'HIGH', 'sec.py.sqli-executemany'),
    (r'\.raw\s*\(\s*\w[^"\'()\n]*\+',
     '[CWE-89] SQL Injection: Raw ORM query with string concatenation.',
     'HIGH', 'sec.py.sqli-orm-raw'),
    (r'cursor\.(execute|executemany)\s*\(\s*["\'].*\{[a-zA-Z_]',
     '[CWE-89] SQL Injection: str.format() used to construct SQL query. Use query placeholders.',
     'HIGH', 'sec.py.sqli-strformat'),

    # ── Command Injection (CWE-78) ──
    (r'subprocess\.(Popen|call|run|check_call|check_output)\s*\([^)]*shell\s*=\s*True',
     '[CWE-78] Command Injection: subprocess call with shell=True. Pass command arguments as a list without shell=True.',
     'CRITICAL', 'sec.py.cmd-shell-true'),
    (r'\bos\.system\s*\(',
     '[CWE-78] Command Injection: os.system() is dangerous. Use subprocess.run(..., shell=False).',
     'CRITICAL', 'sec.py.cmd-os-system'),
    (r'\bos\.popen\s*\(',
     '[CWE-78] Command Injection: os.popen() spawns a shell. Use subprocess with safe list args.',
     'CRITICAL', 'sec.py.cmd-os-popen'),
    (r'\bpty\.spawn\s*\(',
     '[CWE-78] Command Injection: pty.spawn() can spawn arbitrary interactive shell sessions.',
     'HIGH', 'sec.py.cmd-pty-spawn'),

    # ── Code Injection (CWE-94) ──
    (r'\beval\s*\(',
     '[CWE-94] Code Injection: eval() executes arbitrary Python code. Use ast.literal_eval() if parsing literals.',
     'CRITICAL', 'sec.py.code-eval'),
    (r'\bexec\s*\(',
     '[CWE-94] Code Injection: exec() dynamically executes code. Avoid on user-controlled inputs.',
     'CRITICAL', 'sec.py.code-exec'),
    (r'\bcompile\s*\(\s*\w[^,)]*,\s*[^,)]*,\s*["\']exec["\']',
     '[CWE-94] Code Injection: Dynamic compile() with exec mode.',
     'HIGH', 'sec.py.code-compile'),
    (r'jinja2\.Template\s*\(\s*\w',
     '[CWE-94] Server-Side Template Injection (SSTI): Jinja2 template instantiated from dynamic variable.',
     'HIGH', 'sec.py.ssti-jinja2'),
    (r'render_template_string\s*\(',
     '[CWE-94] Server-Side Template Injection (SSTI): render_template_string() with dynamic input leads to RCE.',
     'HIGH', 'sec.py.ssti-flask-render'),

    # ── Insecure Deserialization (CWE-502) ──
    (r'\bpickle\.loads?\s*\(',
     '[CWE-502] Unsafe Deserialization: pickle can execute arbitrary code during load. Use JSON or safer formats.',
     'CRITICAL', 'sec.py.deser-pickle'),
    (r'\bcPickle\.loads?\s*\(',
     '[CWE-502] Unsafe Deserialization via cPickle. Use JSON or safe loaders.',
     'CRITICAL', 'sec.py.deser-cpickle'),
    (r'\byaml\.load\s*\([^,)]*\)',
     '[CWE-502] Unsafe YAML load: yaml.load() without Loader=SafeLoader can execute code. Use yaml.safe_load().',
     'HIGH', 'sec.py.deser-yaml'),
    (r'\bjsonpickle\.decode\s*\(',
     '[CWE-502] Unsafe Deserialization: jsonpickle.decode() on untrusted data can lead to arbitrary code execution.',
     'HIGH', 'sec.py.deser-jsonpickle'),
    (r'\bdill\.loads?\s*\(',
     '[CWE-502] Unsafe Deserialization via dill. Avoid on untrusted payloads.',
     'HIGH', 'sec.py.deser-dill'),
    (r'\bmarshal\.loads?\s*\(',
     '[CWE-502] Unsafe Deserialization: marshal is intended for Python byte code, not untrusted data.',
     'HIGH', 'sec.py.deser-marshal'),
    (r'\bshelve\.open\s*\(',
     '[CWE-502] Unsafe Deserialization: shelve uses pickle under the hood, vulnerable to object injection.',
     'HIGH', 'sec.py.deser-shelve'),

    # ── Hardcoded Secrets & Credentials (CWE-798, CWE-259, CWE-321) ──
    (r'AKIA[0-9A-Z]{16}',
     '[CWE-798] Hardcoded AWS Access Key ID detected. Store credentials in environment variables.',
     'CRITICAL', 'sec.shared.aws-key'),
    (r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
     '[CWE-259] Hardcoded plaintext password detected. Use environment variables or a secret vault.',
     'HIGH', 'sec.py.secrets-password'),
    (r'(?i)(secret_key|api_key|access_token|private_key|jwt_secret)\s*=\s*["\'][^"\']{8,}["\']',
     '[CWE-321] Hardcoded secret or API key. Avoid committing tokens to source control.',
     'HIGH', 'sec.py.secrets-apikey'),
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
     '[CWE-321] Hardcoded Private Key block found in source file.',
     'CRITICAL', 'sec.shared.private-key-header'),

    # ── Broken / Weak Cryptography (CWE-327, CWE-338, CWE-295) ──
    (r'\bhashlib\.md5\s*\(',
     '[CWE-327] Broken Cryptographic Hash: MD5 is vulnerable to collision attacks. Use hashlib.sha256() or higher.',
     'MEDIUM', 'sec.py.crypto-md5'),
    (r'\bhashlib\.sha1\s*\(',
     '[CWE-327] Weak Hash: SHA-1 is cryptographically weak. Use SHA-256 or SHA-3.',
     'MEDIUM', 'sec.py.crypto-sha1'),
    (r'\bCipher\.(DES|ARC4|Blowfish)\b|\bCrypto\.Cipher\.(DES|ARC4|Blowfish)\b',
     '[CWE-327] Weak Cipher: Insecure legacy cipher algorithm. Use AES-256-GCM or ChaCha20.',
     'HIGH', 'sec.py.crypto-weak-cipher'),
    (r'MODE_ECB\b',
     '[CWE-327] Insecure Cipher Mode: ECB mode does not provide serious pattern confidentiality. Use GCM or CBC.',
     'HIGH', 'sec.py.crypto-ecb'),
    (r'\brandom\.(random|randint|choice|randrange|sample)\s*\(',
     '[CWE-338] Insecure PRNG: random module is not cryptographically secure. Use the secrets module for security tokens.',
     'LOW', 'sec.py.crypto-prng'),
    (r'ssl\._create_unverified_context\s*\(',
     '[CWE-295] Disabled SSL Verification: Disabling certificate validation enables Man-in-the-Middle (MITM) attacks.',
     'CRITICAL', 'sec.py.crypto-ssl-noverify'),
    (r'requests\.\w+\s*\([^)]*verify\s*=\s*False',
     '[CWE-295] Disabled SSL Verification in requests (verify=False). Re-enable SSL verification.',
     'HIGH', 'sec.py.requests-ssl-false'),

    # ── Path Traversal & Zip Slip (CWE-22, CWE-29) ──
    (r'open\s*\([^,)]*\+[^,)]*\)',
     '[CWE-22] Potential Path Traversal: Concatenating variables into open() path without validation. Use os.path.abspath validation or pathlib.Path.resolve().',
     'MEDIUM', 'sec.py.path-open-concat'),
    (r'\.extractall\s*\([^)]*\)',
     '[CWE-29] Zip Slip Vulnerability: Unsanitized extractall() can overwrite system files via ../ paths.',
     'HIGH', 'sec.py.path-zip-slip'),

    # ── Cross-Site Scripting (XSS) (CWE-79) ──
    (r'\bmark_safe\s*\(|Markup\s*\(',
     '[CWE-79] Cross-Site Scripting (XSS): Disabling auto-escaping via mark_safe() or Markup(). Ensure inputs are sanitized.',
     'HIGH', 'sec.py.xss-mark-safe'),

    # ── XML External Entity (XXE) (CWE-611) ──
    (r'xml\.etree\.ElementTree\.parse\s*\(',
     '[CWE-611] Potential XXE: Standard ElementTree.parse is vulnerable to XML Entity Expansion. Use defusedxml.',
     'MEDIUM', 'sec.py.xxe-etree'),

    # ── Server-Side Request Forgery (SSRF) (CWE-918) ──
    (r'(requests\.get|requests\.post|urllib\.request\.urlopen|httpx\.get)\s*\(\s*[a-zA-Z_]\w*',
     '[CWE-918] Potential SSRF: Network call with dynamic variable destination. Allowlist permitted hostnames/IPs.',
     'MEDIUM', 'sec.py.ssrf-dynamic-url'),

    # ── CSRF Exemption (CWE-352) ──
    (r'@csrf_exempt',
     '[CWE-352] CSRF Protection Disabled: @csrf_exempt disables cross-site request forgery checks on this endpoint.',
     'HIGH', 'sec.py.csrf-exempt'),

    # ── Open Redirect (CWE-601) ──
    (r'redirect\s*\(\s*request\.(args|GET|values|form)\[',
     '[CWE-601] Open Redirect: Untrusted redirect target directly retrieved from request parameters.',
     'MEDIUM', 'sec.py.open-redirect'),

    # ── Logging Vulnerabilities (CWE-532, CWE-117) ──
    (r'logging\.(info|debug|warning|error)\s*\([^)]*(password|token|secret|key|pwd)',
     '[CWE-532] Sensitive Data in Logs: Logging credential-like variables may leak secrets into monitoring services.',
     'HIGH', 'sec.py.log-secrets'),

    # ── Insecure Temporary Files (CWE-377) ──
    (r'\btempfile\.mktemp\s*\(',
     '[CWE-377] Insecure Temporary File: tempfile.mktemp() is deprecated and vulnerable to symlink race conditions. Use tempfile.NamedTemporaryFile().',
     'HIGH', 'sec.py.insecure-tempfile'),

    # ── Incorrect Permissions (CWE-732) ──
    (r'os\.chmod\s*\([^)]*0[oO]?777',
     '[CWE-732] Overly Permissive File Permissions: Setting permissions to 777 grants full world read/write/execute.',
     'HIGH', 'sec.py.perms-chmod-777'),

    # ── Misuse of Assert for Security (CWE-703) ──
    (r'assert\s+.*(admin|role|permission|authenticated|token|is_valid|auth)',
     '[CWE-703] Security Check via Assert: assert statements are stripped when Python runs with optimization (-O / -OO). Use explicit if/raise exceptions.',
     'HIGH', 'sec.py.assert-in-security'),

    # ── Insecure Configuration & Cleartext (CWE-489, CWE-319) ──
    (r'app\.run\s*\([^)]*debug\s*=\s*True|DEBUG\s*=\s*True',
     '[CWE-489] Active Debug Flag: Debug mode exposes interactive debuggers or stack traces to end users.',
     'HIGH', 'sec.py.debug-flag-active'),
    (r'http://[a-zA-Z0-9_\-\.]+\.(com|org|net|io|api)',
     '[CWE-319] Cleartext HTTP Transmission: Sensitive web traffic over unencrypted http://. Use https://.',
     'LOW', 'sec.py.cleartext-http'),
]


class SecurityAuditor:
    """
    Scans source code for security vulnerabilities, generates risk scores,
    and performs PDG-integrated Taint Analysis.
    """

    def __init__(self, custom_patterns=None):
        self.patterns = custom_patterns or PYTHON_SECURITY_PATTERNS

    def audit_code(self, source_code: str) -> Dict:
        """
        Executes static security audit on Python source code.
        Returns detailed findings, risk score, security score, and remediation steps.
        """
        if not source_code or not source_code.strip():
            return self._empty_result()

        lines = source_code.splitlines()
        findings = []
        seen = set()

        for pattern, message, severity, rule_id in self.patterns:
            for idx, line in enumerate(lines):
                if re.search(pattern, line):
                    key = (rule_id, idx + 1)
                    if key not in seen:
                        seen.add(key)
                        cwe_match = re.search(r'\[(CWE-\d+)\]', message)
                        cwe_id = cwe_match.group(1) if cwe_match else 'CWE-Other'
                        category = CWE_CATEGORY_MAP.get(cwe_id, 'Security Issue')

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
            'risk_score': risk_score,           # 0.0 - 10.0 (lower is safer)
            'security_score': security_score,   # 0 - 100 (higher is safer)
            'rating': rating,
            'findings': findings,
            'remediations': remediations,
            'summary': self._build_summary(security_score, rating, findings)
        }

    def analyze_pdg_taint(self, source_code: str, pdg_graph: dict) -> List[Dict]:
        """
        Correlates PDG data dependency edges with security findings.
        Flags when user input (source) flows into a security-sensitive operation (sink).
        """
        tainted_flows = []
        audit_result = self.audit_code(source_code)
        findings = audit_result.get('findings', [])

        if not findings or not pdg_graph or not pdg_graph.get('edges'):
            return tainted_flows

        edges = pdg_graph.get('edges', [])
        nodes = pdg_graph.get('nodes', {})

        # Dangerous sinks from findings
        sensitive_lines = {f['line']: f for f in findings}

        # Check data dependency edges
        for edge in edges:
            if edge.get('kind') == 'Data':
                source_node = edge.get('source', '')
                target_node = edge.get('target', '')
                var_name = edge.get('label', '')

                source_label = nodes.get(source_node, '')
                target_label = nodes.get(target_node, '')

                # If target performs a dangerous operation
                is_dangerous_sink = any(k in target_label.lower() for k in ['execute', 'system', 'eval', 'popen', 'loads', 'pickle'])
                if is_dangerous_sink:
                    tainted_flows.append({
                        'source': source_label,
                        'target': target_label,
                        'variable': var_name,
                        'description': f"Variable '{var_name}' flows from [{source_label}] into sensitive operation [{target_label}]"
                    })

        return tainted_flows

    def _compute_risk_score(self, findings: List[Dict]) -> float:
        """
        Computes 0.0 to 10.0 risk score based on severity distribution.
        """
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
        # Deduct 1 count of dominant severity so it isn't double-counted
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
        rems = []
        seen_cwes = set()
        for f in findings:
            cwe = f.get('cwe')
            if cwe in seen_cwes:
                continue
            seen_cwes.add(cwe)

            if cwe == 'CWE-89':
                rems.append("Replace dynamic SQL strings with parameterized queries (e.g. cursor.execute('... ?', (val,)))")
            elif cwe == 'CWE-78':
                rems.append("Avoid os.system() and shell=True. Use subprocess.run(['cmd', 'arg1'], shell=False)")
            elif cwe == 'CWE-94':
                rems.append("Remove eval() or exec(). Use safe parsers like ast.literal_eval() for string evaluation")
            elif cwe == 'CWE-502':
                rems.append("Avoid pickle for untrusted payloads. Use json.loads() or yaml.safe_load()")
            elif cwe in ['CWE-798', 'CWE-259', 'CWE-321']:
                rems.append("Remove hardcoded credentials. Store passwords and API keys in environment variables (.env)")
            elif cwe in ['CWE-327', 'CWE-338']:
                rems.append("Upgrade weak hashes to SHA-256 and use Python's 'secrets' module instead of 'random'")
            elif cwe == 'CWE-295':
                rems.append("Enable TLS/SSL verification (remove verify=False or unverified contexts)")
            elif cwe == 'CWE-22':
                rems.append("Validate file paths using os.path.abspath or pathlib.Path.resolve() before opening")
            elif cwe == 'CWE-29':
                rems.append("Sanitize archive member paths before calling extractall() to prevent Zip Slip directory traversal")
            elif cwe == 'CWE-79':
                rems.append("Avoid mark_safe() or Markup() on dynamic inputs; leverage auto-escaping to mitigate XSS")
            elif cwe == 'CWE-352':
                rems.append("Enable CSRF protection tokens; do not disable checks via @csrf_exempt")
            elif cwe == 'CWE-601':
                rems.append("Validate target URLs against an allowed domain whitelist before issuing HTTP redirects")
            elif cwe == 'CWE-377':
                rems.append("Use tempfile.NamedTemporaryFile() or tempfile.mkstemp() instead of deprecated mktemp()")
            elif cwe == 'CWE-732':
                rems.append("Restrict file permissions to minimal necessary access (e.g., 0o600 or 0o700 instead of 0o777)")
            elif cwe == 'CWE-703':
                rems.append("Do not rely on assert for access control or validation; use explicit conditional checks and raise exceptions")
            elif cwe == 'CWE-489':
                rems.append("Disable debug flags (DEBUG=False, app.run(debug=False)) in production deployments")
            elif cwe == 'CWE-319':
                rems.append("Encrypt data in transit by replacing unencrypted HTTP/FTP endpoints with HTTPS/SFTP")
            elif cwe in ['CWE-532', 'CWE-117']:
                rems.append("Sanitize logged output and mask secrets/passwords before writing to log streams")

        if not rems:
            rems.append("No active security vulnerabilities detected; code adheres to basic security best practices.")
        return rems

    def _build_summary(self, score: int, rating: str, findings: List[Dict]) -> str:
        if not findings:
            return f"{rating} (Security Score: 100/100) — No known CWE vulnerabilities found."
        top_cwe = findings[0].get('cwe', 'Unknown')
        top_cat = findings[0].get('category', 'Vulnerability')
        return f"{rating} (Security Score: {score}/100) — {len(findings)} issues found (Highest severity: {top_cwe} - {top_cat})."

    def _empty_result(self) -> Dict:
        return {
            'status': 'empty',
            'findings_count': 0,
            'risk_score': 0.0,
            'security_score': 100,
            'rating': 'Secure',
            'findings': [],
            'remediations': ["Provide Python source code to perform security audit."],
            'summary': "No code provided for security audit."
        }


def audit_security(source_code: str) -> Dict:
    """Convenience helper function to run security audit directly."""
    auditor = SecurityAuditor()
    return auditor.audit_code(source_code)


if __name__ == "__main__":
    test_code = '''
import os
import pickle
import hashlib

def run_user_cmd(user_input):
    api_key = "AKIA1234567890ABCDEF"
    password = "admin_super_secret"
    os.system("ls " + user_input)
    data = pickle.loads(user_input)
    token = hashlib.md5(user_input.encode()).hexdigest()
    return token
'''
    result = audit_security(test_code)
    print("Security Audit Findings:", result['findings_count'])
    print("Risk Score:", result['risk_score'])
    print("Security Score:", result['security_score'])
    print("Rating:", result['rating'])
    for finding in result['findings']:
        print(f" - [{finding['severity']}] {finding['cwe']}: {finding['message']}")
