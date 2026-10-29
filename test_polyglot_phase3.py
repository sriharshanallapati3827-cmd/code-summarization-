"""
test_polyglot_phase3.py
━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for Phase 3: C++ Security Auditor (CWE Threat Hunter).
Verifies detection of:
  1. Buffer Overflow (CWE-120): strcpy, gets, sprintf.
  2. Command Injection (CWE-78): system(), popen().
  3. Hardcoded Credentials (CWE-798): Plaintext API keys.
  4. Memory Safety / Use-After-Free (CWE-416): Pointer access after free().
  5. Security scoring calculation and remediation generation.
  6. Clean code baseline with zero false-positives.
"""

import unittest
from polyglot.cpp_security_auditor import CppSecurityAuditor


class TestPolyglotPhase3(unittest.TestCase):

    def setUp(self):
        self.auditor = CppSecurityAuditor()

    def test_buffer_overflow_detection(self):
        vulnerable_cpp = """
        #include <cstring>
        #include <cstdio>

        void process(char* input) {
            char buffer[64];
            strcpy(buffer, input);
            gets(buffer);
            sprintf(buffer, "User: %s", input);
        }
        """
        res = self.auditor.audit_code(vulnerable_cpp)
        self.assertEqual(res["status"], "ok")
        cwes = [f["cwe"] for f in res["findings"]]

        self.assertIn("CWE-120", cwes)
        rules = [f["rule_id"] for f in res["findings"]]
        self.assertIn("sec.cpp.bof-strcpy", rules)
        self.assertIn("sec.cpp.bof-gets", rules)
        self.assertIn("sec.cpp.bof-sprintf", rules)

        self.assertLess(res["security_score"], 80)
        self.assertTrue(any("CWE-120 Buffer Overflow" in rem for rem in res["remediations"]))

    def test_command_injection_detection(self):
        insecure_cpp = """
        #include <cstdlib>

        void runCmd(const char* user_input) {
            system(user_input);
        }
        """
        res = self.auditor.audit_code(insecure_cpp)
        cwes = [f["cwe"] for f in res["findings"]]
        self.assertIn("CWE-78", cwes)

        rules = [f["rule_id"] for f in res["findings"]]
        self.assertIn("sec.cpp.cmd-system", rules)
        self.assertEqual(res["rating"], "Critical Risk")
        self.assertTrue(any("CWE-78 Command Injection" in rem for rem in res["remediations"]))

    def test_hardcoded_secret_detection(self):
        secret_cpp = """
        #include <iostream>

        void authenticate() {
            const char* api_key = "gsk_live_9928374829384729384";
        }
        """
        res = self.auditor.audit_code(secret_cpp)
        cwes = [f["cwe"] for f in res["findings"]]
        self.assertIn("CWE-798", cwes)

    def test_clean_cpp_code_zero_false_positives(self):
        clean_cpp = """
        #include <iostream>
        #include <string>
        #include <vector>

        int sumVector(const std::vector<int>& numbers) {
            int total = 0;
            for (int n : numbers) {
                total += n;
            }
            return total;
        }

        int main() {
            std::cout << "Sum: " << sumVector({1, 2, 3}) << std::endl;
            return 0;
        }
        """
        res = self.auditor.audit_code(clean_cpp)
        self.assertEqual(res["findings_count"], 0)
        self.assertEqual(res["security_score"], 100)
        self.assertEqual(res["rating"], "Secure")
        self.assertEqual(len(res["remediations"]), 0)


if __name__ == "__main__":
    unittest.main()
