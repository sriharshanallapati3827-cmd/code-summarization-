"""
test_polyglot_phase6.py
━━━━━━━━━━━━━━━━━━━━━━━
Test suite for Phase 6: Full Polyglot Pipeline & Dashboard Integration.
Verifies:
  1. Full 5-agent pipeline execution on Python code.
  2. Full 5-agent pipeline execution on C++ code (AST, PDG, Green, CWEs, Doxygen).
  3. C++ Self-Healing Agent execution in the pipeline on broken C++ syntax.
  4. C++ Security Threat Hunter in the pipeline detecting CWE-120 and CWE-78.
  5. C++ Doxygen docstring output generation.
  6. Presets dictionary availability in gui_app.
"""

import unittest
import textwrap
from agent_controller import AgentController, run_agentic_pipeline
from polyglot.cpp_samples import CPP_SAMPLE_CODES


class TestPolyglotPhase6(unittest.TestCase):

    def setUp(self):
        self.controller = AgentController()

    def test_pipeline_python_execution(self):
        """Test full 5-agent pipeline runs cleanly on Python."""
        py_code = textwrap.dedent("""
            def compute_interest(principal, rate, years):
                interest = (principal * rate * years) / 100.0
                total = principal + interest
                return total
        """).strip()
        ctx = self.controller.run_workflow(py_code, language="python")
        self.assertEqual(ctx.language, "python")
        self.assertFalse(ctx.dfa_trapped)
        self.assertFalse(ctx.input_rejected)
        self.assertEqual(ctx.healing_report.get('status'), 'valid')
        self.assertIn("def compute_interest", ctx.docstrings)
        self.assertIn("Args:", ctx.docstrings)

    def test_pipeline_cpp_execution(self):
        """Test full 5-agent pipeline runs cleanly on C++."""
        cpp_code = """
        #include <iostream>
        #include <vector>

        int sum_numbers(const std::vector<int>& arr) {
            int total = 0;
            for (int val : arr) total += val;
            return total;
        }

        int main() {
            std::vector<int> vals = {1, 2, 3};
            std::cout << sum_numbers(vals) << std::endl;
            return 0;
        }
        """
        ctx = self.controller.run_workflow(cpp_code, language="cpp")
        self.assertEqual(ctx.language, "cpp")
        self.assertFalse(ctx.dfa_trapped)
        self.assertFalse(ctx.input_rejected)
        self.assertGreater(len(ctx.pdg_graph.get('nodes', {})), 0)
        self.assertEqual(ctx.green_profile.get('status'), 'ok')
        self.assertEqual(ctx.security_profile.get('status'), 'ok')
        self.assertIn("/**", ctx.docstrings)
        self.assertIn("@brief", ctx.docstrings)
        self.assertIn("@param", ctx.docstrings)

    def test_pipeline_cpp_self_healing(self):
        """Test that Agent 0 in pipeline repairs broken C++ syntax and reports repair_details."""
        broken_cpp = """
        #include <vector>

        int calculate_metrics(int factor, int count) {
            int total = 0
            for (int i = 0; i < count; i++) {
                if (i % 2 == 0) {
                    total += i * factor
                }
            return total;
        }
        """
        ctx = self.controller.run_workflow(broken_cpp, language="cpp")
        self.assertEqual(ctx.language, "cpp")
        self.assertTrue(ctx.healing_report.get('is_healed'))
        self.assertGreater(len(ctx.healing_report.get('repairs', [])), 0)
        self.assertGreater(len(ctx.healing_report.get('repair_details', [])), 0)
        # Semicolon should be appended to total = 0;
        self.assertIn("int total = 0;", ctx.clean_code)

    def test_pipeline_cpp_security_audit_cwe(self):
        """Test that Agent 3 in pipeline identifies CWE-120 and CWE-78 in vulnerable C++ sample."""
        vuln_cpp = CPP_SAMPLE_CODES["C++ Buffer Overflow & Insecure system() Demo"]
        ctx = self.controller.run_workflow(vuln_cpp, language="cpp")
        self.assertEqual(ctx.language, "cpp")
        findings = ctx.security_profile.get('findings', [])
        cwe_list = [f.get('cwe') for f in findings]
        self.assertIn("CWE-120", cwe_list)
        self.assertIn("CWE-78", cwe_list)

    def test_gui_presets_structure(self):
        """Test that C++ preset sample dictionaries are fully populated."""
        self.assertGreaterEqual(len(CPP_SAMPLE_CODES), 4)
        self.assertIn("C++ Buffer Overflow & Insecure system() Demo", CPP_SAMPLE_CODES)
        self.assertIn("C++ Broken Syntax / Missing Semicolons (Self-Healing Demo)", CPP_SAMPLE_CODES)
        self.assertIn("C++ O(N²) Nested Loop Complexity Demo", CPP_SAMPLE_CODES)
        self.assertIn("C++ Clean RAII & Memory-Safe Logic", CPP_SAMPLE_CODES)


if __name__ == "__main__":
    unittest.main()
