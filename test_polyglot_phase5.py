"""
test_polyglot_phase5.py
━━━━━━━━━━━━━━━━━━━━━━━
Test suite for Phase 5: C++ Dual-Mode Execution & Profiler Engine.
Verifies:
  1. Compiled subprocess sandbox execution with g++ (when compiler present).
  2. C++ AST Gatekeeper blocking critical CWE-78 system() calls.
  3. Graceful static degradation mode calculating Big-O from C++ AST.
  4. Timeout watchdog terminating long-running / infinite loop C++ code.
  5. Transparent polyglot routing in HardwareProfiler.profile_code_snippet().
"""

import unittest
from polyglot.cpp_profiler import CppProfiler, profile_cpp_code
from hardware_profiler import HardwareProfiler, profile_code


class TestPolyglotPhase5(unittest.TestCase):

    def setUp(self):
        self.profiler = CppProfiler(timeout_seconds=3.0, memory_limit_mb=50.0)

    def test_compiled_execution_benign_cpp(self):
        """Test compiling and executing a benign C++ program in sandbox."""
        cpp_code = """
        #include <iostream>
        #include <vector>

        int main() {
            std::vector<int> numbers;
            for (int i = 0; i < 50000; ++i) {
                numbers.push_back(i * 3);
            }
            return 0;
        }
        """
        result = self.profiler.profile(cpp_code)
        self.assertFalse(result['blocked'])
        self.assertFalse(result['timed_out'])
        self.assertFalse(result['memory_exceeded'])
        self.assertEqual(result['status'], 'ok')
        self.assertGreater(result['latency_ms'], 0.0)
        self.assertGreaterEqual(result['dynamic_energy_kwh'], 0.0)
        self.assertIn(result['execution_mode'], ('compiled_sandbox', 'static_degradation'))

    def test_cpp_gatekeeper_blocks_command_injection(self):
        """Test that C++ AST Gatekeeper intercepts critical CWE-78 system() calls."""
        malicious_cpp = """
        #include <cstdlib>

        int main() {
            system("calc.exe");
            return 0;
        }
        """
        result = self.profiler.profile(malicious_cpp)
        self.assertTrue(result['blocked'])
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['execution_mode'], 'gatekeeper_blocked')
        self.assertTrue(any("system" in r.lower() for r in result['block_reasons']))

    def test_graceful_static_degradation_nested_loops(self):
        """Test static AST complexity estimation when compiler is bypassed or unavailable."""
        nested_cpp = """
        #include <vector>

        void bubble_sort(std::vector<int>& arr) {
            int n = arr.size();
            for (int i = 0; i < n; i++) {
                for (int j = 0; j < n - i - 1; j++) {
                    if (arr[j] > arr[j + 1]) {
                        int temp = arr[j];
                        arr[j] = arr[j + 1];
                        arr[j + 1] = temp;
                    }
                }
            }
        }
        """
        result = self.profiler.profile(nested_cpp, force_static=True)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['execution_mode'], 'static_degradation')
        self.assertEqual(result['complexity'], 'O(N^2)')
        self.assertEqual(result['max_loop_depth'], 2)
        self.assertGreater(result['latency_ms'], 0.0)
        self.assertGreater(result['dynamic_energy_kwh'], 0.0)
        self.assertIn("static-pdg-degradation", result['profiler_backend'])

    def test_timeout_watchdog(self):
        """Test that an infinite loop C++ snippet is terminated by watchdog."""
        if not self.profiler.compiler_path:
            self.skipTest("No C++ compiler available to test binary timeout")

        infinite_loop_cpp = """
        int main() {
            while (true) {
                // busy wait
            }
            return 0;
        }
        """
        short_timeout_prof = CppProfiler(timeout_seconds=0.5)
        result = short_timeout_prof.profile(infinite_loop_cpp)
        self.assertTrue(result['timed_out'])
        self.assertEqual(result['status'], 'timeout')
        self.assertIn("watchdog", result['profiler_backend'])

    def test_hardware_profiler_polyglot_routing(self):
        """Test that HardwareProfiler transparently handles both Python and C++ snippets."""
        hw_profiler = HardwareProfiler()

        # Python snippet
        py_snippet = "x = sum(i * 2 for i in range(1000))"
        py_res = hw_profiler.profile_code_snippet(py_snippet)
        self.assertFalse(py_res['blocked'])
        self.assertEqual(py_res['status'], 'ok')
        self.assertIn("subprocess", py_res['profiler_backend'])

        # C++ snippet
        cpp_snippet = """
        #include <iostream>
        int main() {
            int total = 0;
            for (int i = 0; i < 1000; i++) total += i;
            return 0;
        }
        """
        cpp_res = hw_profiler.profile_code_snippet(cpp_snippet)
        self.assertFalse(cpp_res['blocked'])
        self.assertEqual(cpp_res['status'], 'ok')
        self.assertIn(cpp_res['execution_mode'], ('compiled_sandbox', 'static_degradation'))


if __name__ == "__main__":
    unittest.main()
