"""
test_polyglot_phase4.py
━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for Phase 4: C++ Syntax Self-Healer.
Verifies autonomous repair of:
  1. Missing semicolons ';' on variable declarations, assignments, and returns.
  2. Unclosed curly braces '{}' block termination.
  3. Missing standard headers (#include <iostream>).
  4. Generation of rich before/after repair_details.
  5. Clean C++ code baseline passes with 0 false repairs.
"""

import unittest
from polyglot.cpp_self_healing import CppSelfHealingAgent, heal_cpp_code


class TestPolyglotPhase4(unittest.TestCase):

    def setUp(self):
        self.healer = CppSelfHealingAgent()

    def test_heal_missing_semicolons(self):
        broken_cpp = """
#include <iostream>

int main() {
    int a = 5
    int b = 10;
    std::cout << a + b << std::endl
    return 0
}
"""
        res = self.healer.heal(broken_cpp)
        self.assertTrue(res["is_healed"], "Expected C++ code to be healed")
        self.assertGreaterEqual(len(res["repairs"]), 2)
        self.assertGreaterEqual(len(res["repair_details"]), 2)

        # Verify repaired clean code is now syntactically valid
        clean = res["clean_code"]
        self.assertIn("int a = 5;", clean)
        self.assertIn("return 0;", clean)

        # Verify structured detail attributes
        first_detail = res["repair_details"][0]
        self.assertIn("line", first_detail)
        self.assertIn("before", first_detail)
        self.assertIn("after", first_detail)
        self.assertEqual(first_detail["rule"], "SYN-CPP-001: Missing Semicolon")

    def test_heal_unclosed_braces(self):
        broken_cpp = """
#include <iostream>

int main() {
    int total = 0;
    for (int i = 0; i < 5; i++) {
        total += i;
"""
        res = self.healer.heal(broken_cpp)
        self.assertTrue(res["is_healed"])
        clean = res["clean_code"]
        self.assertTrue(clean.strip().endswith("}"))

    def test_heal_missing_iostream_include(self):
        broken_cpp = """
int main() {
    std::cout << "Hello" << std::endl;
    return 0;
}
"""
        res = self.healer.heal(broken_cpp)
        self.assertTrue(res["is_healed"])
        self.assertIn("#include <iostream>", res["clean_code"])

    def test_clean_cpp_zero_false_repairs(self):
        clean_cpp = """
#include <iostream>

int main() {
    int x = 42;
    std::cout << x << std::endl;
    return 0;
}
"""
        res = self.healer.heal(clean_cpp)
        self.assertEqual(res["status"], "valid")
        self.assertFalse(res["is_healed"])
        self.assertEqual(len(res["repairs"]), 0)
        self.assertEqual(len(res["repair_details"]), 0)


if __name__ == "__main__":
    unittest.main()
