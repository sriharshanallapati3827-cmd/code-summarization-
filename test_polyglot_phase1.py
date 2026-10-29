"""
test_polyglot_phase1.py
━━━━━━━━━━━━━━━━━━━━━━━━
Unit verification suite for Polyglot Phase 1:
1. Language detection (Python vs C++)
2. Tree-sitter C++ AST parsing
3. Tree-sitter Python AST parsing
4. Syntax error node diagnosis in malformed C++
"""

import unittest
from polyglot.language_detector import detect_language, SupportedLanguage
from polyglot.parser_factory import ParserFactory


class TestPolyglotPhase1(unittest.TestCase):

    def test_language_detection_by_filename(self):
        self.assertEqual(detect_language("", filename="main.cpp"), SupportedLanguage.CPP)
        self.assertEqual(detect_language("", filename="solution.cc"), SupportedLanguage.CPP)
        self.assertEqual(detect_language("", filename="header.hpp"), SupportedLanguage.CPP)
        self.assertEqual(detect_language("", filename="script.py"), SupportedLanguage.PYTHON)

    def test_language_detection_by_syntax(self):
        cpp_code = """
        #include <iostream>
        using namespace std;
        int main() {
            cout << "Hello World" << endl;
            return 0;
        }
        """
        self.assertEqual(detect_language(cpp_code), SupportedLanguage.CPP)

        py_code = """
        def compute_sum(values):
            total = 0
            for v in values:
                total += v
            return total
        """
        self.assertEqual(detect_language(py_code), SupportedLanguage.PYTHON)

    def test_cpp_valid_ast_parsing(self):
        cpp_code = """
        #include <iostream>
        #include <vector>

        int sumElements(const std::vector<int>& nums) {
            int total = 0;
            for (int n : nums) {
                total += n;
            }
            return total;
        }

        int main() {
            std::vector<int> data = {1, 2, 3, 4, 5};
            std::cout << sumElements(data) << std::endl;
            return 0;
        }
        """
        parsed = ParserFactory.parse(cpp_code, language=SupportedLanguage.CPP)
        self.assertEqual(parsed.language, SupportedLanguage.CPP)
        self.assertTrue(parsed.is_valid)
        self.assertEqual(len(parsed.diagnostics), 0)
        self.assertEqual(parsed.root_node.type, "translation_unit")

        # Verify child function_definition nodes exist
        func_nodes = [child for child in parsed.root_node.children if child.type == "function_definition"]
        self.assertEqual(len(func_nodes), 2)  # sumElements and main

    def test_cpp_syntax_error_detection(self):
        # Malformed C++: missing semicolon and unmatched brace
        broken_cpp = """
        int main() {
            int x = 10
            return 0;
        """
        parsed = ParserFactory.parse(broken_cpp, language=SupportedLanguage.CPP)
        self.assertEqual(parsed.language, SupportedLanguage.CPP)
        self.assertFalse(parsed.is_valid)
        self.assertTrue(parsed.has_errors)
        self.assertGreater(len(parsed.diagnostics), 0)

    def test_python_tree_sitter_parsing(self):
        py_code = """
        def greet(name: str) -> str:
            return f"Hello {name}"
        """
        parsed = ParserFactory.parse(py_code, language=SupportedLanguage.PYTHON)
        self.assertEqual(parsed.language, SupportedLanguage.PYTHON)
        self.assertTrue(parsed.is_valid)
        self.assertEqual(parsed.root_node.type, "module")


if __name__ == "__main__":
    unittest.main()
