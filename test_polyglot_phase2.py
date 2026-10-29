"""
test_polyglot_phase2.py
━━━━━━━━━━━━━━━━━━━━━━━━
Unit tests for Phase 2: C++ Program Dependence Graph (PDG) Builder.
Verifies:
  1. Control flow dependency extraction for C++ functions, loops, and ifs.
  2. Data flow dependency extraction for C++ variables and parameters.
  3. Structured dictionary output compatibility with vis.js frontend.
  4. Integration with graph_visualizer.generate_pdg_html.
"""

import unittest
from polyglot.cpp_pdg_extractor import extract_cpp_pdg_graph, extract_cpp_pdg_context
from graph_visualizer import generate_pdg_html


class TestPolyglotPhase2(unittest.TestCase):

    def setUp(self):
        self.sample_cpp = """
        #include <iostream>

        int calculate_total(int base, int multiplier) {
            int result = 0;
            if (multiplier > 1) {
                result = base * multiplier;
            }
            for (int i = 0; i < 3; i++) {
                result += i;
            }
            return result;
        }
        """

    def test_cpp_pdg_graph_structure(self):
        graph = extract_cpp_pdg_graph(self.sample_cpp)
        self.assertEqual(graph.get("status"), "ok")
        self.assertIn("nodes", graph)
        self.assertIn("edges", graph)

        nodes = graph["nodes"]
        self.assertIn("root", nodes)
        self.assertTrue(any("Function calculate_total" in label for label in nodes.values()))
        self.assertTrue(any("If" in label for label in nodes.values()))
        self.assertTrue(any("For" in label for label in nodes.values()))
        self.assertTrue(any("Return" in label for label in nodes.values()))

    def test_cpp_control_and_data_edges(self):
        graph = extract_cpp_pdg_graph(self.sample_cpp)
        edges = graph["edges"]
        self.assertGreater(len(edges), 0)

        control_edges = [e for e in edges if e.get("kind") == "Control"]
        data_edges = [e for e in edges if e.get("kind") == "Data"]

        self.assertGreater(len(control_edges), 0, "Expected control flow edges")
        self.assertGreater(len(data_edges), 0, "Expected data flow dependency edges")

        # Verify data flow edge for 'multiplier' or 'base'
        var_labels = [e.get("label") for e in data_edges]
        self.assertTrue(any(v in ("multiplier", "base", "result") for v in var_labels))

    def test_cpp_pdg_context_string(self):
        context = extract_cpp_pdg_context(self.sample_cpp)
        self.assertIn("Nodes:", context)
        self.assertIn("Edges:", context)
        self.assertIn("calculate_total", context)
        self.assertIn("(Control)", context)

    def test_cpp_pdg_visualizer_html_rendering(self):
        graph = extract_cpp_pdg_graph(self.sample_cpp)
        html = generate_pdg_html(graph)
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("vis.DataSet", html)
        self.assertIn("calculate_total", html)
        self.assertNotIn("SyntaxError", html)


if __name__ == "__main__":
    unittest.main()
