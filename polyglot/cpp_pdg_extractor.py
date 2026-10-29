"""
polyglot/cpp_pdg_extractor.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Constructs a Program Dependence Graph (PDG) from Tree-sitter C++ ASTs.
Generates:
  1. Control Flow Edges: Function definitions, If/Else, For/While loops, Switches.
  2. Data Flow Edges: Variable declarations, assignments, parameters, returns.
Outputs identical schema to pdg_extractor.py for seamless vis.js frontend rendering.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from polyglot.parser_factory import ParserFactory, SupportedLanguage


class CppPDGExtractor:
    """
    Extracts PDG nodes, control edges, and data dependency edges from C++ ASTs.
    """

    def __init__(self) -> None:
        self.nodes: List[str] = []
        self.control_edges: List[str] = []
        self.data_edges: List[str] = []

        self.current_control_node: str = "root"
        self.var_definitions: Dict[str, str] = {}  # var_name -> defining_node_id
        self.node_counter: int = 0

    def add_node(self, desc: str) -> str:
        clean_desc = desc.replace("\n", " ").strip()
        node_id = f"N{self.node_counter}"
        self.node_counter += 1
        self.nodes.append(f"{node_id}: {clean_desc}")
        return node_id

    def add_control_edge(self, target_id: str, source_id: str) -> None:
        self.control_edges.append(f"{target_id} depends on {source_id} (Control)")

    def add_data_edge(self, target_id: str, var_name: str, source_id: str) -> None:
        self.data_edges.append(f"{target_id} uses '{var_name}' from {source_id} (Data)")

    def extract(self, root_node: Any) -> None:
        if root_node is None:
            return
        self._traverse(root_node)

    def _traverse(self, node: Any) -> None:
        if not node:
            return

        ntype = node.type

        if ntype == "function_definition":
            self._visit_function(node)
        elif ntype == "declaration":
            self._visit_declaration(node)
        elif ntype == "expression_statement":
            self._visit_expression_statement(node)
        elif ntype == "if_statement":
            self._visit_if(node)
        elif ntype in ("for_statement", "for_range_loop"):
            self._visit_for(node)
        elif ntype == "while_statement":
            self._visit_while(node)
        elif ntype == "return_statement":
            self._visit_return(node)
        else:
            for child in node.children:
                self._traverse(child)

    def _get_text(self, node: Any) -> str:
        if not node:
            return ""
        return node.text.decode("utf-8", errors="replace").strip()

    def _find_identifiers(self, node: Any) -> Set[str]:
        """Collect all identifier names in a subtree."""
        res: Set[str] = set()
        stack = [node]
        while stack:
            curr = stack.pop()
            if curr.type == "identifier":
                name = self._get_text(curr)
                if name:
                    res.add(name)
            for child in curr.children:
                stack.append(child)
        return res

    def _visit_function(self, node: Any) -> None:
        func_name = "anonymous"
        params: List[str] = []

        # Find function declarator
        for child in node.children:
            if child.type == "function_declarator":
                for sub in child.children:
                    if sub.type == "identifier":
                        func_name = self._get_text(sub)
                    elif sub.type == "parameter_list":
                        for p in sub.children:
                            if p.type == "parameter_declaration":
                                p_id = [self._get_text(c) for c in p.children if c.type == "identifier"]
                                if p_id:
                                    params.append(p_id[-1])

        node_id = self.add_node(f"Function {func_name}")
        self.add_control_edge(node_id, "root")

        # Record parameter definitions
        for p in params:
            self.var_definitions[p] = node_id

        prev_ctrl = self.current_control_node
        self.current_control_node = node_id

        # Visit function body
        body = next((c for c in node.children if c.type == "compound_statement"), None)
        if body:
            for stmt in body.children:
                self._traverse(stmt)

        self.current_control_node = prev_ctrl

    def _visit_declaration(self, node: Any) -> None:
        decl_text = self._get_text(node).rstrip(";")
        node_id = self.add_node(f"Decl {decl_text}")
        self.add_control_edge(node_id, self.current_control_node)

        defined_vars: List[str] = []

        # Look for init_declarator or identifier
        for child in node.children:
            if child.type == "init_declarator":
                target_var = ""
                value_node = None
                for sub in child.children:
                    if sub.type == "identifier":
                        target_var = self._get_text(sub)
                    elif sub.type not in ("=", ","):
                        value_node = sub

                if target_var:
                    defined_vars.append(target_var)
                if value_node:
                    for used_id in self._find_identifiers(value_node):
                        if used_id in self.var_definitions and used_id != target_var:
                            self.add_data_edge(node_id, used_id, self.var_definitions[used_id])

            elif child.type == "identifier":
                defined_vars.append(self._get_text(child))

        for v in defined_vars:
            self.var_definitions[v] = node_id

    def _visit_expression_statement(self, node: Any) -> None:
        text = self._get_text(node).rstrip(";")

        # Check for assignment_expression
        assign_node = next((c for c in node.children if c.type == "assignment_expression"), None)
        if assign_node:
            node_id = self.add_node(f"Assign {text}")
            self.add_control_edge(node_id, self.current_control_node)

            lhs = assign_node.child_by_field_name("left") or (assign_node.children[0] if assign_node.children else None)
            rhs = assign_node.child_by_field_name("right") or (assign_node.children[-1] if assign_node.children else None)

            lhs_var = self._get_text(lhs) if lhs else ""

            if rhs:
                for used_id in self._find_identifiers(rhs):
                    if used_id in self.var_definitions:
                        self.add_data_edge(node_id, used_id, self.var_definitions[used_id])

            if lhs_var:
                self.var_definitions[lhs_var] = node_id
        else:
            node_id = self.add_node(f"Statement {text}")
            self.add_control_edge(node_id, self.current_control_node)
            for used_id in self._find_identifiers(node):
                if used_id in self.var_definitions:
                    self.add_data_edge(node_id, used_id, self.var_definitions[used_id])

    def _visit_if(self, node: Any) -> None:
        cond_node = next((c for c in node.children if c.type == "condition_clause"), None)
        cond_text = self._get_text(cond_node) if cond_node else "condition"
        node_id = self.add_node(f"If {cond_text}")
        self.add_control_edge(node_id, self.current_control_node)

        if cond_node:
            for used_id in self._find_identifiers(cond_node):
                if used_id in self.var_definitions:
                    self.add_data_edge(node_id, used_id, self.var_definitions[used_id])

        prev_ctrl = self.current_control_node
        self.current_control_node = node_id

        # Consequent branch
        consequent = next((c for c in node.children if c.type in ("compound_statement", "expression_statement")), None)
        if consequent:
            if consequent.type == "compound_statement":
                for stmt in consequent.children:
                    self._traverse(stmt)
            else:
                self._traverse(consequent)

        # Alternative branch (else)
        else_kw = next((c for c in node.children if c.type == "else"), None)
        if else_kw:
            self.current_control_node = f"{node_id}_Else"
            idx = node.children.index(else_kw)
            for after_else in node.children[idx + 1:]:
                self._traverse(after_else)

        self.current_control_node = prev_ctrl

    def _visit_for(self, node: Any) -> None:
        header_text = self._get_text(node).split("{")[0].strip()
        node_id = self.add_node(f"For {header_text}")
        self.add_control_edge(node_id, self.current_control_node)

        for used_id in self._find_identifiers(node):
            if used_id in self.var_definitions:
                self.add_data_edge(node_id, used_id, self.var_definitions[used_id])

        prev_ctrl = self.current_control_node
        self.current_control_node = node_id

        body = next((c for c in node.children if c.type == "compound_statement"), None)
        if body:
            for stmt in body.children:
                self._traverse(stmt)

        self.current_control_node = prev_ctrl

    def _visit_while(self, node: Any) -> None:
        cond_node = next((c for c in node.children if c.type == "condition_clause"), None)
        cond_text = self._get_text(cond_node) if cond_node else "condition"
        node_id = self.add_node(f"While {cond_text}")
        self.add_control_edge(node_id, self.current_control_node)

        if cond_node:
            for used_id in self._find_identifiers(cond_node):
                if used_id in self.var_definitions:
                    self.add_data_edge(node_id, used_id, self.var_definitions[used_id])

        prev_ctrl = self.current_control_node
        self.current_control_node = node_id

        body = next((c for c in node.children if c.type == "compound_statement"), None)
        if body:
            for stmt in body.children:
                self._traverse(stmt)

        self.current_control_node = prev_ctrl

    def _visit_return(self, node: Any) -> None:
        ret_text = self._get_text(node).rstrip(";")
        node_id = self.add_node(f"Return {ret_text}")
        self.add_control_edge(node_id, self.current_control_node)

        for used_id in self._find_identifiers(node):
            if used_id in self.var_definitions:
                self.add_data_edge(node_id, used_id, self.var_definitions[used_id])


def extract_cpp_pdg_graph(source_code: str) -> Dict[str, Any]:
    """
    Extracts structured PDG nodes and edges for C++ source code.
    Matches schema of pdg_extractor.extract_pdg_graph().
    """
    try:
        parsed = ParserFactory.parse(source_code, language=SupportedLanguage.CPP)
        extractor = CppPDGExtractor()
        extractor.extract(parsed.root_node)

        nodes: Dict[str, str] = {"root": "Program root"}
        for node_text in extractor.nodes:
            node_id, _, label = node_text.partition(": ")
            if node_id:
                nodes[node_id] = label or node_id

        edges: List[Dict[str, str]] = []
        for edge_text in extractor.control_edges:
            match = re.match(r"(?P<target>\S+) depends on (?P<source>\S+) \(Control\)", edge_text)
            if match:
                edges.append({
                    "source": match.group("source"),
                    "target": match.group("target"),
                    "kind": "Control",
                    "label": "control",
                })

        for edge_text in extractor.data_edges:
            match = re.match(r"(?P<target>\S+) uses '(?P<var>[^']+)' from (?P<source>\S+) \(Data\)", edge_text)
            if match:
                edges.append({
                    "source": match.group("source"),
                    "target": match.group("target"),
                    "kind": "Data",
                    "label": match.group("var"),
                })

        return {
            "status": "ok",
            "nodes": nodes,
            "edges": edges,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "nodes": {},
            "edges": [],
        }


def extract_cpp_pdg_context(source_code: str) -> str:
    """Extracts simplified text PDG representation for LLM prompts."""
    try:
        parsed = ParserFactory.parse(source_code, language=SupportedLanguage.CPP)
        extractor = CppPDGExtractor()
        extractor.extract(parsed.root_node)

        pdg_representation = "Nodes:\n" + "\n".join(extractor.nodes) + "\n"
        pdg_representation += "Edges:\n" + "\n".join(extractor.control_edges + extractor.data_edges)

        if len(pdg_representation) > 1000:
            pdg_representation = pdg_representation[:1000] + "\n...[Truncated]"

        return pdg_representation.strip()
    except Exception as e:
        return f"C++ PDG parsing failed: {str(e)}"
