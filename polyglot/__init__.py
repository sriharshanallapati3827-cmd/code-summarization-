"""
polyglot package - Multi-language analysis abstraction layer.
Supports Python and C++ with Tree-sitter AST parsing and PDG graph extraction.
"""

from polyglot.language_detector import detect_language, SupportedLanguage
from polyglot.parser_factory import ParserFactory, ParsedAST
from polyglot.cpp_pdg_extractor import extract_cpp_pdg_graph, extract_cpp_pdg_context, CppPDGExtractor

__all__ = [
    "detect_language",
    "SupportedLanguage",
    "ParserFactory",
    "ParsedAST",
    "extract_cpp_pdg_graph",
    "extract_cpp_pdg_context",
    "CppPDGExtractor",
]
