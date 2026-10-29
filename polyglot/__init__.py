"""
polyglot package - Multi-language analysis abstraction layer.
Supports Python and C++ with Tree-sitter AST parsing, PDG graph extraction, CWE security auditing, and self-healing.
"""

from polyglot.language_detector import detect_language, SupportedLanguage
from polyglot.parser_factory import ParserFactory, ParsedAST
from polyglot.cpp_pdg_extractor import extract_cpp_pdg_graph, extract_cpp_pdg_context, CppPDGExtractor
from polyglot.cpp_security_auditor import CppSecurityAuditor, DANGEROUS_CALLS_MAP
from polyglot.cpp_self_healing import CppSelfHealingAgent, heal_cpp_code
from polyglot.cpp_profiler import CppProfiler, profile_cpp_code

__all__ = [
    "detect_language",
    "SupportedLanguage",
    "ParserFactory",
    "ParsedAST",
    "extract_cpp_pdg_graph",
    "extract_cpp_pdg_context",
    "CppPDGExtractor",
    "CppSecurityAuditor",
    "DANGEROUS_CALLS_MAP",
    "CppSelfHealingAgent",
    "heal_cpp_code",
    "CppProfiler",
    "profile_cpp_code",
]
