"""
polyglot package - Multi-language analysis abstraction layer.
Supports Python and C++ with Tree-sitter AST parsing.
"""

from polyglot.language_detector import detect_language, SupportedLanguage
from polyglot.parser_factory import ParserFactory, ParsedAST

__all__ = [
    "detect_language",
    "SupportedLanguage",
    "ParserFactory",
    "ParsedAST",
]
