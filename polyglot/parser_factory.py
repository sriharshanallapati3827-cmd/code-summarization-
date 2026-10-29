"""
polyglot/parser_factory.py
━━━━━━━━━━━━━━━━━━━━━━━━━━
Unified Tree-sitter Parser Factory supporting Python and C++.
Provides standardized AST parsing, error detection, and node exploration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List, Optional, Union

try:
    import tree_sitter
    from tree_sitter import Language, Parser, Tree, Node
    import tree_sitter_cpp
    import tree_sitter_python
    _TREE_SITTER_AVAILABLE = True
except ImportError:
    _TREE_SITTER_AVAILABLE = False
    tree_sitter = None
    Language = None
    Parser = None
    Tree = None
    Node = None

from polyglot.language_detector import SupportedLanguage, detect_language


@dataclass
class SyntaxDiagnostic:
    line: int
    column: int
    message: str
    node_type: str


@dataclass
class ParsedAST:
    """Standardized result of a polyglot parse operation."""
    language: SupportedLanguage
    source_bytes: bytes
    tree: Optional[Any]  # Tree-sitter Tree
    root_node: Optional[Any]  # Tree-sitter root Node
    is_valid: bool
    diagnostics: List[SyntaxDiagnostic]

    @property
    def has_errors(self) -> bool:
        return not self.is_valid or len(self.diagnostics) > 0


class ParserFactory:
    """
    Thread-safe factory managing Tree-sitter parsers for Python and C++.
    """

    _cpp_language: Optional[Any] = None
    _python_language: Optional[Any] = None

    @classmethod
    def is_available(cls) -> bool:
        return _TREE_SITTER_AVAILABLE

    @classmethod
    def get_language(cls, lang: Union[SupportedLanguage, str]) -> Any:
        if not _TREE_SITTER_AVAILABLE:
            raise RuntimeError("tree-sitter libraries are not installed.")

        norm = lang.value if isinstance(lang, SupportedLanguage) else str(lang).lower()

        if norm in ("cpp", "c++", "c"):
            if cls._cpp_language is None:
                cls._cpp_language = Language(tree_sitter_cpp.language())
            return cls._cpp_language

        if norm in ("python", "py"):
            if cls._python_language is None:
                cls._python_language = Language(tree_sitter_python.language())
            return cls._python_language

        raise ValueError(f"Unsupported language: {lang}")

    @classmethod
    def create_parser(cls, lang: Union[SupportedLanguage, str]) -> Any:
        ts_lang = cls.get_language(lang)
        return Parser(ts_lang)

    @classmethod
    def parse(
        cls, 
        code: Union[str, bytes], 
        language: Optional[Union[SupportedLanguage, str]] = None,
        filename: Optional[str] = None
    ) -> ParsedAST:
        """
        Parse source code into a normalized ParsedAST instance.

        If language is not provided, it is auto-detected via language_detector.
        """
        source_str = code if isinstance(code, str) else code.decode("utf-8", errors="replace")
        source_bytes = code.encode("utf-8") if isinstance(code, str) else code

        if language is None:
            detected = detect_language(source_str, filename=filename)
            lang_enum = detected if detected != SupportedLanguage.UNKNOWN else SupportedLanguage.PYTHON
        elif isinstance(language, str):
            lang_enum = SupportedLanguage(language.lower())
        else:
            lang_enum = language

        if not _TREE_SITTER_AVAILABLE:
            return ParsedAST(
                language=lang_enum,
                source_bytes=source_bytes,
                tree=None,
                root_node=None,
                is_valid=False,
                diagnostics=[SyntaxDiagnostic(line=1, column=0, message="tree-sitter not installed", node_type="error")]
            )

        parser = cls.create_parser(lang_enum)
        tree = parser.parse(source_bytes)
        root = tree.root_node

        # Scan for ERROR nodes in tree
        diagnostics: List[SyntaxDiagnostic] = []
        cls._collect_syntax_errors(root, diagnostics)

        is_valid = not root.has_error and len(diagnostics) == 0

        return ParsedAST(
            language=lang_enum,
            source_bytes=source_bytes,
            tree=tree,
            root_node=root,
            is_valid=is_valid,
            diagnostics=diagnostics
        )

    @classmethod
    def _collect_syntax_errors(cls, node: Any, diagnostics: List[SyntaxDiagnostic]) -> None:
        """Iterative traversal collecting syntax ERROR and MISSING nodes."""
        if not node:
            return

        stack = [node]
        while stack:
            curr = stack.pop()
            if curr.is_error or curr.is_missing:
                diagnostics.append(
                    SyntaxDiagnostic(
                        line=curr.start_point.row + 1,
                        column=curr.start_point.column,
                        message=f"Syntax defect '{curr.type}' detected at line {curr.start_point.row + 1}",
                        node_type=curr.type
                    )
                )
            # Add children to stack
            for child in curr.children:
                if child.has_error or child.is_error or child.is_missing:
                    stack.append(child)
