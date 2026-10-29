"""
polyglot/language_detector.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Deterministic language detector distinguishing Python and C++ source code.
Uses file extensions, shebangs, and distinctive lexical keywords/fingerprints.
"""

from __future__ import annotations

import re
from enum import Enum
from typing import Optional


class SupportedLanguage(str, Enum):
    PYTHON = "python"
    CPP = "cpp"
    UNKNOWN = "unknown"


# C++ distinctive patterns
_CPP_KEYWORDS = [
    r"#include\s*<[^>]+>",
    r"#include\s*\"[^\"]+\"",
    r"\busing\s+namespace\s+std\s*;",
    r"\bstd::[a-zA-Z0-9_]+",
    r"\bint\s+main\s*\([^)]*\)",
    r"\bcout\s*<<",
    r"\bcin\s*>>",
    r"\bprintf\s*\(",
    r"\bvector<",
    r"\bnullptr\b",
    r"\bpublic:\b|\bprivate:\b|\bprotected:\b",
    r"\btemplate\s*<",
]

# Python distinctive patterns
_PYTHON_KEYWORDS = [
    r"^\s*def\s+[a-zA-Z0-9_]+\s*\(",
    r"^\s*import\s+[a-zA-Z0-9_]+",
    r"^\s*from\s+[a-zA-Z0-9_]+\s+import",
    r"\bprint\s*\(",
    r"\belif\b",
    r"if\s+__name__\s*==\s*['\"]__main__['\"]:",
    r"^\s*class\s+[a-zA-Z0-9_]+\s*(\([^)]*\))?:",
]


def detect_language(code: str, filename: Optional[str] = None) -> SupportedLanguage:
    """
    Detect whether the source code is Python or C++.

    Parameters:
      code: The raw source code string.
      filename: Optional filename or path with an extension.

    Returns:
      SupportedLanguage.PYTHON, SupportedLanguage.CPP, or SupportedLanguage.UNKNOWN.
    """
    if filename:
        ext = filename.lower().split(".")[-1] if "." in filename else ""
        if ext in ("py", "pyw", "python"):
            return SupportedLanguage.PYTHON
        if ext in ("cpp", "cc", "cxx", "c++", "h", "hpp", "hxx"):
            return SupportedLanguage.CPP

    if not code or not code.strip():
        return SupportedLanguage.UNKNOWN

    lines = code.splitlines()

    # Check for shebang
    if lines and lines[0].startswith("#!"):
        first_line = lines[0].lower()
        if "python" in first_line:
            return SupportedLanguage.PYTHON

    # Score based on syntax fingerprints
    cpp_score = 0
    py_score = 0

    for pattern in _CPP_KEYWORDS:
        if re.search(pattern, code, re.MULTILINE):
            cpp_score += 2

    for pattern in _PYTHON_KEYWORDS:
        if re.search(pattern, code, re.MULTILINE):
            py_score += 2

    # Semicolons and curly braces at line ends are heavy indicators of C++
    semicolon_count = sum(1 for line in lines if line.strip().endswith(";"))
    brace_count = sum(1 for line in lines if line.strip().endswith("{") or line.strip().endswith("}"))

    if semicolon_count >= 2 or brace_count >= 2:
        cpp_score += 3

    # Colons at line ends for block headers are heavy indicators of Python
    colon_count = sum(
        1 for line in lines 
        if line.strip().endswith(":") and any(line.strip().startswith(kw) for kw in ("def", "class", "if", "for", "while", "else", "elif", "try", "except", "with"))
    )
    if colon_count >= 1:
        py_score += 3

    if cpp_score > py_score:
        return SupportedLanguage.CPP
    elif py_score > cpp_score:
        return SupportedLanguage.PYTHON

    return SupportedLanguage.PYTHON  # Default to Python if ambiguous
