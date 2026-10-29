"""
agent_security/safe_regex.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 4A — ReDoS Prevention Engine with Safe Regex Matching.

Wraps regular expression searching to prevent catastrophic backtracking:
  1. Compiles and caches patterns in an LRU cache.
  2. Binds string length to MAX_LINE_LENGTH (2,000 chars) before search.
  3. Uses native `regex` library with timeout parameter if available.
  4. Falls back to thread-isolated execution with ReDoS pattern pre-screening.

Public API:
  safe_search(pattern, string, timeout=REGEX_TIMEOUT_SECONDS) -> tuple[Match | None, bool]
      Returns (match_object_or_none, did_timeout)
  timed_search(pattern, string, flags=0, timeout=REGEX_TIMEOUT_SECONDS) -> Match | None
      Convenience function returning Match | None
"""

from __future__ import annotations

import re
import threading
from functools import lru_cache
from typing import Any, Optional, Tuple, Union

from agent_security.config import REGEX_TIMEOUT_SECONDS, MAX_LINE_LENGTH

try:
    import regex as third_party_regex
    _REGEX_LIB_AVAILABLE = True
except ImportError:
    _REGEX_LIB_AVAILABLE = False
    third_party_regex = None  # type: ignore[assignment]

_NESTED_QUANTIFIERS_RE = re.compile(r"(\+|\*|\{\d*,?\d*\})\s*\)\s*(\+|\*|\{\d*,?\d*\})")


@lru_cache(maxsize=512)
def get_compiled_pattern(pattern_str: str, flags: int = 0) -> Any:
    """Compile and cache regex patterns to minimize recompilation overhead."""
    if _REGEX_LIB_AVAILABLE:
        try:
            return third_party_regex.compile(pattern_str, flags)
        except Exception:
            pass
    return re.compile(pattern_str, flags)


def safe_search(
    pattern: Union[str, Any],
    string: str,
    timeout: float = REGEX_TIMEOUT_SECONDS,
) -> Tuple[Optional[Any], bool]:
    """
    Search string for pattern with length limits and strict timeout.

    Parameters:
      pattern: String regex or compiled pattern.
      string: Untrusted string to search.
      timeout: Max seconds to wait before abandoning.

    Returns:
      (match_or_none, timed_out_boolean)
    """
    if not string:
        return None, False

    # 1. Truncate long lines to MAX_LINE_LENGTH
    effective_str = string[:MAX_LINE_LENGTH] if len(string) > MAX_LINE_LENGTH else string

    pat_str = pattern.pattern if hasattr(pattern, "pattern") else str(pattern)

    # 2. Check for catastrophic nested quantifiers (e.g. (a+)+)
    if len(effective_str) > 10 and _NESTED_QUANTIFIERS_RE.search(pat_str):
        # Abort immediately as ReDoS risk
        return None, True

    # 3. Try native regex timeout if third_party_regex is available
    if _REGEX_LIB_AVAILABLE:
        try:
            compiled = get_compiled_pattern(pat_str)
            match = compiled.search(effective_str, timeout=timeout)
            return match, False
        except TimeoutError:
            return None, True
        except Exception:
            pass

    # 4. Fallback: Thread-isolated execution with wall-clock timeout
    compiled = get_compiled_pattern(pat_str)
    result_box: list = [None]
    timed_out_box: list = [False]

    def _worker():
        try:
            result_box[0] = compiled.search(effective_str)
        except Exception:
            pass

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        return None, True

    return result_box[0], False


def timed_search(
    pattern: Union[str, Any],
    string: str,
    flags: int = 0,
    timeout: float = REGEX_TIMEOUT_SECONDS,
) -> Optional[Any]:
    """Backward-compatible helper returning only the match object or None."""
    match, _ = safe_search(pattern, string, timeout=timeout)
    return match
