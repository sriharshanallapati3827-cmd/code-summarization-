"""
agent_security/regex_timeout.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 3 / Attack-5 defence — Thread-based regex timeout wrapper.

Python's built-in ``re`` module has no native timeout.  Crafted
ReDoS (Regular Expression Denial of Service) strings can make certain
patterns backtrack exponentially, freezing the scanner thread for minutes.

This module wraps ``re.search`` (and ``re.match``) so that if the match
operation does not complete within ``REGEX_TIMEOUT_SECONDS``, it is
abandoned and ``None`` is returned — as if the pattern did not match.

The design uses:
  • Catastrophic backtracking pattern screening (detects nested quantifiers
    like `(a+)+` before execution).
  • Input line length bounded by `MAX_LINE_LENGTH`.
  • A daemon ``threading.Thread`` with wall-clock timeout join.

Public API
──────────
  timed_search(pattern, string, flags=0, timeout=REGEX_TIMEOUT_SECONDS)
      -> re.Match | None
  timed_match(pattern, string, flags=0, timeout=REGEX_TIMEOUT_SECONDS)
      -> re.Match | None
"""

from __future__ import annotations

import re
import threading
from typing import Optional

from agent_security.config import REGEX_TIMEOUT_SECONDS, MAX_LINE_LENGTH

# Pattern detecting nested quantifiers capable of exponential backtracking
_REDOS_PATTERN_RE = re.compile(r'(\+|\*|\{\d*,?\d*\})\s*\)\s*(\+|\*|\{\d*,?\d*\})')


def timed_search(
    pattern: str | re.Pattern,
    string: str,
    flags: int = 0,
    timeout: float = REGEX_TIMEOUT_SECONDS,
) -> Optional[re.Match]:
    """
    Run ``re.search(pattern, string, flags)`` with a wall-clock timeout.

    Parameters
    ----------
    pattern : str | re.Pattern
        The regex pattern (compiled or raw string).
    string : str
        The string to search.
    flags : int
        Flags passed to ``re.search`` (ignored if *pattern* is pre-compiled).
    timeout : float
        Seconds to wait before abandoning the search. Defaults to
        ``REGEX_TIMEOUT_SECONDS`` from config (0.5 s).

    Returns
    -------
    re.Match or None
        None if no match, if a timeout occurs, or if any error is raised.
    """
    return _run_with_timeout(re.search, pattern, string, flags, timeout)


def timed_match(
    pattern: str | re.Pattern,
    string: str,
    flags: int = 0,
    timeout: float = REGEX_TIMEOUT_SECONDS,
) -> Optional[re.Match]:
    """
    Run ``re.match(pattern, string, flags)`` with a wall-clock timeout.

    Same semantics as :func:`timed_search`.
    """
    return _run_with_timeout(re.match, pattern, string, flags, timeout)


# ─────────────────────────────────────────────────────────────────────────────
# Internal
# ─────────────────────────────────────────────────────────────────────────────

def _run_with_timeout(func, pattern, string: str, flags: int, timeout: float):
    """Execute ``func(pattern, string, flags)`` with safety bounds and timeout."""
    if not string:
        return None

    pat_str = pattern.pattern if isinstance(pattern, re.Pattern) else str(pattern)

    # Fast-reject known catastrophic ReDoS patterns on non-trivial strings
    if len(string) > 10 and _REDOS_PATTERN_RE.search(pat_str):
        return None

    # Cap search string length to MAX_LINE_LENGTH to prevent backtracking blowout
    effective_string = string[:MAX_LINE_LENGTH] if len(string) > MAX_LINE_LENGTH else string

    result_box: list = [None]
    error_box: list = [None]

    def _worker():
        try:
            if isinstance(pattern, re.Pattern):
                result_box[0] = func(pattern, effective_string)
            else:
                result_box[0] = func(pattern, effective_string, flags)
        except Exception as exc:
            error_box[0] = exc

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout=timeout)

    if t.is_alive():
        # Timeout: abandon and return None
        return None

    if error_box[0] is not None:
        return None

    return result_box[0]
