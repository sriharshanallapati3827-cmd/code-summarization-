"""
agent_security/regex_timeout.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Compatibility wrapper delegating to agent_security.safe_regex.
"""

from __future__ import annotations

import re
from typing import Optional

from agent_security.safe_regex import safe_search, timed_search as _safe_timed_search
from agent_security.config import REGEX_TIMEOUT_SECONDS


def timed_search(
    pattern: str | re.Pattern,
    string: str,
    flags: int = 0,
    timeout: float = REGEX_TIMEOUT_SECONDS,
) -> Optional[re.Match]:
    return _safe_timed_search(pattern, string, flags=flags, timeout=timeout)


def timed_match(
    pattern: str | re.Pattern,
    string: str,
    flags: int = 0,
    timeout: float = REGEX_TIMEOUT_SECONDS,
) -> Optional[re.Match]:
    match, _ = safe_search(pattern, string, timeout=timeout)
    if match and match.start() == 0:
        return match
    return None
