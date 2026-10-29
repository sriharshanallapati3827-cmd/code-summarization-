# agent_security/config.py
# ──────────────────────────────────────────────────────────────────────────────
# Central constants for the agent_security package.
# These are the ONLY contents of this file; do not add logic here.
# ──────────────────────────────────────────────────────────────────────────────

MAX_SOURCE_BYTES: int = 200_000
MAX_LINE_LENGTH: int = 2_000
MAX_NESTING_DEPTH: int = 40
MAX_AST_DEPTH: int = 100
PROFILER_TIMEOUT_SECONDS: float = 2.0
PROFILER_MEMORY_LIMIT_MB: int = 50
REGEX_TIMEOUT_SECONDS: float = 0.5
