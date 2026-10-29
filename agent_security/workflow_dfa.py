"""
agent_security/workflow_dfa.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Pillar 2 – DFA Agent Workflow Guard.

Implements a Deterministic Finite Automaton (DFA) that models the legal
execution order of the 5-agent pipeline.  Any attempt to fire an event
out-of-order transitions the DFA into the absorbing TRAP state and raises
WorkflowViolation, stopping the pipeline before executing potentially
dangerous or incoherent work.

Public API
──────────
  WorkflowViolation     – Exception carrying from_state and event.
  WorkflowDFA           – The automaton itself.
  render_dot()          – Graphviz DOT representation of the automaton.
  render_table()        – Plain-text transition table (for reports).

DFA Specification
─────────────────
  States
  ──────
  START            – initial state, no agent has run yet
  HEALED           – Agent 0 (self-healing) completed
  AST_VERIFIED     – Agent 1 AST pass completed
  PDG_BUILT        – Agent 1 PDG pass completed
  SECURITY_AUDITED – Agent 3 security audit completed; also green+hw done
  OPTIMIZED        – optional optimizer pass completed
  TRAP (∅)         – absorbing error state; every event stays in TRAP

  Alphabet (event names)
  ──────────────────────
  validate    – Agent 0 validates / heals source code
  parse       – Agent 1 builds AST
  graph       – Agent 1 builds PDG graph
  green_audit – Agent 2 performs green-computing audit
  audit       – Agent 3 performs security audit
  summarize   – Agent 4 generates summaries / docstrings
  profile     – hardware profiler measures runtime metrics
  optimize    – optimizer agent rewrites code

  Transition table (legal edges only; all others → TRAP)
  ────────────────────────────────────────────────────────
  (START,            validate)   → HEALED
  (HEALED,           parse)      → AST_VERIFIED
  (AST_VERIFIED,     graph)      → PDG_BUILT
  (PDG_BUILT,        green_audit)→ PDG_BUILT          (self-loop)
  (PDG_BUILT,        audit)      → SECURITY_AUDITED
  (SECURITY_AUDITED, summarize)  → SECURITY_AUDITED   (self-loop)
  (SECURITY_AUDITED, profile)    → SECURITY_AUDITED   (self-loop)
  (SECURITY_AUDITED, optimize)   → OPTIMIZED

  Accepting states: SECURITY_AUDITED, OPTIMIZED
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Tuple


# ─────────────────────────────────────────────────────────────────────────────
# States
# ─────────────────────────────────────────────────────────────────────────────

class DFAState(str, Enum):
    START            = "START"
    HEALED           = "HEALED"
    AST_VERIFIED     = "AST_VERIFIED"
    PDG_BUILT        = "PDG_BUILT"
    SECURITY_AUDITED = "SECURITY_AUDITED"
    OPTIMIZED        = "OPTIMIZED"
    TRAP             = "TRAP"   # absorbing error state (∅)


# ─────────────────────────────────────────────────────────────────────────────
# Alphabet
# ─────────────────────────────────────────────────────────────────────────────

#: All legal event names.  Any string not in this set also causes TRAP.
ALPHABET = frozenset({
    "validate",
    "parse",
    "graph",
    "green_audit",
    "audit",
    "summarize",
    "profile",
    "optimize",
})


# ─────────────────────────────────────────────────────────────────────────────
# Transition table
# ─────────────────────────────────────────────────────────────────────────────

#: (from_state, event) → to_state.
#: Only *legal* transitions are listed.  Anything missing → TRAP.
_TRANSITIONS: Dict[Tuple[DFAState, str], DFAState] = {
    (DFAState.START,            "validate")   : DFAState.HEALED,
    (DFAState.HEALED,           "parse")      : DFAState.AST_VERIFIED,
    (DFAState.AST_VERIFIED,     "graph")      : DFAState.PDG_BUILT,
    (DFAState.PDG_BUILT,        "green_audit"): DFAState.PDG_BUILT,          # self-loop
    (DFAState.PDG_BUILT,        "audit")      : DFAState.SECURITY_AUDITED,
    (DFAState.SECURITY_AUDITED, "summarize")  : DFAState.SECURITY_AUDITED,   # self-loop
    (DFAState.SECURITY_AUDITED, "profile")    : DFAState.SECURITY_AUDITED,   # self-loop
    (DFAState.SECURITY_AUDITED, "optimize")   : DFAState.OPTIMIZED,
}

#: States that represent successful (accepting) pipeline completions.
ACCEPTING_STATES = frozenset({DFAState.SECURITY_AUDITED, DFAState.OPTIMIZED})


# ─────────────────────────────────────────────────────────────────────────────
# Exception
# ─────────────────────────────────────────────────────────────────────────────

class WorkflowViolation(Exception):
    """
    Raised when a DFA event would transition into the TRAP state.

    Attributes
    ----------
    from_state : DFAState
        The state the DFA was in when the illegal event was fired.
    event : str
        The event that triggered the violation.
    """

    def __init__(self, from_state: DFAState, event: str) -> None:
        self.from_state: DFAState = from_state
        self.event: str = event
        super().__init__(
            f"WorkflowViolation: illegal event '{event}' in state '{from_state.value}' "
            f"— transition goes to TRAP (∅)"
        )


# ─────────────────────────────────────────────────────────────────────────────
# WorkflowDFA
# ─────────────────────────────────────────────────────────────────────────────

class WorkflowDFA:
    """
    Deterministic Finite Automaton guarding the agent pipeline's execution
    order.

    Parameters
    ----------
    initial_state : DFAState, optional
        Starting state.  Defaults to ``DFAState.START``.

    Example
    -------
    ::

        dfa = WorkflowDFA()
        dfa.step("validate")   # → HEALED
        dfa.step("parse")      # → AST_VERIFIED
        dfa.step("graph")      # → PDG_BUILT
        dfa.step("green_audit")# → PDG_BUILT  (self-loop)
        dfa.step("audit")      # → SECURITY_AUDITED
        dfa.step("summarize")  # → SECURITY_AUDITED (self-loop)
        assert dfa.state in ACCEPTING_STATES
    """

    def __init__(self, initial_state: DFAState = DFAState.START) -> None:
        self._state: DFAState = initial_state
        # Each entry: (from_state, event, to_state)
        self._history: List[Tuple[DFAState, str, DFAState]] = []

    # ── public properties ─────────────────────────────────────────────────────

    @property
    def state(self) -> DFAState:
        """Current DFA state."""
        return self._state

    @property
    def is_trapped(self) -> bool:
        """True if the DFA is currently in the TRAP (absorbing error) state."""
        return self._state is DFAState.TRAP

    @property
    def is_accepted(self) -> bool:
        """True if the DFA is in an accepting state."""
        return self._state in ACCEPTING_STATES

    @property
    def history(self) -> List[Tuple[DFAState, str, DFAState]]:
        """Ordered list of (from_state, event, to_state) triples."""
        return list(self._history)

    # ── core methods ──────────────────────────────────────────────────────────

    def step(self, event: str) -> DFAState:
        """
        Fire *event* and advance to the next state.

        TRAP is absorbing: every event from TRAP stays in TRAP.

        Parameters
        ----------
        event : str
            One of the alphabet strings.

        Returns
        -------
        DFAState
            The new (current) state after the transition.
        """
        from_state = self._state

        if from_state is DFAState.TRAP:
            # Absorbing: stay in TRAP, record the attempt.
            self._history.append((from_state, event, DFAState.TRAP))
            return DFAState.TRAP

        to_state = _TRANSITIONS.get((from_state, event), DFAState.TRAP)
        self._state = to_state
        self._history.append((from_state, event, to_state))
        return to_state

    def require(self, event: str) -> None:
        """
        Dry-check that firing *event* from the current state would NOT lead
        to TRAP.  If it would, raise :class:`WorkflowViolation` WITHOUT
        performing the transition.

        This is a pure pre-condition guard; the DFA state is not changed.

        Parameters
        ----------
        event : str
            The event to check.

        Raises
        ------
        WorkflowViolation
            If the event would transition to TRAP from the current state.
        """
        from_state = self._state

        if from_state is DFAState.TRAP:
            raise WorkflowViolation(from_state, event)

        to_state = _TRANSITIONS.get((from_state, event), DFAState.TRAP)
        if to_state is DFAState.TRAP:
            raise WorkflowViolation(from_state, event)
        # No state change — this was a dry check only.

    def reset(self, initial_state: DFAState = DFAState.START) -> None:
        """
        Reset the DFA to *initial_state* (default: START) and clear history.
        """
        self._state = initial_state
        self._history.clear()


# ─────────────────────────────────────────────────────────────────────────────
# Visualisation helpers
# ─────────────────────────────────────────────────────────────────────────────

def render_dot() -> str:
    """
    Return a Graphviz DOT string representing the complete automaton.

    Accepting states are rendered with a double circle.
    TRAP is rendered in red.
    Self-loop transitions are labelled on the arc.

    The string can be written to a ``.dot`` file and compiled with::

        dot -Tpng workflow_dfa.dot -o workflow_dfa.png
    """
    lines = [
        "digraph WorkflowDFA {",
        '    rankdir=LR;',
        '    node [shape=circle fontname="Courier" fontsize=11];',
        "",
        "    // Accepting states — double circle",
    ]
    for s in ACCEPTING_STATES:
        lines.append(f'    {s.value} [shape=doublecircle];')

    lines.append("")
    lines.append("    // TRAP state — red")
    lines.append('    TRAP [label="∅ TRAP" style=filled fillcolor="#ffcccc" color="#cc0000" fontcolor="#cc0000"];')

    lines.append("")
    lines.append("    // Invisible start arrow")
    lines.append('    __start__ [shape=none label=""];')
    lines.append('    __start__ -> START;')

    lines.append("")
    lines.append("    // Legal transitions")
    for (from_s, event), to_s in sorted(_TRANSITIONS.items(), key=lambda kv: kv[0][0].value):
        label = event
        # Mark self-loops
        style = ' style=dashed' if from_s == to_s else ''
        lines.append(f'    {from_s.value} -> {to_s.value} [label="{label}"{style}];')

    lines.append("")
    lines.append("    // TRAP is absorbing — add a self-loop arc")
    lines.append('    TRAP -> TRAP [label="*" style=dashed];')

    lines.append("}")
    return "\n".join(lines)


def render_table() -> str:
    """
    Return a plain-text ASCII transition table suitable for a project report.

    Format::

        Current State    | Event       | Next State
        ─────────────────┼─────────────┼──────────────────
        START            | validate    | HEALED
        ...
    """
    header = f"{'Current State':<20}| {'Event':<15}| {'Next State'}"
    separator = "-" * 20 + "+-" + "-" * 15 + "+-" + "-" * 20
    rows = [header, separator]

    for (from_s, event), to_s in sorted(
        _TRANSITIONS.items(),
        key=lambda kv: (
            list(DFAState).index(kv[0][0]),  # ordering by state enum position
            kv[0][1],
        ),
    ):
        self_note = "  (self-loop)" if from_s == to_s else ""
        rows.append(f"{from_s.value:<20}| {event:<15}| {to_s.value}{self_note}")

    rows.append(separator)
    rows.append(f"{'ANY':<20}| {'(other)':<15}| TRAP (∅)  (absorbing)")
    rows.append(separator)
    rows.append(f"Accepting states: {', '.join(s.value for s in ACCEPTING_STATES)}")
    return "\n".join(rows)


# ─────────────────────────────────────────────────────────────────────────────
# Module self-test (python -m agent_security.workflow_dfa)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    print("=== Transition Table ===")
    print(render_table())

    print("\n=== Happy-path walk-through ===")
    dfa = WorkflowDFA()
    for ev in ["validate", "parse", "graph", "green_audit", "audit", "profile", "summarize"]:
        new = dfa.step(ev)
        print(f"  event={ev:<12} → {new.value}")
    print(f"  is_accepted={dfa.is_accepted}  is_trapped={dfa.is_trapped}")

    print("\n=== Out-of-order event → TRAP ===")
    dfa2 = WorkflowDFA()
    dfa2.step("validate")
    try:
        dfa2.require("audit")   # 'parse' was expected first
    except WorkflowViolation as exc:
        print(f"  WorkflowViolation caught: {exc}")
    print(f"  state after require (must be unchanged)={dfa2.state.value}")

    print("\n=== DOT snippet (first 5 lines) ===")
    dot = render_dot()
    for line in dot.splitlines()[:5]:
        print(" ", line)
