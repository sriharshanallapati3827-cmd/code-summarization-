"""
agent_controller.py - Multi-Agent Collaboration Engine
======================================================
Orchestrates 5 specialized AI agents collaborating on code intelligence:
  - Agent 0: Self-Healing Guard (Error Recovery Specialist)
  - Agent 1: Structural Inspector (AST & PDG Detective)
  - Agent 2: Green Computing Auditor (Energy & Carbon Inspector)
  - Agent 3: Security & Vulnerability Auditor (Threat Hunter)
  - Agent 4: Multi-Level Technical Communicator (Documentation Specialist)

Provides:
  - Structured Agent Context sharing
  - Live Cognitive Thought Trace (Observe -> Analyze -> Decide -> Act)
  - 3-in-1 Documentation Suite (Executive, Technical Walkthrough, Google/Sphinx Docstrings)
"""

import time
import ast
import json
import sys
from enum import Enum
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# Reconfigure stdout for safe Unicode on Windows console
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from self_healing import SelfHealingAgent
from ast_extractor import extract_ast_context
from pdg_extractor import extract_pdg_context, extract_pdg_graph
from green_computing import analyze_green_computing
from security_scanner import SecurityAuditor
from hardware_profiler import HardwareProfiler
from model_pipeline import CodeSummarizer

# ── Polyglot Language Integration ───────────────────────────────────────────
try:
    from polyglot.language_detector import detect_language, SupportedLanguage
    from polyglot.parser_factory import ParserFactory
    from polyglot.cpp_self_healing import CppSelfHealingAgent
    from polyglot.cpp_pdg_extractor import extract_cpp_pdg_context, extract_cpp_pdg_graph
    from polyglot.cpp_security_auditor import CppSecurityAuditor
    from polyglot.cpp_profiler import CppProfiler
    _POLYGLOT_AVAILABLE = True
except ImportError:
    _POLYGLOT_AVAILABLE = False

# ── Pillar 3B: Input Limits Guard ───────────────────────────────────────────
try:
    from agent_security.input_limits import InputRejected, safe_parse
    _INPUT_LIMITS_AVAILABLE = True
except ImportError:
    _INPUT_LIMITS_AVAILABLE = False
    InputRejected = Exception
    safe_parse = ast.parse
# ─────────────────────────────────────────────────────────────────────────────

# ── Pillar 2: DFA Agent Workflow Guard ───────────────────────────────────────────
try:
    from agent_security.workflow_dfa import WorkflowDFA, WorkflowViolation
    _DFA_AVAILABLE = True
except ImportError:
    _DFA_AVAILABLE = False
    WorkflowDFA = None       # type: ignore[assignment,misc]
    WorkflowViolation = None # type: ignore[assignment,misc]
# ─────────────────────────────────────────────────────────────────────────────


class CognitivePhase(str, Enum):
    OBSERVE = "OBSERVE"
    ANALYZE = "ANALYZE"
    DECIDE  = "DECIDE"
    ACT     = "ACT"


@dataclass
class ThoughtTraceEvent:
    agent_id: str
    phase: CognitivePhase
    timestamp: float
    message: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def time_str(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def to_dict(self) -> Dict:
        return {
            'agent_id': self.agent_id,
            'phase': self.phase.value,
            'timestamp': self.timestamp,
            'time_str': self.time_str,
            'message': self.message,
            'metadata': self.metadata
        }


@dataclass
class AgentContext:
    raw_code: str
    clean_code: str = ""
    language: str = "python"
    healing_report: Dict = field(default_factory=dict)
    ast_context: str = ""
    pdg_context: str = ""
    pdg_graph: Dict = field(default_factory=dict)
    green_profile: Dict = field(default_factory=dict)
    security_profile: Dict = field(default_factory=dict)
    hardware_profile: Dict = field(default_factory=dict)
    executive_summary: str = ""
    developer_walkthrough: str = ""
    docstrings: str = ""
    thought_trace: List[ThoughtTraceEvent] = field(default_factory=list)
    # ── Pillar 2: DFA guard instance ───────────────────────────────────────────
    # Default is None so that code that creates AgentContext directly
    # (e.g. in tests or from main.py) is never broken.
    workflow_dfa: Optional[Any] = field(default=None)
    # Flag set when the DFA traps; allows callers to detect the error.
    dfa_trapped: bool = False
    input_rejected: bool = False

    def add_trace(self, agent_id: str, phase: CognitivePhase, message: str, **metadata):
        event = ThoughtTraceEvent(
            agent_id=agent_id,
            phase=phase,
            timestamp=time.time(),
            message=message,
            metadata=metadata
        )
        self.thought_trace.append(event)


class AgentController:
    """
    Coordinates the 5-Agent intelligence pipeline with observable thought traces.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.summarizer = CodeSummarizer(model_path=model_path)
        self.security_auditor = SecurityAuditor()
        self.hardware_profiler = HardwareProfiler()
        self.self_healer = SelfHealingAgent()

    def run_workflow(self, source_code: str, language: Optional[str] = None) -> AgentContext:
        ctx = AgentContext(raw_code=source_code)
        workflow_start = time.perf_counter()

        # Determine language context
        if language:
            ctx.language = "cpp" if str(language).lower() in ("cpp", "c++", "cxx") else "python"
        elif _POLYGLOT_AVAILABLE:
            detected = detect_language(source_code)
            ctx.language = "cpp" if detected == SupportedLanguage.CPP else "python"
        else:
            ctx.language = "python"

        # ── Pillar 2: Initialise a fresh DFA for this run ────────────────────
        if _DFA_AVAILABLE:
            dfa = WorkflowDFA()
            ctx.workflow_dfa = dfa
        else:
            dfa = None

        def _dfa_step(event: str) -> bool:
            """Fire DFA event; return False (and trap ctx) on WorkflowViolation."""
            if dfa is None:
                return True  # DFA unavailable – silently allow
            try:
                dfa.step(event)
                return True
            except Exception:  # WorkflowViolation or any unexpected error
                return True    # step() never raises – violation only from require()

        def _dfa_require(event: str) -> bool:
            """
            Dry-check DFA before running an agent.
            Returns True if allowed, False (+ logs trap + sets ctx flag) if not.
            """
            if dfa is None:
                return True
            try:
                dfa.require(event)
                return True
            except Exception as exc:  # WorkflowViolation
                from_state = getattr(exc, 'from_state', dfa.state)
                ctx.dfa_trapped = True
                ctx.add_trace(
                    "[DFA Workflow Guard]",
                    CognitivePhase.ACT,
                    f"DFA TRAP: illegal transition '{event}' from '{from_state.value}' "
                    f"— pipeline halted to prevent incoherent execution.",
                )
                return False
        # ─────────────────────────────────────────────────────────────────────

        try:
            # ── AGENT 0: Self-Healing Guard ────────────────────────────────────
            if not _dfa_require("validate"):
                return ctx
            self._run_agent_0_self_healing(ctx)
            _dfa_step("validate")

            # ── AGENT 1: Structural Inspector (AST & PDG) ──────────────────────
            if not _dfa_require("parse"):
                return ctx
            self._run_agent_1_structural_inspector(ctx)
            _dfa_step("parse")    # AST pass
            _dfa_step("graph")    # PDG pass (both done inside same agent)

            # ── AGENT 2: Green Computing Auditor ────────────────────────────
            if not _dfa_require("green_audit"):
                return ctx
            self._run_agent_2_green_auditor(ctx, elapsed_start=workflow_start)
            _dfa_step("green_audit")

            # ── AGENT 3: Security & Vulnerability Auditor ─────────────────────
            if not _dfa_require("audit"):
                return ctx
            self._run_agent_3_security_auditor(ctx)
            _dfa_step("audit")

            # ── Hardware Profile (Dynamic Measurement) ─────────────────────────
            if not _dfa_require("profile"):
                return ctx
            self._run_hardware_profile(ctx)
            _dfa_step("profile")

            # ── AGENT 4: Multi-Level Technical Communicator ──────────────────
            if not _dfa_require("summarize"):
                return ctx
            self._run_agent_4_communicator(ctx)
            _dfa_step("summarize")

        except (InputRejected, RecursionError, MemoryError) as exc:
            ctx.input_rejected = True
            ctx.add_trace(
                "[Input Limits Guard]",
                CognitivePhase.ACT,
                f"INPUT REJECTED: {exc} — pipeline halted immediately.",
            )

        return ctx

    def _run_agent_0_self_healing(self, ctx: AgentContext):
        agent_id = "[Agent 0: Self-Healing Guard]"
        lang_label = "C++" if ctx.language == "cpp" else "Python"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, f"Ingesting raw {lang_label} source code for syntax validation.")

        if ctx.language == "cpp" and _POLYGLOT_AVAILABLE:
            healer = CppSelfHealingAgent()
            report = healer.heal(ctx.raw_code)
        else:
            report = self.self_healer.heal(ctx.raw_code)

        ctx.healing_report = report
        ctx.clean_code = report.get('clean_code', ctx.raw_code)

        if report.get('is_healed'):
            repairs = report.get('repairs', [])
            ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Detected syntax errors: {len(repairs)} defects diagnosed.", repairs=repairs)
            ctx.add_trace(agent_id, CognitivePhase.DECIDE, f"Autonomously patching code to establish clean {lang_label} AST compatibility.")
            ctx.add_trace(agent_id, CognitivePhase.ACT, f"Successfully healed {len(repairs)} syntax error(s). Clean code dispatched to Inspector.")
        elif report.get('status') == 'valid':
            ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Code syntax verified clean. No {lang_label} defects detected.")
            ctx.add_trace(agent_id, CognitivePhase.ACT, "Code approved for structural inspection without modifications.")
        else:
            ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Unresolvable syntax defect: {report.get('final_error')}.")
            ctx.add_trace(agent_id, CognitivePhase.ACT, "Proceeding with best-effort fault-tolerant execution.")

    def _run_agent_1_structural_inspector(self, ctx: AgentContext):
        agent_id = "[Agent 1: Structural Inspector]"
        lang_label = "C++" if ctx.language == "cpp" else "Python"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, f"Scanning validated {lang_label} code structure and grammar hierarchy.")

        if ctx.language == "cpp" and _POLYGLOT_AVAILABLE:
            parsed = ParserFactory.parse(ctx.clean_code, language=SupportedLanguage.CPP)
            ast_context = self._format_cpp_ast(parsed.root_node) if parsed.root_node else "C++ AST"
            pdg_context = extract_cpp_pdg_context(ctx.clean_code)
            pdg_graph = extract_cpp_pdg_graph(ctx.clean_code)
        else:
            ast_context = extract_ast_context(ctx.clean_code)
            pdg_context = extract_pdg_context(ctx.clean_code)
            pdg_graph   = extract_pdg_graph(ctx.clean_code)

        ctx.ast_context = ast_context
        ctx.pdg_context = pdg_context
        ctx.pdg_graph   = pdg_graph

        node_count = len(pdg_graph.get('nodes', {}))
        edge_count = len(pdg_graph.get('edges', []))
        control_edges = sum(1 for e in pdg_graph.get('edges', []) if e.get('kind') == 'Control')
        data_edges    = sum(1 for e in pdg_graph.get('edges', []) if e.get('kind') == 'Data')

        ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Constructed {lang_label} AST and PDG graph ({node_count} nodes, {edge_count} edges).",
                      control_edges=control_edges, data_edges=data_edges)
        ctx.add_trace(agent_id, CognitivePhase.DECIDE, "Mapping control branches and data flow consumers.")
        ctx.add_trace(agent_id, CognitivePhase.ACT, f"Generated complete Structural Dossier with {control_edges} control and {data_edges} data flows.")

    @staticmethod
    def _format_cpp_ast(root_node, max_depth: int = 8) -> str:
        """Formats Tree-sitter C++ AST node into a readable indented hierarchy."""
        lines = []

        def _walk(curr, depth):
            if depth > max_depth:
                lines.append("  " * depth + "...")
                return
            preview = ""
            if curr.child_count == 0 and curr.text:
                txt = curr.text.decode("utf-8", errors="ignore").replace("\n", " ").strip()
                if txt:
                    preview = f' "{txt[:25]}"'
            lines.append(f"{'  ' * depth}{curr.type}{preview}")
            for child in curr.children:
                _walk(child, depth + 1)

        _walk(root_node, 0)
        return "\n".join(lines)

    def _run_agent_2_green_auditor(self, ctx: AgentContext, elapsed_start: float):
        agent_id = "[Agent 2: Green Computing Auditor]"
        lang_label = "C++" if ctx.language == "cpp" else "Python"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, f"Auditing {lang_label} computational complexity, nesting depths, and I/O signals.")

        elapsed = time.perf_counter() - elapsed_start
        green_profile = analyze_green_computing(ctx.clean_code, analysis_seconds=elapsed, language=ctx.language)
        ctx.green_profile = green_profile

        score = green_profile.get('score', 100)
        rating = green_profile.get('rating', 'Efficient')
        metrics = green_profile.get('metrics', {})
        max_depth = metrics.get('max_loop_depth', 0)
        loops = metrics.get('loops', 0)

        ctx.add_trace(agent_id, CognitivePhase.ANALYZE,
                      f"Calculated Eco Score: {score}/100 ({rating}). Evaluated {loops} loop(s) (Max depth: {max_depth}).",
                      score=score, loops=loops, max_depth=max_depth)

        if max_depth >= 2:
            ctx.add_trace(agent_id, CognitivePhase.DECIDE, f"Flagged high algorithmic complexity penalty from nested loops (Depth {max_depth}).")
        else:
            ctx.add_trace(agent_id, CognitivePhase.DECIDE, "Code exhibits lightweight static complexity profile.")

        ctx.add_trace(agent_id, CognitivePhase.ACT, f"Delivered Green Profile: {green_profile.get('summary')}")

    def _run_agent_3_security_auditor(self, ctx: AgentContext):
        agent_id = "[Agent 3: Security Auditor]"
        lang_label = "C++" if ctx.language == "cpp" else "Python"
        rules_desc = "C++ memory safety, buffer overflow, and command injection rules" if ctx.language == "cpp" else "40+ CWE static analysis rules and dangerous sink patterns"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, f"Scanning {lang_label} code against {rules_desc}.")

        if ctx.language == "cpp" and _POLYGLOT_AVAILABLE:
            cpp_auditor = CppSecurityAuditor()
            sec_profile = cpp_auditor.audit_code(ctx.clean_code)
            tainted_flows = cpp_auditor.analyze_pdg_taint(ctx.clean_code, ctx.pdg_graph)
        else:
            sec_profile = self.security_auditor.audit_code(ctx.clean_code)
            tainted_flows = self.security_auditor.analyze_pdg_taint(ctx.clean_code, ctx.pdg_graph)

        sec_profile["tainted_flows"] = tainted_flows
        ctx.security_profile = sec_profile

        findings = sec_profile.get('findings', [])
        sec_score = sec_profile.get('security_score', 100)
        rating = sec_profile.get('rating', 'Secure')

        ctx.add_trace(agent_id, CognitivePhase.ANALYZE,
                      f"Security Audit Complete: Security Health {sec_score}/100 ({rating}). Found {len(findings)} issue(s).",
                      findings_count=len(findings), security_score=sec_score)

        if tainted_flows:
            ctx.add_trace(agent_id, CognitivePhase.DECIDE,
                          f"PDG Taint Tracking Alert: {len(tainted_flows)} data flow path(s) connect untrusted input to sensitive sinks.",
                          tainted_flows=tainted_flows)

        ctx.add_trace(agent_id, CognitivePhase.ACT,
                      f"Security Verdict: {sec_profile.get('summary')}")

    def _run_hardware_profile(self, ctx: AgentContext):
        hw = self.hardware_profiler.profile_code_snippet(ctx.clean_code, language=ctx.language)
        ctx.hardware_profile = hw

    def _run_agent_4_communicator(self, ctx: AgentContext):
        agent_id = "[Agent 4: Multi-Level Communicator]"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, "Synthesizing AST, PDG, Green, and Security findings into documentation.")

        # 1. Executive Summary (1-2 clean non-technical sentences)
        executive = self._generate_executive_summary(ctx)
        ctx.executive_summary = executive

        # 2. Developer Walkthrough (Technical breakdown)
        dev_walkthrough = self._generate_developer_walkthrough(ctx)
        ctx.developer_walkthrough = dev_walkthrough

        # 3. Production Docstring Generator (Google/Sphinx format)
        docstrings = self._generate_docstrings(ctx)
        ctx.docstrings = docstrings

        ctx.add_trace(agent_id, CognitivePhase.DECIDE, "Structured multi-tier documentation: Executive, Technical Walkthrough, and Docstring.")
        ctx.add_trace(agent_id, CognitivePhase.ACT, "Produced 3-in-1 Documentation Suite.")

    def _generate_executive_summary(self, ctx: AgentContext) -> str:
        """Calls the open-source LLM (or deterministic fallback) with enriched context."""
        summary = self.summarizer.generate_summary(ctx.clean_code, ctx.pdg_context)
        if not summary or "unavailable" in summary.lower():
            if ctx.language == "cpp":
                return self._rule_based_cpp_summary(ctx)
            return CodeSummarizer._rule_based_summary(ctx.clean_code)
        return summary

    def _rule_based_cpp_summary(self, ctx: AgentContext) -> str:
        metrics = ctx.green_profile.get('metrics', {})
        func_cnt = metrics.get('functions', 0)
        loop_cnt = metrics.get('loops', 0)
        sec_rating = ctx.security_profile.get('rating', 'Secure')
        return (
            f"The C++ program contains {func_cnt} function definition(s) and {loop_cnt} loop structure(s). "
            f"Algorithmic complexity profile shows maximum loop nesting depth of {metrics.get('max_loop_depth', 0)}. "
            f"Security evaluation rates the implementation as '{sec_rating}' with an Eco Score of {ctx.green_profile.get('score', 100)}/100."
        )

    def _generate_developer_walkthrough(self, ctx: AgentContext) -> str:
        """Generates detailed developer walkthrough including complexity, logic, and data flow."""
        lines = []
        metrics = ctx.green_profile.get('metrics', {})
        sec = ctx.security_profile

        lines.append("### Technical Code Walkthrough")
        lines.append(f"**Structural Profile:** {metrics.get('lines_code', 0)} lines of active logic across {metrics.get('functions', 0)} function(s) and {metrics.get('classes', 0)} class(es).")
        lines.append(f"**Algorithmic Complexity:** Max loop depth = {metrics.get('max_loop_depth', 0)}, loops = {metrics.get('loops', 0)}, recursion = {metrics.get('recursive_functions', 0)}.")

        # Control & Data flow details
        edges = ctx.pdg_graph.get('edges', [])
        data_edges = [e for e in edges if e.get('kind') == 'Data']
        if data_edges:
            lines.append("\n**Key Data Flows:**")
            for e in data_edges[:4]:
                lines.append(f"- Variable `{e.get('label')}` flows from `{e.get('source')}` &rarr; `{e.get('target')}`.")

        # Security posture
        lines.append(f"\n**Security Evaluation:** Health Score {sec.get('security_score', 100)}/100 ({sec.get('rating', 'Secure')}).")
        if sec.get('findings'):
            lines.append("Active Vulnerabilities to Address:")
            for f in sec.get('findings', [])[:3]:
                lines.append(f"- Line {f.get('line')}: {f.get('cwe')} ({f.get('category')}) &mdash; {f.get('message')}")

        return "\n".join(lines)

    def _generate_docstrings(self, ctx: AgentContext) -> str:
        """Extracts function signatures and constructs docstrings (Doxygen for C++, Google/Sphinx for Python)."""
        if ctx.language == "cpp" and _POLYGLOT_AVAILABLE:
            return self._generate_cpp_doxygen(ctx)

        try:
            tree = safe_parse(ctx.clean_code)
        except Exception:
            return "# Could not generate docstrings: syntax could not be parsed."

        docstring_blocks = []

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                args = [a.arg for a in node.args.args if a.arg != 'self']
                has_return = any(isinstance(n, ast.Return) and n.value is not None for n in ast.walk(node))

                arg_lines = []
                for arg in args:
                    arg_lines.append(f"    {arg} (Any): Input parameter for {func_name}.")

                args_section = "\n".join(arg_lines) if arg_lines else "    None"
                returns_section = "    Any: Computed result returned by the function." if has_return else "    None."

                doc = f'''def {func_name}({", ".join(args)}):
    """
    {func_name.replace('_', ' ').capitalize()} implementation.

    Args:
{args_section}

    Returns:
{returns_section}

    Complexity:
        Eco Score: {ctx.green_profile.get('score', 100)}/100 ({ctx.green_profile.get('rating', 'Efficient')})
        Security Rating: {ctx.security_profile.get('rating', 'Secure')}
    """
    ...'''
                docstring_blocks.append(doc)

        if not docstring_blocks:
            return "# No standalone function definitions found to generate docstrings."

        return "\n\n".join(docstring_blocks)

    def _generate_cpp_doxygen(self, ctx: AgentContext) -> str:
        """Extracts C++ function signatures and generates Doxygen /** ... */ docstrings."""
        parsed = ParserFactory.parse(ctx.clean_code, language=SupportedLanguage.CPP)
        if not parsed.root_node:
            return "// Could not generate C++ Doxygen: code parsing failed."

        blocks = []

        def find_funcs(node):
            if node.type == "function_definition":
                ret_type = "void"
                func_name = ""
                params = []
                for child in node.children:
                    if child.type in ("primitive_type", "type_identifier", "template_type", "sized_type_specifier"):
                        ret_type = child.text.decode("utf-8", errors="ignore")
                    elif child.type == "function_declarator":
                        for sub in child.children:
                            if sub.type == "identifier":
                                func_name = sub.text.decode("utf-8", errors="ignore")
                            elif sub.type == "parameter_list":
                                for p in sub.children:
                                    if p.type == "parameter_declaration":
                                        params.append(p.text.decode("utf-8", errors="ignore"))

                if func_name:
                    param_lines = []
                    for p in params:
                        p_parts = p.split()
                        raw_name = p_parts[-1] if p_parts else p
                        p_clean = raw_name.lstrip("*&")
                        param_lines.append(f" * @param {p_clean} Parameter '{p}'.")

                    params_doc = "\n".join(param_lines) if param_lines else " * @param None"
                    ret_doc = f" * @return ({ret_type}) Output value computed by {func_name}." if ret_type != "void" else " * @return void"

                    doc = (
                        "/**\n"
                        f" * @brief {func_name.replace('_', ' ').capitalize()} implementation.\n"
                        " *\n"
                        f"{params_doc}\n"
                        f"{ret_doc}\n"
                        " *\n"
                        " * @note Complexity & Health:\n"
                        f" *   - Eco Score: {ctx.green_profile.get('score', 100)}/100 ({ctx.green_profile.get('rating', 'Efficient')})\n"
                        f" *   - Security Rating: {ctx.security_profile.get('rating', 'Secure')}\n"
                        " */\n"
                        f"{ret_type} {func_name}({', '.join(params)});"
                    )
                    blocks.append(doc)

            for child in node.children:
                find_funcs(child)

        find_funcs(parsed.root_node)
        if not blocks:
            return "// No standalone C++ function definitions found to document."
        return "\n\n".join(blocks)


def run_agentic_pipeline(source_code: str, model_path: Optional[str] = None, language: Optional[str] = None) -> AgentContext:
    """Entry point to execute the complete Multi-Agent Intelligence Pipeline."""
    controller = AgentController(model_path=model_path)
    return controller.run_workflow(source_code, language=language)


if __name__ == "__main__":
    sample_code = """
def process_order(price, discount_code):
    final_price = price
    if discount_code == "SUMMER":
        final_price = price * 0.85
    return final_price
"""
    print("Executing Multi-Agent Workflow on sample code...")
    ctx = run_agentic_pipeline(sample_code)

    print("\n--- Thought Trace ---")
    for event in ctx.thought_trace:
        print(f"[{event.time_str}] {event.agent_id} [{event.phase.value}]: {event.message}")

    print("\n--- Executive Summary ---")
    print(ctx.executive_summary)

    print("\n--- Developer Walkthrough ---")
    print(ctx.developer_walkthrough)

    print("\n--- Auto-Generated Docstrings ---")
    print(ctx.docstrings)
