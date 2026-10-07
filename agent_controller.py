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

    def run_workflow(self, source_code: str) -> AgentContext:
        ctx = AgentContext(raw_code=source_code)
        workflow_start = time.perf_counter()

        # ── AGENT 0: Self-Healing Guard ──
        self._run_agent_0_self_healing(ctx)

        # ── AGENT 1: Structural Inspector (AST & PDG) ──
        self._run_agent_1_structural_inspector(ctx)

        # ── AGENT 2: Green Computing Auditor ──
        self._run_agent_2_green_auditor(ctx, elapsed_start=workflow_start)

        # ── AGENT 3: Security & Vulnerability Auditor ──
        self._run_agent_3_security_auditor(ctx)

        # ── Hardware Profile (Dynamic Measurement) ──
        self._run_hardware_profile(ctx)

        # ── AGENT 4: Multi-Level Technical Communicator ──
        self._run_agent_4_communicator(ctx)

        return ctx

    def _run_agent_0_self_healing(self, ctx: AgentContext):
        agent_id = "[Agent 0: Self-Healing Guard]"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, "Ingesting raw Python source code for syntax validation.")

        report = self.self_healer.heal(ctx.raw_code)
        ctx.healing_report = report
        ctx.clean_code = report.get('clean_code', ctx.raw_code)

        if report.get('is_healed'):
            repairs = report.get('repairs', [])
            ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Detected syntax errors: {len(repairs)} defects diagnosed.", repairs=repairs)
            ctx.add_trace(agent_id, CognitivePhase.DECIDE, "Autonomously patching code to establish clean AST compatibility.")
            ctx.add_trace(agent_id, CognitivePhase.ACT, f"Successfully healed {len(repairs)} syntax error(s). Clean code dispatched to Inspector.")
        elif report.get('status') == 'valid':
            ctx.add_trace(agent_id, CognitivePhase.ANALYZE, "Code syntax verified clean. No defects detected.")
            ctx.add_trace(agent_id, CognitivePhase.ACT, "Code approved for structural inspection without modifications.")
        else:
            ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Unresolvable syntax defect: {report.get('final_error')}.")
            ctx.add_trace(agent_id, CognitivePhase.ACT, "Proceeding with best-effort fault-tolerant execution.")

    def _run_agent_1_structural_inspector(self, ctx: AgentContext):
        agent_id = "[Agent 1: Structural Inspector]"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, "Scanning validated code structure and grammar hierarchy.")

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

        ctx.add_trace(agent_id, CognitivePhase.ANALYZE, f"Constructed AST and PDG graph ({node_count} nodes, {edge_count} edges).",
                      control_edges=control_edges, data_edges=data_edges)
        ctx.add_trace(agent_id, CognitivePhase.DECIDE, "Mapping control branches and data flow consumers.")
        ctx.add_trace(agent_id, CognitivePhase.ACT, f"Generated complete Structural Dossier with {control_edges} control and {data_edges} data flows.")

    def _run_agent_2_green_auditor(self, ctx: AgentContext, elapsed_start: float):
        agent_id = "[Agent 2: Green Computing Auditor]"
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, "Auditing computational complexity, nesting depths, and I/O signals.")

        elapsed = time.perf_counter() - elapsed_start
        green_profile = analyze_green_computing(ctx.clean_code, analysis_seconds=elapsed)
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
        ctx.add_trace(agent_id, CognitivePhase.OBSERVE, "Scanning code against 40+ CWE static analysis rules and dangerous sink patterns.")

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
        hw = self.hardware_profiler.profile_code_snippet(ctx.clean_code)
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
            # Robust fallback synthesis
            return CodeSummarizer._rule_based_summary(ctx.clean_code)
        return summary

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
        """Extracts function signatures from AST and constructs Google-style docstrings."""
        try:
            tree = ast.parse(ctx.clean_code)
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


def run_agentic_pipeline(source_code: str, model_path: Optional[str] = None) -> AgentContext:
    """Entry point to execute the complete Multi-Agent Intelligence Pipeline."""
    controller = AgentController(model_path=model_path)
    return controller.run_workflow(source_code)


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
