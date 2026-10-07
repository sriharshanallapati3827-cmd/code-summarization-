import argparse
import time
from pdg_extractor import extract_pdg_context
from pdg_extractor import extract_pdg_graph
from ast_extractor import extract_ast_context
from green_computing import analyze_green_computing, write_green_report_svg
from model_pipeline import CodeSummarizer
from security_scanner import SecurityAuditor, audit_security
from self_healing import SelfHealingAgent, heal_code
from hardware_profiler import HardwareProfiler, profile_code
from agent_controller import AgentController
from optimizer_agent import optimize_code


def run_pipeline(source_code: str, model_path: str | None = None) -> dict:
    start_time = time.perf_counter()

    # Stage 1: Self-Healing Guard (Phase 2)
    healer = SelfHealingAgent()
    healing_report = healer.heal(source_code)
    clean_code = healing_report.get('clean_code', source_code)

    # Stage 2: Structural Analysis on clean code
    ast_context = extract_ast_context(clean_code)
    pdg_context = extract_pdg_context(clean_code)
    pdg_graph = extract_pdg_graph(clean_code)

    # Stage 3: Summarization
    summarizer = CodeSummarizer(model_path=model_path)
    summary = summarizer.generate_summary(clean_code, pdg_context)
    elapsed_seconds = time.perf_counter() - start_time

    # Stage 4: Static Green Computing
    green_profile = analyze_green_computing(clean_code, analysis_seconds=elapsed_seconds)

    # Stage 5: Security Audit & PDG Taint Tracking (Phase 1)
    auditor = SecurityAuditor()
    security_profile = auditor.audit_code(clean_code)
    tainted_flows = auditor.analyze_pdg_taint(clean_code, pdg_graph)
    security_profile["tainted_flows"] = tainted_flows

    # Stage 6: Real-Time Hardware Profiling (Phase 2)
    profiler = HardwareProfiler()
    hardware_profile = profiler.profile_code_snippet(clean_code)

    return {
        "raw_code": source_code,
        "clean_code": clean_code,
        "healing_report": healing_report,
        "ast_context": ast_context,
        "pdg_context": pdg_context,
        "pdg_graph": pdg_graph,
        "summary": summary,
        "model_path": summarizer.model_path,
        "green_profile": green_profile,
        "security_profile": security_profile,
        "hardware_profile": hardware_profile,
    }


def main():
    parser = argparse.ArgumentParser(description="PDG-Enhanced Code Summarization (Open-Source API)")
    parser.add_argument("--file", type=str, help="Path to Python file to summarize")
    parser.add_argument("--code", type=str, help="Python code string to summarize")
    parser.add_argument(
        "--model-path",
        type=str,
        default=None,
        help=(
            "Optional open-source model id. "
            "If omitted, uses OPEN_SOURCE_MODEL_ID or default model."
        ),
    )
    parser.add_argument(
        "--green-report",
        type=str,
        default=None,
        help="Optional path for a green-computing SVG report.",
    )
    parser.add_argument(
        "--agentic",
        action="store_true",
        help="Run the 5-Agent Collaborative AI Pipeline with Thought Trace.",
    )
    parser.add_argument(
        "--optimize",
        action="store_true",
        help="Run Autonomous Green & Secure Optimizer with closed-loop verification.",
    )
    
    args = parser.parse_args()
    
    source_code = ""
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            source_code = f.read()
    elif args.code:
        source_code = args.code
    else:
        # Default sample if nothing provided
        source_code = '''
def calculate_discount(price, is_member):
    """Calculates final price ."""
    discount = 0
    if is_member:
        discount = price * 0.1
    final_price = price - discount
    return final_price
'''
        print("No input provided. Using sample code:\n", source_code)

    if args.optimize:
        print("\n================ AUTONOMOUS GREEN & SECURE OPTIMIZER ================")
        opt_res = optimize_code(source_code, model_path=args.model_path)
        print(f"\nVerification Status: {'[PASSED]' if opt_res.verified else '[FAILED]'}")
        print(f"Eco Score:      {opt_res.original_eco_score}/100 -> {opt_res.optimized_eco_score}/100 (Delta: +{opt_res.eco_delta})")
        print(f"Security Score: {opt_res.original_sec_score}/100 -> {opt_res.optimized_sec_score}/100 (Delta: +{opt_res.sec_delta})")
        print(f"\nVerification Notes: {opt_res.verification_notes}")

        if opt_res.vulnerabilities_fixed:
            print("\nVulnerabilities Remediated:")
            for v in opt_res.vulnerabilities_fixed:
                print(f"  + [FIXED] {v}")

        if opt_res.algorithmic_improvements:
            print("\nAlgorithmic Improvements:")
            for a in opt_res.algorithmic_improvements:
                print(f"  + [OPTIMIZED] {a}")

        if opt_res.diff:
            print("\nUnified Diff:")
            print(opt_res.diff)

        print("\nRefactored & Verified Code:")
        print(opt_res.optimized_code)
        return

    if args.agentic:
        print("\n================ MULTI-AGENT COLLABORATION ENGINE ================")
        controller = AgentController(model_path=args.model_path)
        ctx = controller.run_workflow(source_code)

        print("\n--- Live Cognitive Thought Trace ---")
        for event in ctx.thought_trace:
            print(f"[{event.time_str}] {event.agent_id} [{event.phase.value}]: {event.message}")

        print("\n--- 1. Executive Summary ---")
        print(ctx.executive_summary)

        print("\n--- 2. Developer Walkthrough ---")
        print(ctx.developer_walkthrough)

        print("\n--- 3. Production Docstring Suite ---")
        print(ctx.docstrings)
        return

    result = run_pipeline(source_code, model_path=args.model_path)

    # Self-Healing Status
    healing = result.get("healing_report", {})
    if healing.get("is_healed"):
        print("\n--- Self-Healing Guard Alert ---")
        print(" [REPAIRED] Code had syntax errors that were autonomously healed:")
        for r in healing.get("repairs", []):
            print(f"  + {r}")
    elif healing.get("status") == "unresolved":
        print("\n--- Self-Healing Guard Warning ---")
        print(f" [WARNING] Code has unresolvable syntax error: {healing.get('final_error')}")

    print("\n--- AST (Abstract Syntax Tree) Extraction ---")
    print(result["ast_context"])
    print("\n--- PDG (Program Dependence Graph) Extraction ---")
    print(result["pdg_context"])
    print("\n--- Code Summarization ---")
    print(f"Model used: {result['model_path']}")
    print("\nGenerated Summary:")
    print(result["summary"])

    green_profile = result["green_profile"]
    print("\n--- Green Computing Profile (Static) ---")
    print(green_profile["summary"])
    print(
        "Estimated analysis footprint: "
        f"{green_profile['estimated_energy_kwh']} kWh, "
        f"{green_profile['estimated_co2_kg']} kg CO2e"
    )
    print("Recommendations:")
    for recommendation in green_profile["recommendations"]:
        print(f"- {recommendation}")

    # Real-Time Hardware Performance (Phase 2)
    hw = result.get("hardware_profile", {})
    if hw:
        print("\n--- Real-Time Hardware Profiler (Dynamic) ---")
        print(f"Latency: {hw['latency_ms']} ms | CPU Execution: {hw['cpu_time_ms']} ms ({hw['cpu_percent']}% CPU)")
        print(f"Peak RAM: {hw['peak_ram_mb']} MB | RSS Memory: {hw['rss_memory_mb']} MB")
        print(f"Dynamic Energy Impact: {hw['dynamic_energy_kwh']:.9f} kWh ({hw['dynamic_co2_kg']:.9f} kg CO2e)")
        print(f"Profiler Backend: {hw['profiler_backend']}")

    security_profile = result["security_profile"]
    print("\n--- Security & CWE Vulnerability Audit ---")
    print(security_profile["summary"])
    print(f"Security Health Score: {security_profile['security_score']}/100 | Risk Rating: {security_profile['rating']}")
    if security_profile["findings"]:
        print("Vulnerabilities Detected:")
        for f in security_profile["findings"]:
            print(f" - [{f['severity']}] Line {f['line']}: {f['cwe']} ({f['category']}) - {f['message']}")
    if security_profile.get("tainted_flows"):
        print("\nPDG Taint Tracking Alerts:")
        for flow in security_profile["tainted_flows"]:
            print(f" ! [TAINT] {flow['description']}")
    if security_profile.get("remediations"):
        print("\nSecurity Remediation Advice:")
        for rem in security_profile["remediations"]:
            print(f" * {rem}")

    if args.green_report:
        report_path = write_green_report_svg(green_profile, args.green_report)
        print(f"\nGreen report graph saved to: {report_path}")


if __name__ == "__main__":
    main()
