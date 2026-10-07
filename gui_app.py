"""
gui_app.py - Agentic AI Code Intelligence & Security Lab (Streamlit UI)
======================================================================
Modern, interactive dashboard providing:
  1. Multi-Agent Intelligence (Executive, Developer Walkthrough, Auto Docstrings, Thought Trace)
  2. Security & CWE Audit (40+ rules, PDG Taint Tracking, Remediations)
  3. Autonomous Green & Secure Optimizer (Closed-loop refactoring, Before vs. After diff)
  4. Interactive Physics PDG Graph (vis.js physics network)
  5. Green Computing & Real-Time Hardware Profiler (psutil CPU/RAM/latency/energy)
  6. AST Structural Explorer

Authors: M. SATHWIK & N. HARSHA
"""

import sys
import streamlit as st
import streamlit.components.v1 as components

# Ensure safe UTF-8 encoding
if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from main import run_pipeline
from agent_controller import AgentController
from optimizer_agent import optimize_code
from graph_visualizer import generate_pdg_html


st.set_page_config(
    page_title="Agentic AI Code Intelligence & Security Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom Styling (Dark/Modern Glassmorphism)
st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top right, #0f172a, #0b1120 40%, #030712 100%);
        color: #f8fafc;
    }
    .hero-banner {
        padding: 1.4rem 1.8rem;
        border-radius: 16px;
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 50%, #1e1b4b 100%);
        border: 1px solid #334155;
        color: #f8fafc;
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
    }
    .hero-banner h1 {
        margin: 0;
        font-size: 1.85rem;
        font-weight: 800;
        letter-spacing: -0.5px;
        background: linear-gradient(90deg, #38bdf8, #818cf8, #c084fc);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .hero-banner p {
        margin: 0.4rem 0 0 0;
        font-size: 0.95rem;
        color: #94a3b8;
    }
    .author-badge {
        display: inline-block;
        margin-top: 0.5rem;
        padding: 0.2rem 0.75rem;
        border-radius: 9999px;
        background: rgba(56, 189, 248, 0.12);
        border: 1px solid rgba(56, 189, 248, 0.3);
        color: #38bdf8;
        font-size: 0.8rem;
        font-weight: 600;
    }
    .metric-card {
        background: #1e293b;
        border: 1px solid #334155;
        padding: 1rem;
        border-radius: 12px;
        text-align: center;
    }
    .metric-card h3 {
        margin: 0;
        font-size: 1.8rem;
        color: #38bdf8;
    }
    .metric-card span {
        font-size: 0.82rem;
        color: #94a3b8;
        text-transform: uppercase;
    }
    .agent-trace-box {
        background: #111827;
        border-left: 4px solid #3b82f6;
        padding: 0.6rem 0.9rem;
        border-radius: 0 8px 8px 0;
        margin-bottom: 0.5rem;
        font-size: 0.88rem;
    }
    .stTextArea textarea {
        font-family: Consolas, monospace !important;
        font-size: 0.88rem !important;
        background: #0f172a !important;
        color: #e2e8f0 !important;
        border: 1px solid #334155 !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# Hero Header
st.markdown(
    """
    <div class="hero-banner">
        <h1>Agentic AI Code Intelligence & Security Lab</h1>
        <p>AST &bull; PDG &bull; Qwen LLM &bull; 40+ CWE Security Audits &bull; Self-Healing &bull; Hardware Profiler &bull; Autonomous Green Optimizer</p>
        <div class="author-badge">Project by M. SATHWIK & N. HARSHA</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# Preset Samples
SAMPLE_CODES = {
    "Vulnerable & Inefficient (Full Demo)": '''import os

def process_transaction(user_id, token, records):
    # Hardcoded sensitive credential (CWE-321)
    api_key = "sk_live_992384729384729384"
    
    # O(N^2) inefficient nested search
    matches = []
    for r in records:
        for u in user_id:
            if r == u:
                matches.append(r)
                
    # Arbitrary code execution vulnerability (CWE-94)
    payload = eval(token)
    
    # Insecure shell command execution (CWE-78)
    os.system("echo Audit completed for transaction")
    
    return matches, payload
''',
    "Broken Syntax (Self-Healing Demo)": '''def calculate_metrics(values, factor)
    total = 0
    for v in values
        if v > 0
            total += v * factor
    return total
''',
    "Algorithmic Complexity (O(N^2) Loops)": '''def check_duplicates(list_a, list_b):
    duplicates = []
    for item_a in list_a:
        for item_b in list_b:
            if item_a == item_b:
                duplicates.append(item_a)
    return duplicates
''',
    "Clean Business Logic": '''def compute_interest(principal, rate, years):
    """Calculates simple annual interest."""
    interest = (principal * rate * years) / 100.0
    total = principal + interest
    return total
'''
}

# Sidebar Controls
with st.sidebar:
    st.subheader("⚙️ Control Panel")
    selected_sample = st.selectbox("Choose a Benchmark Sample:", list(SAMPLE_CODES.keys()))

    st.markdown("---")
    st.markdown("### 🤖 Multi-Agent Engine")
    st.markdown(
        """
        - **Agent 0:** Self-Healing Guard
        - **Agent 1:** Structural AST/PDG Inspector
        - **Agent 2:** Green Computing Auditor
        - **Agent 3:** Security Threat Hunter (40+ CWEs)
        - **Agent 4:** Multi-Level Communicator
        """
    )
    st.markdown("---")
    st.caption("Active LLM Backend: Groq / `qwen/qwen3.8-27b`")


# Main Input Columns
col_code, col_act = st.columns([2.5, 1])

with col_code:
    code_input = st.text_area(
        "Python Source Code to Analyze:",
        value=SAMPLE_CODES[selected_sample],
        height=280,
    )

with col_act:
    st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
    run_agentic = st.button("🚀 Run 5-Agent Intelligence Pipeline", use_container_width=True, type="primary")
    run_optimizer = st.button("⚡ Run Green & Secure Optimizer", use_container_width=True)
    uploaded_file = st.file_uploader("Or Upload .py Script", type=["py", "txt"])

# Handle file upload override
if uploaded_file is not None:
    try:
        code_input = uploaded_file.getvalue().decode("utf-8")
    except Exception:
        code_input = uploaded_file.getvalue().decode("latin-1")


# Session state persistence
if "agent_context" not in st.session_state:
    st.session_state.agent_context = None

if "opt_result" not in st.session_state:
    st.session_state.opt_result = None


# Trigger Pipeline Execution
if run_agentic:
    if not code_input.strip():
        st.warning("Please provide Python code to analyze.")
    else:
        with st.spinner("🤖 5 Specialized Agents Collaborating on Code Intelligence..."):
            try:
                controller = AgentController()
                ctx = controller.run_workflow(code_input)
                st.session_state.agent_context = ctx
                st.success("Multi-Agent Intelligence Synthesis Complete!")
            except Exception as e:
                st.error(f"Error during agentic execution: {e}")

# Trigger Optimizer Execution
if run_optimizer:
    if not code_input.strip():
        st.warning("Please provide Python code to optimize.")
    else:
        with st.spinner("⚡ Autonomous Optimizer Refactoring & Verifying Code..."):
            try:
                res = optimize_code(code_input)
                st.session_state.opt_result = res
                st.success("Autonomous Optimization & Closed-Loop Verification Finished!")
            except Exception as e:
                st.error(f"Error during optimization: {e}")


# Render Results Tabs
ctx = st.session_state.agent_context
opt = st.session_state.opt_result

if ctx is not None or opt is not None:
    tabs = st.tabs([
        "🧠 Multi-Agent Intelligence",
        "🛡️ Security & CWE Audit",
        "⚡ Green & Secure Optimizer",
        "🌐 Interactive PDG (Physics)",
        "🌿 Green & Hardware Profiler",
        "🌳 AST Structure"
    ])

    # ─────────────────────────────────────────────────────────────
    # TAB 1: Multi-Agent Intelligence & Summaries
    # ─────────────────────────────────────────────────────────────
    with tabs[0]:
        if ctx is None:
            st.info("Run the 5-Agent Pipeline to view multi-level summaries and live thought trace.")
        else:
            # Self-healing banner if repaired
            healing = ctx.healing_report
            if healing.get('is_healed'):
                st.warning(f"🩹 **Self-Healing Guard Triggered:** Repaired {len(healing.get('repairs', []))} syntax error(s) autonomously.")
                with st.expander("View Self-Healing Patch Details"):
                    for r in healing.get('repairs', []):
                        st.write(f"- {r}")

            st.markdown("### 📋 3-in-1 Documentation Suite")
            doc_col1, doc_col2 = st.columns([1.2, 1])

            with doc_col1:
                st.markdown("#### 1. Executive Summary")
                st.info(ctx.executive_summary)

                st.markdown("#### 2. Technical Developer Walkthrough")
                st.markdown(ctx.developer_walkthrough)

            with doc_col2:
                st.markdown("#### 3. Production Docstrings (Google/Sphinx)")
                st.code(ctx.docstrings, language="python")

            st.markdown("---")
            st.markdown("### 🔬 Live Cognitive Thought Trace")
            st.caption("Inspect how Agent 0 through Agent 4 observe, analyze, decide, and act in real time.")
            
            for event in ctx.thought_trace:
                phase_color = {
                    "OBSERVE": "#38bdf8",
                    "ANALYZE": "#818cf8",
                    "DECIDE": "#fbbf24",
                    "ACT": "#34d399"
                }.get(event.phase.value, "#94a3b8")

                st.markdown(
                    f"""
                    <div class="agent-trace-box" style="border-left-color: {phase_color};">
                        <strong style="color: {phase_color};">[{event.phase.value}]</strong>
                        <span style="color: #94a3b8; font-size: 0.8rem; margin-left: 6px;">{event.time_str}</span> &bull;
                        <span style="font-weight: 600; color: #f1f5f9;">{event.agent_id}</span><br/>
                        <span style="color: #cbd5e1;">{event.message}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

    # ─────────────────────────────────────────────────────────────
    # TAB 2: Security & CWE Audit
    # ─────────────────────────────────────────────────────────────
    with tabs[1]:
        if ctx is None:
            st.info("Run the 5-Agent Pipeline to view full security audit results.")
        else:
            sec = ctx.security_profile
            findings = sec.get("findings", [])
            tainted = sec.get("tainted_flows", [])

            # Metrics Row
            m1, m2, m3, m4 = st.columns(4)
            with m1:
                score = sec.get("security_score", 100)
                score_color = "#34d399" if score >= 80 else ("#fbbf24" if score >= 50 else "#f87171")
                st.markdown(f"<div class='metric-card'><h3 style='color: {score_color}'>{score}/100</h3><span>Security Health Score</span></div>", unsafe_allow_html=True)
            with m2:
                rating = sec.get("rating", "Secure")
                st.markdown(f"<div class='metric-card'><h3>{rating}</h3><span>Risk Rating</span></div>", unsafe_allow_html=True)
            with m3:
                st.markdown(f"<div class='metric-card'><h3>{len(findings)}</h3><span>Vulnerabilities</span></div>", unsafe_allow_html=True)
            with m4:
                st.markdown(f"<div class='metric-card'><h3>{len(tainted)}</h3><span>Tainted Data Flows</span></div>", unsafe_allow_html=True)

            st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)
            st.info(sec.get("summary", ""))

            # Taint Tracking Alerts
            if tainted:
                st.markdown("#### 🚨 PDG Taint Tracking Alerts (Untrusted Flow to Sinks)")
                for t in tainted:
                    st.error(f"**Tainted Flow:** {t.get('description')} (Variable: `{t.get('variable')}` from `{t.get('source_node')}` &rarr; `{t.get('sink_node')}`)")

            # Vulnerabilities List
            st.markdown("#### 🔍 Detected CWE Vulnerabilities")
            if not findings:
                st.success("✅ Clean bill of health! No known CWE vulnerabilities found in code.")
            else:
                for f in findings:
                    sev = f.get("severity", "MEDIUM")
                    sev_badge = "🔴 CRITICAL" if sev == "CRITICAL" else ("🟠 HIGH" if sev == "HIGH" else "🟡 MEDIUM")
                    with st.expander(f"{sev_badge} - Line {f.get('line')}: {f.get('cwe')} ({f.get('category')})"):
                        st.markdown(f"**Defect:** {f.get('message')}")
                        st.markdown(f"**Remediation:** `{f.get('remediation')}`")

            # Remediation Summary
            if sec.get("remediations"):
                st.markdown("#### 💡 Automated Hardening Advice")
                for rem in sec.get("remediations", []):
                    st.write(f"- {rem}")

    # ─────────────────────────────────────────────────────────────
    # TAB 3: Autonomous Green & Secure Optimizer
    # ─────────────────────────────────────────────────────────────
    with tabs[2]:
        if opt is None:
            # If agent pipeline was run, offer 1-click optimization
            st.info("Click **⚡ Run Green & Secure Optimizer** to refactor, secure, and verify your code.")
            if st.button("Optimize Current Code Now"):
                with st.spinner("Optimizing..."):
                    opt = optimize_code(code_input)
                    st.session_state.opt_result = opt
                    st.rerun()
        else:
            # Show Optimizer Results
            verif_badge = "🟢 VERIFIED PASSED" if opt.verified else "🟡 BEST-EFFORT REFACTORED"
            st.markdown(f"### Closed-Loop Verification: {verif_badge}")
            st.caption(opt.verification_notes)

            # Score Delta Cards
            s1, s2, s3, s4 = st.columns(4)
            with s1:
                st.markdown(f"<div class='metric-card'><h3>{opt.original_eco_score} &rarr; {opt.optimized_eco_score}</h3><span>Eco Score (Delta: +{opt.eco_delta})</span></div>", unsafe_allow_html=True)
            with s2:
                st.markdown(f"<div class='metric-card'><h3>{opt.original_sec_score} &rarr; {opt.optimized_sec_score}</h3><span>Security Score (Delta: +{opt.sec_delta})</span></div>", unsafe_allow_html=True)
            with s3:
                st.markdown(f"<div class='metric-card'><h3>{len(opt.vulnerabilities_fixed)}</h3><span>CWEs Fixed</span></div>", unsafe_allow_html=True)
            with s4:
                st.markdown(f"<div class='metric-card'><h3>{len(opt.algorithmic_improvements)}</h3><span>Optimizations</span></div>", unsafe_allow_html=True)

            st.markdown("<div style='height: 18px;'></div>", unsafe_allow_html=True)

            # Side-by-Side Comparison
            col_orig, col_opt = st.columns(2)
            with col_orig:
                st.markdown("#### ❌ Original Code")
                st.code(opt.original_code, language="python")
            with col_opt:
                st.markdown("#### ✅ Refactored & Hardened Code")
                st.code(opt.optimized_code, language="python")

            # Unified Diff
            if opt.diff:
                with st.expander("🔍 View Unified Code Diff", expanded=True):
                    st.code(opt.diff, language="diff")

            # Improvements breakdown
            b1, b2 = st.columns(2)
            with b1:
                st.markdown("#### 🛡️ Security Fixes Applied")
                if opt.vulnerabilities_fixed:
                    for v in opt.vulnerabilities_fixed:
                        st.success(f"Fixed: {v}")
                else:
                    st.write("No security vulnerabilities required patching.")
            with b2:
                st.markdown("#### 🌿 Algorithmic Improvements")
                for a in opt.algorithmic_improvements:
                    st.info(f"Speedup: {a}")

    # ─────────────────────────────────────────────────────────────
    # TAB 4: Interactive Physics PDG Graph
    # ─────────────────────────────────────────────────────────────
    with tabs[3]:
        st.markdown("### 🌐 Program Dependence Graph (vis.js Physics Simulation)")
        st.caption("Drag nodes, zoom, toggle control/data edges, and click on nodes to inspect structural dependencies.")

        active_graph = ctx.pdg_graph if ctx else None
        active_taints = ctx.security_profile.get("tainted_flows", []) if ctx else []

        if not active_graph:
            from pdg_extractor import extract_pdg_graph
            active_graph = extract_pdg_graph(code_input)

        if active_graph.get("status") == "ok":
            html_vis = generate_pdg_html(active_graph, tainted_flows=active_taints, height="560px")
            components.html(html_vis, height=580)
        else:
            st.error(f"Failed to generate PDG: {active_graph.get('error')}")

    # ─────────────────────────────────────────────────────────────
    # TAB 5: Green Computing & Hardware Profiler
    # ─────────────────────────────────────────────────────────────
    with tabs[4]:
        st.markdown("### 🌿 Green Computing & Runtime Hardware Profiling")
        
        green = ctx.green_profile if ctx else {}
        hw = ctx.hardware_profile if ctx else {}

        # Top row: Hardware real-time metrics
        if hw:
            st.markdown("#### ⚡ Real-Time Dynamic Hardware Performance")
            h1, h2, h3, h4 = st.columns(4)
            h1.metric("Execution Latency", f"{hw.get('latency_ms', 0):.2f} ms")
            h2.metric("CPU Execution Time", f"{hw.get('cpu_time_ms', 0):.2f} ms", f"{hw.get('cpu_percent', 0)}% CPU")
            h3.metric("Peak Memory (RAM)", f"{hw.get('peak_ram_mb', 0):.4f} MB")
            h4.metric("Dynamic Energy", f"{hw.get('dynamic_energy_kwh', 0):.8f} kWh")

        st.markdown("#### 🍃 Static Green Computing Profile")
        if green:
            g1, g2, g3 = st.columns(3)
            g1.metric("Eco-Efficiency Score", f"{green.get('score', 100)}/100")
            g2.metric("Rating", green.get("rating", "Efficient"))
            g3.metric("Estimated CO2e", f"{green.get('estimated_co2_kg', 0):.8f} kg")

            st.info(green.get("summary", ""))

            st.markdown("#### Recommendations for Sustainable Code")
            for rec in green.get("recommendations", []):
                st.write(f"- {rec}")

            # Charts
            if "chart_data" in green:
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("##### Control Flow Distribution")
                    st.bar_chart({"Value": green["chart_data"].get("Control Flow", {})})
                with c2:
                    st.markdown("##### Efficiency Signals")
                    st.bar_chart({"Value": green["chart_data"].get("Efficiency Signals", {})})

    # ─────────────────────────────────────────────────────────────
    # TAB 6: AST Structure
    # ─────────────────────────────────────────────────────────────
    with tabs[5]:
        st.markdown("### 🌳 Abstract Syntax Tree (AST) Hierarchy")
        ast_text = ctx.ast_context if ctx else ""
        if not ast_text:
            from ast_extractor import extract_ast_context
            ast_text = extract_ast_context(code_input)
        st.code(ast_text, language="text")
