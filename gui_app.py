import streamlit as st

from main import run_pipeline


st.set_page_config(
    page_title="Code Summary Studio",
    page_icon="🧠",
    layout="wide",
)

st.markdown(
    """
    <style>
    .stApp {
        background: radial-gradient(circle at top right, #e7f1ff, #f9fbff 35%, #f5f7fa 100%);
    }
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        max-width: 1100px;
    }
    .hero {
        padding: 1.1rem 1.2rem;
        border-radius: 14px;
        background: linear-gradient(135deg, #0f172a 0%, #1d4ed8 60%, #0ea5e9 100%);
        color: white;
        margin-bottom: 1rem;
        box-shadow: 0 8px 24px rgba(2, 8, 23, 0.2);
    }
    .hero h1 {
        margin: 0;
        font-size: 1.7rem;
        font-weight: 700;
        letter-spacing: 0.2px;
    }
    .hero p {
        margin: 0.35rem 0 0 0;
        opacity: 0.95;
        font-size: 0.97rem;
    }
    div[data-testid="stTextArea"] textarea {
        border-radius: 12px;
        border: 1px solid #cbd5e1;
        font-family: Consolas, "Courier New", monospace;
        font-size: 0.92rem;
    }
    .stButton > button {
        border-radius: 12px;
        border: none;
        padding: 0.55rem 1rem;
        background: linear-gradient(135deg, #2563eb, #0284c7);
        color: white;
        font-weight: 600;
    }
    .stButton > button:hover {
        filter: brightness(1.04);
    }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
        <h1>Code Summary Studio</h1>
        <p>Paste Python code or upload a file, then click <strong>Summaries</strong> to generate AST, PDG, and summary output.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

left, right = st.columns([1.35, 1], gap="large")

with left:
    st.subheader("Input")
    code_input = st.text_area(
        "Write Python code",
        height=360,
        placeholder="def example(x):\n    return x * 2",
    )
    uploaded_file = st.file_uploader(
        "Or upload a Python file",
        type=["py", "txt"],
        accept_multiple_files=False,
    )

    run_button = st.button("Summaries", use_container_width=True, type="primary")

with right:
    st.subheader("Quick Tips")
    st.info(
        "1. Paste code directly for quick tests.\n"
        "2. Upload `.py` files for larger examples."
    )


def _resolve_source(code_text: str, file_obj) -> tuple[str, str]:
    if code_text.strip():
        return code_text, "editor"

    if file_obj is not None:
        raw = file_obj.getvalue()
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw.decode("latin-1")
        return decoded, file_obj.name

    return "", ""


if "pipeline_result" not in st.session_state:
    st.session_state.pipeline_result = None

if run_button:
    source_code, source_name = _resolve_source(code_input, uploaded_file)
    if not source_code.strip():
        st.warning("Please write code or upload a file before clicking Summaries.")
    else:
        with st.spinner("Analyzing code and generating summaries..."):
            try:
                result = run_pipeline(source_code, model_path=None)
                result["source_name"] = source_name
                st.session_state.pipeline_result = result
            except Exception as exc:
                st.error(f"Failed to generate output: {exc}")

if st.session_state.pipeline_result is not None:
    result = st.session_state.pipeline_result
    st.success("Analysis complete.")
    st.caption(f"Source: `{result.get('source_name', 'editor')}`")

    st.markdown("### Generated Summary")
    st.write(result["summary"])

    st.markdown("### PDG Output")
    st.code(result["pdg_context"], language="text")

    st.markdown("### AST Output")
    st.code(result["ast_context"], language="text")
