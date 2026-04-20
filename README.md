# PDG-Enhanced Code Summarization via Open-Source API Models

This project summarizes Python code by combining:
1. **AST extraction** (structure)
2. **PDG extraction** (control/data dependencies)
3. **Open-source LLM API inference** (natural-language summary)

The pipeline now uses API calls to open-source models instead of local fine-tuned checkpoints.

## Default API Setup

- **Default API URL**: `https://router.huggingface.co/v1/chat/completions`
- **Default Model**: `Qwen/Qwen2.5-Coder-7B-Instruct`
- **API Key Env Vars** (either one):
  - `OPEN_SOURCE_API_KEY`
  - `HF_API_TOKEN`

## How to Run

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set your API key in `.env`:
   ```bash
   OPEN_SOURCE_API_KEY=your_api_key_here
   ```

3. Optional model/API overrides in `.env`:
   ```bash
   OPEN_SOURCE_MODEL_ID=Qwen/Qwen2.5-Coder-7B-Instruct
   OPEN_SOURCE_API_URL=https://router.huggingface.co/v1/chat/completions
   ```

4. Run the pipeline:
   ```bash
   python main.py --file my_python_file.py
   ```

5. Or pass code directly:
   ```bash
   python main.py --code "def add(a,b): return a+b"
   ```

6. Optional CLI model override:
   ```bash
   python main.py --model-path Qwen/Qwen2.5-Coder-7B-Instruct
   ```

## GUI App

Run the Streamlit GUI:

```bash
streamlit run gui_app.py
```

The GUI supports:
- Writing code in an editor section
- Uploading a `.py`/`.txt` file
- Clicking the `Summaries` button to generate:
  - Code Summary
  - AST output
  - PDG output

## Notes

- If the API key is missing or API call fails, the app falls back to an AST-based deterministic summary so it still produces output.
- `train.py` remains in the repo for experimentation, but the runtime summarization path now uses API inference.

## Groq Quick Setup

Use these `.env` values when using a Groq key:

```bash
OPEN_SOURCE_API_KEY=your_groq_key
OPEN_SOURCE_API_URL=https://api.groq.com/openai/v1/chat/completions
OPEN_SOURCE_MODEL_ID=llama-3.1-8b-instant
```
