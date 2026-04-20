import argparse
from pdg_extractor import extract_pdg_context
from ast_extractor import extract_ast_context
from model_pipeline import CodeSummarizer


def run_pipeline(source_code: str, model_path: str | None = None) -> dict:
    ast_context = extract_ast_context(source_code)
    pdg_context = extract_pdg_context(source_code)
    summarizer = CodeSummarizer(model_path=model_path)
    summary = summarizer.generate_summary(source_code, pdg_context)
    return {
        "ast_context": ast_context,
        "pdg_context": pdg_context,
        "summary": summary,
        "model_path": summarizer.model_path,
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

    result = run_pipeline(source_code, model_path=args.model_path)

    print("\n--- AST (Abstract Syntax Tree) Extraction ---")
    print(result["ast_context"])
    print("\n--- PDG (Program Dependence Graph) Extraction ---")
    print(result["pdg_context"])
    print("\n--- Code Summarization ---")
    print(f"Model used: {result['model_path']}")
    print("\nGenerated Summary:")
    print(result["summary"])


if __name__ == "__main__":
    main()
