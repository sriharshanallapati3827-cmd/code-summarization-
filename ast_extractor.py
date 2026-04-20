import ast

class CodeFeatureExtractor(ast.NodeVisitor):
    def __init__(self):
        self.features = {
            'functions': [],
            'classes': [],
        }

    def visit_FunctionDef(self, node):
        args = [arg.arg for arg in node.args.args]

        decorators = []
        if hasattr(ast, "unparse"):
            decorators = [ast.unparse(dec) for dec in node.decorator_list]

        has_loops = any(isinstance(n, (ast.For, ast.While)) for n in ast.walk(node))
        has_conditions = any(isinstance(n, ast.If) for n in ast.walk(node))

        try:
            returns = ast.unparse(node.returns) if node.returns and hasattr(ast, "unparse") else None
        except:
            returns = None

        func_info = {
            'name': node.name,
            'args': args,
            'decorators': decorators,
            'has_loops': has_loops,
            'has_conditions': has_conditions,
            'docstring': ast.get_docstring(node),
            'returns': returns
        }

        self.features['functions'].append(func_info)
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.features['classes'].append(node.name)
        self.generic_visit(node)


def extract_ast_context(source_code: str) -> str:
    """
    Extracts both:
    1. Structural features from AST
    2. Full AST tree representation
    """

    try:
        tree = ast.parse(source_code)

        # -------- FEATURE EXTRACTION --------
        extractor = CodeFeatureExtractor()
        extractor.visit(tree)

        feature_output = []

        if extractor.features['classes']:
            feature_output.append(
                f"Classes: {', '.join(extractor.features['classes'])}"
            )

        for func in extractor.features['functions']:
            desc = f"Function '{func['name']}' takes arguments ({', '.join(func['args'])})."

            traits = []
            if func['has_loops']:
                traits.append("contains loops")
            if func['has_conditions']:
                traits.append("contains conditional logic")
            if func['decorators']:
                traits.append(f"uses decorators ({', '.join(func['decorators'])})")
            if func['returns']:
                traits.append(f"returns {func['returns']}")

            if traits:
                desc += " It " + ", ".join(traits) + "."

            feature_output.append(desc)

        feature_text = "\n".join(feature_output)

        # -------- AST TREE --------
        ast_tree = ast.dump(
            tree,
            indent=4,
            include_attributes=False
        )

        # -------- COMBINED OUTPUT --------
        final_output = (
            "=== Extracted Structural Features ===\n"
            + feature_text
            + "\n\n=== Full AST Representation ===\n"
            + ast_tree
        )

        return final_output

    except Exception as e:
        return f"AST parsing failed: {str(e)}"


if __name__ == "__main__":
    sample_code = '''
def calculate_metrics(data, threshold=0.5):
    """Calculate basic metrics."""
    result = []
    for item in data:
        if item > threshold:
            result.append(item)
    return result
'''

    print(extract_ast_context(sample_code))