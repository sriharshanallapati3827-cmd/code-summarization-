import os
import ast
import re
import requests
from dotenv import load_dotenv

load_dotenv()

class CodeSummarizer:
    def __init__(self, model_path: str | None = None):
        self.api_key = (
            os.getenv("OPEN_SOURCE_API_KEY")
            or os.getenv("GROQ_API_KEY")
            or os.getenv("HF_API_TOKEN")
        )

        configured_url = os.getenv("OPEN_SOURCE_API_URL")
        if configured_url:
            self.api_url = configured_url
        elif self.api_key and self.api_key.startswith("gsk_"):
            # Groq OpenAI-compatible endpoint
            self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        else:
            self.api_url = "https://router.huggingface.co/v1/chat/completions"

        # Selection priority:
        # 1) Explicit CLI --model-path
        # 2) OPEN_SOURCE_MODEL_ID env var
        # 3) Default open-source model id
        default_model = "Qwen/Qwen2.5-Coder-7B-Instruct"
        if self.api_key and self.api_key.startswith("gsk_"):
            default_model = "llama-3.1-8b-instant"

        self.model_path = model_path or os.getenv("OPEN_SOURCE_MODEL_ID") or default_model

        print(f"Using open-source API model: {self.model_path}")
        print(f"API endpoint: {self.api_url}")

    def generate_summary(self, source_code: str, pdg_context: str = "") -> str:
        if not self.api_key:
            return "API summary unavailable: missing OPEN_SOURCE_API_KEY/GROQ_API_KEY/HF_API_TOKEN."

        if pdg_context:
            user_prompt = (
                "Summarize this Python code in plain English.\n"
                "Focus on behavior, inputs, outputs, and important conditions.\n"
                "Do not output code.\n\n"
                f"PDG Info:\n{pdg_context}\n\n"
                f"Code:\n{source_code}"
            )
        else:
            user_prompt = (
                "Summarize this Python code in plain English.\n"
                "Focus on behavior, inputs, outputs, and important conditions.\n"
                "Do not output code.\n\n"
                f"Code:\n{source_code}"
            )

        summary = self._call_open_source_api(user_prompt)
        if not summary:
            return "API summary unavailable: request failed. Check API key, model, endpoint, and network access."

        summary = summary.strip()

        return summary

    def _call_open_source_api(self, user_prompt: str) -> str | None:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model_path,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You summarize Python code precisely. "
                        "Always respond with 1-3 sentences in plain English."
                    ),
                },
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 120,
        }

        try:
            response = requests.post(
                self.api_url,
                headers=headers,
                json=payload,
                timeout=60,
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except requests.HTTPError as exc:
            status = exc.response.status_code if exc.response is not None else "unknown"
            body = exc.response.text[:500] if exc.response is not None else ""
            print(
                "API summarization failed: "
                f"HTTP {status}. Response: {body}"
            )
            return None
        except Exception as exc:
            print(f"API summarization failed: {exc}")
            return None

    @staticmethod
    def _looks_like_code(summary: str, source_code: str) -> bool:
        if not summary:
            return True

        normalized = summary.strip().lower()
        code_markers = [
            "def ",
            "return ",
            "class ",
            "if ",
            "for ",
            "{",
            "}",
            ":",
            "=>",
        ]
        if any(marker in normalized for marker in code_markers):
            return True

        source_tokens = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", source_code))
        summary_tokens = set(re.findall(r"[a-zA-Z_][a-zA-Z0-9_]*", summary))
        if summary_tokens:
            overlap = len(summary_tokens & source_tokens) / len(summary_tokens)
            if overlap > 0.85:
                return True

        return False

    @staticmethod
    def _is_low_quality_summary(summary: str, fallback: str) -> bool:
        if not summary:
            return True

        summary_words = summary.split()
        if len(summary_words) < 6:
            return True

        summary_lower = summary.lower()
        fallback_lower = fallback.lower()

        # If fallback clearly states returned behavior and model summary does not,
        # prefer fallback for clearer functional intent.
        fallback_has_return_signal = "return" in fallback_lower
        summary_has_return_signal = "return" in summary_lower
        if fallback_has_return_signal and not summary_has_return_signal:
            return True

        return False

    @staticmethod
    def _rule_based_summary(source_code: str) -> str:
        try:
            tree = ast.parse(source_code)
        except Exception:
            return "Summarizes the provided code logic."

        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                func_name = node.name
                args = [arg.arg for arg in node.args.args]
                args_text = ", ".join(args) if args else "no arguments"

                has_loop = any(isinstance(n, (ast.For, ast.While)) for n in ast.walk(node))
                has_conditional = any(isinstance(n, ast.If) for n in ast.walk(node))
                has_return = any(isinstance(n, ast.Return) for n in ast.walk(node))
                purpose = CodeSummarizer._infer_function_purpose(node)

                parts = [f"This function '{func_name}' takes {args_text}."]
                if purpose:
                    parts.append(purpose)
                else:
                    if has_conditional:
                        parts.append("It applies conditional logic.")
                    if has_loop:
                        parts.append("It iterates through data using a loop.")
                    if has_return:
                        parts.append("It returns a computed result.")
                return " ".join(parts)

        return "Summarizes the provided code logic."

    @staticmethod
    def _infer_function_purpose(func_node: ast.FunctionDef) -> str | None:
        # Collect simple return expressions from the function.
        returns = [n for n in ast.walk(func_node) if isinstance(n, ast.Return) and n.value is not None]
        first_return = returns[0].value if returns else None

        if isinstance(first_return, ast.BinOp) and isinstance(first_return.op, ast.Add):
            return "It returns the sum of its input values."

        if isinstance(first_return, ast.Call) and isinstance(first_return.func, ast.Name):
            builtin_name = first_return.func.id
            if builtin_name == "sum":
                return "It returns the sum of the provided collection."
            if builtin_name == "len":
                return "It returns the number of items in the provided collection."
            if builtin_name == "sorted":
                return "It returns the input data in sorted order."
            if builtin_name in {"max", "min"}:
                return f"It returns the {builtin_name} value from the provided data."

        # Detect list-building filter pattern:
        # result = []
        # for item in items:
        #     if condition:
        #         result.append(item)
        # return result
        return_name = None
        if isinstance(first_return, ast.Name):
            return_name = first_return.id

        if return_name:
            assigns_empty_list = any(
                isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == return_name for t in n.targets)
                and isinstance(n.value, ast.List)
                and len(n.value.elts) == 0
                for n in func_node.body
            )
            if assigns_empty_list:
                condition_text = CodeSummarizer._extract_append_filter_condition(func_node, return_name)
                if condition_text:
                    return f"It filters the input data and returns items where {condition_text}."
                if CodeSummarizer._has_append_to_list(func_node, return_name):
                    return "It builds and returns a new list based on the input data."

        return None

    @staticmethod
    def _has_append_to_list(func_node: ast.FunctionDef, list_name: str) -> bool:
        for node in ast.walk(func_node):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == list_name
                and node.func.attr == "append"
            ):
                return True
        return False

    @staticmethod
    def _extract_append_filter_condition(func_node: ast.FunctionDef, list_name: str) -> str | None:
        for if_node in [n for n in ast.walk(func_node) if isinstance(n, ast.If)]:
            has_target_append = any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name)
                and n.func.value.id == list_name
                and n.func.attr == "append"
                for n in ast.walk(if_node)
            )
            if has_target_append:
                return CodeSummarizer._describe_condition(if_node.test)
        return None

    @staticmethod
    def _describe_condition(expr: ast.AST) -> str:
        # Special-case common "even number" pattern: x % 2 == 0
        if isinstance(expr, ast.Compare) and len(expr.ops) == 1 and len(expr.comparators) == 1:
            left = expr.left
            op = expr.ops[0]
            right = expr.comparators[0]
            if isinstance(left, ast.BinOp) and isinstance(left.op, ast.Mod):
                if (
                    isinstance(left.right, ast.Constant)
                    and left.right.value == 2
                    and isinstance(right, ast.Constant)
                    and right.value == 0
                    and isinstance(op, ast.Eq)
                ):
                    return "the value is even"

        try:
            return ast.unparse(expr)
        except Exception:
            return "the condition is satisfied"
