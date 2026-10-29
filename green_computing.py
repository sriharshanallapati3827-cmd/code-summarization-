import ast
import html
from pathlib import Path

try:
    from agent_security.input_limits import safe_parse
except ImportError:
    safe_parse = ast.parse

try:
    from polyglot.language_detector import detect_language, SupportedLanguage
    from polyglot.parser_factory import ParserFactory
    _POLYGLOT_AVAILABLE = True
except ImportError:
    _POLYGLOT_AVAILABLE = False


CARBON_INTENSITY_KG_PER_KWH = 0.475
DEFAULT_DEVICE_WATTS = 45.0


class GreenCodeVisitor(ast.NodeVisitor):
    def __init__(self):
        self.metrics = {
            "functions": 0,
            "classes": 0,
            "imports": 0,
            "loops": 0,
            "conditionals": 0,
            "comprehensions": 0,
            "generator_expressions": 0,
            "recursive_functions": 0,
            "file_operations": 0,
            "network_calls": 0,
            "max_loop_depth": 0,
        }
        self._function_stack = []
        self._loop_depth = 0

    def visit_FunctionDef(self, node):
        self.metrics["functions"] += 1
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node):
        self.metrics["classes"] += 1
        self.generic_visit(node)

    def visit_Import(self, node):
        self.metrics["imports"] += 1
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        self.metrics["imports"] += 1
        self.generic_visit(node)

    def visit_For(self, node):
        self._enter_loop(node)

    def visit_AsyncFor(self, node):
        self._enter_loop(node)

    def visit_While(self, node):
        self._enter_loop(node)

    def visit_If(self, node):
        self.metrics["conditionals"] += 1
        self.generic_visit(node)

    def visit_ListComp(self, node):
        self.metrics["comprehensions"] += 1
        self.generic_visit(node)

    def visit_SetComp(self, node):
        self.metrics["comprehensions"] += 1
        self.generic_visit(node)

    def visit_DictComp(self, node):
        self.metrics["comprehensions"] += 1
        self.generic_visit(node)

    def visit_GeneratorExp(self, node):
        self.metrics["generator_expressions"] += 1
        self.generic_visit(node)

    def visit_Call(self, node):
        call_name = self._call_name(node)

        if self._function_stack and call_name == self._function_stack[-1]:
            self.metrics["recursive_functions"] += 1
        if call_name == "open" or call_name.endswith(".open"):
            self.metrics["file_operations"] += 1
        if call_name.startswith(("requests.", "urllib.", "httpx.", "aiohttp.")):
            self.metrics["network_calls"] += 1

        self.generic_visit(node)

    def _enter_loop(self, node):
        self.metrics["loops"] += 1
        self._loop_depth += 1
        self.metrics["max_loop_depth"] = max(self.metrics["max_loop_depth"], self._loop_depth)
        self.generic_visit(node)
        self._loop_depth -= 1

    @staticmethod
    def _call_name(node):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))


def analyze_cpp_green_computing(
    source_code: str,
    analysis_seconds: float = 0.0,
    device_watts: float = DEFAULT_DEVICE_WATTS,
) -> dict:
    lines = source_code.splitlines()
    total_lines = len(lines)
    comment_lines = [
        l for l in lines 
        if l.strip().startswith("//") or l.strip().startswith("/*") or l.strip().startswith("*")
    ]
    code_lines = [
        l for l in lines 
        if l.strip() and not (l.strip().startswith("//") or l.strip().startswith("/*") or l.strip().startswith("*"))
    ]
    blank_lines = [l for l in lines if not l.strip()]

    metrics = {
        "lines_total": total_lines,
        "lines_code": len(code_lines),
        "lines_comment": len(comment_lines),
        "lines_blank": len(blank_lines),
        "source_bytes": len(source_code.encode("utf-8")),
        "functions": 0,
        "classes": 0,
        "imports": 0,
        "loops": 0,
        "conditionals": 0,
        "comprehensions": 0,
        "generator_expressions": 0,
        "recursive_functions": 0,
        "file_operations": 0,
        "network_calls": 0,
        "max_loop_depth": 0,
    }
    issues = []
    recommendations = []

    if not _POLYGLOT_AVAILABLE:
        score = 100
        rating = "Efficient"
        energy_kwh = (max(analysis_seconds, 0.0) * device_watts) / 3_600_000
        co2_kg = energy_kwh * CARBON_INTENSITY_KG_PER_KWH
        return {
            "status": "ok",
            "score": score,
            "rating": rating,
            "summary": f"{rating} green score: {score}/100.",
            "metrics": metrics,
            "estimated_energy_kwh": round(energy_kwh, 8),
            "estimated_co2_kg": round(co2_kg, 8),
            "analysis_seconds": round(analysis_seconds, 4),
            "device_watts": device_watts,
            "carbon_intensity_kg_per_kwh": CARBON_INTENSITY_KG_PER_KWH,
            "chart_data": {},
            "recommendations": ["Polyglot parser not available for full C++ green audit."],
        }

    parsed = ParserFactory.parse(source_code, language=SupportedLanguage.CPP)
    root = parsed.root_node

    loop_types = {"for_statement", "while_statement", "do_statement", "for_range_loop"}
    cond_types = {"if_statement", "switch_statement"}
    file_keywords = {"fopen", "ifstream", "ofstream", "freopen", "fstream"}
    net_keywords = {"socket", "connect", "send", "recv", "curl"}

    max_depth = 0
    recursive_count = 0

    def traverse(node, current_depth: int, current_func: str | None = None):
        nonlocal max_depth, recursive_count

        node_type = node.type
        next_func = current_func

        if node_type == "function_definition":
            metrics["functions"] += 1
            for child in node.children:
                if child.type == "function_declarator":
                    for sub in child.children:
                        if sub.type == "identifier":
                            next_func = sub.text.decode("utf-8", errors="ignore")
        elif node_type in ("class_specifier", "struct_specifier"):
            metrics["classes"] += 1
        elif node_type == "preproc_include":
            metrics["imports"] += 1
        elif node_type in cond_types:
            metrics["conditionals"] += 1
        elif node_type == "call_expression":
            for child in node.children:
                if child.type == "identifier":
                    c_name = child.text.decode("utf-8", errors="ignore")
                    if c_name in file_keywords:
                        metrics["file_operations"] += 1
                    if c_name in net_keywords:
                        metrics["network_calls"] += 1
                    if current_func and c_name == current_func:
                        recursive_count += 1

        is_loop = node_type in loop_types
        new_depth = current_depth + 1 if is_loop else current_depth
        if is_loop:
            metrics["loops"] += 1
            if new_depth > max_depth:
                max_depth = new_depth

        for child in node.children:
            traverse(child, new_depth, next_func)

    traverse(root, 0, None)
    metrics["max_loop_depth"] = max_depth
    metrics["recursive_functions"] = recursive_count

    score = 100
    if metrics["max_loop_depth"] >= 3:
        score -= 22
        issues.append("deeply nested loops")
        recommendations.append("Flatten nested loops or pre-index data so repeated scans do less work.")
    elif metrics["max_loop_depth"] == 2:
        score -= 10
        recommendations.append("Review nested loops for opportunities to use std::unordered_map or cached lookups.")

    if metrics["recursive_functions"]:
        score -= min(18, metrics["recursive_functions"] * 6)
        issues.append("recursive calls")
        recommendations.append("Use iteration or memoization when recursion can revisit the same inputs.")

    if metrics["network_calls"]:
        score -= min(18, metrics["network_calls"] * 4)
        issues.append("network calls")
        recommendations.append("Batch remote calls and cache responses to reduce energy and latency.")

    if metrics["file_operations"]:
        score -= min(12, metrics["file_operations"] * 3)
        recommendations.append("Group file I/O operations and avoid repeated disk seeks inside loops.")

    if metrics["lines_code"] > 300:
        score -= 8
        recommendations.append("Split large C++ translation units into modular components.")

    score = max(0, min(100, score))
    energy_kwh = (max(analysis_seconds, 0.0) * device_watts) / 3_600_000
    co2_kg = energy_kwh * CARBON_INTENSITY_KG_PER_KWH

    if not recommendations:
        recommendations.append("The code has a light static footprint; keep inputs bounded and use move semantics/RAII.")

    if score >= 85:
        rating = "Efficient"
    elif score >= 65:
        rating = "Moderate"
    else:
        rating = "Needs attention"

    chart_data = {
        "Structure": {
            "Functions": metrics["functions"],
            "Classes": metrics["classes"],
            "Imports": metrics["imports"],
        },
        "Control Flow": {
            "Loops": metrics["loops"],
            "Conditionals": metrics["conditionals"],
            "Max loop depth": metrics["max_loop_depth"],
        },
        "Efficiency Signals": {
            "Comprehensions": 0,
            "Generators": 0,
            "Recursion": metrics["recursive_functions"],
            "Network calls": metrics["network_calls"],
            "File operations": metrics["file_operations"],
        },
        "Source Mix": {
            "Code": metrics["lines_code"],
            "Comments": metrics["lines_comment"],
            "Blank": metrics["lines_blank"],
        },
    }

    issue_text = ", ".join(issues) if issues else "no major static efficiency risks"
    return {
        "status": "ok",
        "score": score,
        "rating": rating,
        "summary": f"{rating} green score: {score}/100 with {issue_text}.",
        "metrics": metrics,
        "estimated_energy_kwh": round(energy_kwh, 8),
        "estimated_co2_kg": round(co2_kg, 8),
        "analysis_seconds": round(analysis_seconds, 4),
        "device_watts": device_watts,
        "carbon_intensity_kg_per_kwh": CARBON_INTENSITY_KG_PER_KWH,
        "chart_data": chart_data,
        "recommendations": recommendations,
    }


def analyze_green_computing(
    source_code: str,
    analysis_seconds: float = 0.0,
    device_watts: float = DEFAULT_DEVICE_WATTS,
    language: str | None = None,
) -> dict:
    # ── Polyglot C++ Routing Check ───────────────────────────────────────────
    if _POLYGLOT_AVAILABLE:
        is_cpp = False
        if language:
            is_cpp = str(language).lower() in ("cpp", "c++", "cxx")
        else:
            detected = detect_language(source_code)
            is_cpp = (detected == SupportedLanguage.CPP)

        if is_cpp:
            return analyze_cpp_green_computing(
                source_code,
                analysis_seconds=analysis_seconds,
                device_watts=device_watts,
            )

    lines = source_code.splitlines()
    total_lines = len(lines)
    code_lines = [
        line
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    ]
    comment_lines = [line for line in lines if line.lstrip().startswith("#")]
    blank_lines = [line for line in lines if not line.strip()]

    metrics = {
        "lines_total": total_lines,
        "lines_code": len(code_lines),
        "lines_comment": len(comment_lines),
        "lines_blank": len(blank_lines),
        "source_bytes": len(source_code.encode("utf-8")),
    }
    issues = []
    recommendations = []

    try:
        tree = safe_parse(source_code)
    except SyntaxError as exc:
        return {
            "status": "invalid",
            "score": 0,
            "summary": f"Green analysis unavailable because Python parsing failed: {exc}",
            "metrics": metrics,
            "estimated_energy_kwh": 0.0,
            "estimated_co2_kg": 0.0,
            "chart_data": {},
            "recommendations": ["Fix syntax errors before running the green-computing analysis."],
        }

    visitor = GreenCodeVisitor()
    visitor.visit(tree)
    metrics.update(visitor.metrics)

    score = 100
    if metrics["max_loop_depth"] >= 3:
        score -= 22
        issues.append("deeply nested loops")
        recommendations.append("Flatten nested loops or pre-index data so repeated scans do less work.")
    elif metrics["max_loop_depth"] == 2:
        score -= 10
        recommendations.append("Review nested loops for opportunities to use dictionaries, sets, or cached lookups.")

    if metrics["recursive_functions"]:
        score -= min(18, metrics["recursive_functions"] * 6)
        issues.append("recursive calls")
        recommendations.append("Use iteration or memoization when recursion can revisit the same inputs.")

    if metrics["network_calls"]:
        score -= min(18, metrics["network_calls"] * 4)
        issues.append("network calls")
        recommendations.append("Batch remote calls and cache stable responses to reduce energy and latency.")

    if metrics["file_operations"]:
        score -= min(12, metrics["file_operations"] * 3)
        recommendations.append("Group file reads/writes and avoid repeatedly opening the same file in loops.")

    if metrics["lines_code"] > 300:
        score -= 8
        recommendations.append("Split large modules into focused units so only necessary code paths run.")

    if metrics["generator_expressions"] > 0:
        score += min(6, metrics["generator_expressions"] * 2)
    if metrics["comprehensions"] > 0 and metrics["max_loop_depth"] <= 1:
        score += min(4, metrics["comprehensions"])

    score = max(0, min(100, score))
    energy_kwh = (max(analysis_seconds, 0.0) * device_watts) / 3_600_000
    co2_kg = energy_kwh * CARBON_INTENSITY_KG_PER_KWH

    if not recommendations:
        recommendations.append("The code has a light static footprint; keep inputs bounded and reuse computed results.")

    if score >= 85:
        rating = "Efficient"
    elif score >= 65:
        rating = "Moderate"
    else:
        rating = "Needs attention"

    chart_data = {
        "Structure": {
            "Functions": metrics["functions"],
            "Classes": metrics["classes"],
            "Imports": metrics["imports"],
        },
        "Control Flow": {
            "Loops": metrics["loops"],
            "Conditionals": metrics["conditionals"],
            "Max loop depth": metrics["max_loop_depth"],
        },
        "Efficiency Signals": {
            "Comprehensions": metrics["comprehensions"],
            "Generators": metrics["generator_expressions"],
            "Recursion": metrics["recursive_functions"],
            "Network calls": metrics["network_calls"],
            "File operations": metrics["file_operations"],
        },
        "Source Mix": {
            "Code": metrics["lines_code"],
            "Comments": metrics["lines_comment"],
            "Blank": metrics["lines_blank"],
        },
    }

    issue_text = ", ".join(issues) if issues else "no major static efficiency risks"
    return {
        "status": "ok",
        "score": score,
        "rating": rating,
        "summary": f"{rating} green score: {score}/100 with {issue_text}.",
        "metrics": metrics,
        "estimated_energy_kwh": round(energy_kwh, 8),
        "estimated_co2_kg": round(co2_kg, 8),
        "analysis_seconds": round(analysis_seconds, 4),
        "device_watts": device_watts,
        "carbon_intensity_kg_per_kwh": CARBON_INTENSITY_KG_PER_KWH,
        "chart_data": chart_data,
        "recommendations": recommendations,
    }


def write_green_report_svg(profile: dict, output_path: str | Path) -> Path:
    output_path = Path(output_path)
    chart = profile.get("chart_data", {}).get("Control Flow", {})
    values = [
        ("Loops", chart.get("Loops", 0)),
        ("Conditionals", chart.get("Conditionals", 0)),
        ("Depth", chart.get("Max loop depth", 0)),
    ]
    max_value = max([value for _, value in values] + [1])
    bars = []
    for index, (label, value) in enumerate(values):
        width = int((value / max_value) * 360) if max_value else 0
        y = 150 + index * 58
        bars.append(
            f'<text x="70" y="{y + 22}" font-size="15" fill="#334155">{html.escape(label)}</text>'
            f'<rect x="180" y="{y}" width="{width}" height="30" rx="5" fill="#2f855a" />'
            f'<text x="{190 + width}" y="{y + 21}" font-size="14" fill="#0f172a">{value}</text>'
        )

    score = int(profile.get("score", 0))
    score_width = int((score / 100) * 460)
    summary = html.escape(profile.get("summary", "Green computing report"))
    recommendations = profile.get("recommendations", [])[:3]
    recommendation_text = "".join(
        f'<text x="70" y="{365 + i * 28}" font-size="14" fill="#334155">- {html.escape(item)}</text>'
        for i, item in enumerate(recommendations)
    )

    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="720" height="470" viewBox="0 0 720 470">
<rect width="720" height="470" fill="#f8fafc" />
<text x="70" y="62" font-size="28" font-family="Arial, sans-serif" font-weight="700" fill="#0f172a">Green Computing Report</text>
<text x="70" y="94" font-size="15" font-family="Arial, sans-serif" fill="#475569">{summary}</text>
<text x="70" y="125" font-size="15" font-family="Arial, sans-serif" fill="#334155">Eco score</text>
<rect x="180" y="108" width="460" height="26" rx="6" fill="#dbeafe" />
<rect x="180" y="108" width="{score_width}" height="26" rx="6" fill="#22c55e" />
<text x="650" y="127" font-size="15" font-family="Arial, sans-serif" fill="#0f172a">{score}/100</text>
{"".join(bars)}
<text x="70" y="330" font-size="18" font-family="Arial, sans-serif" font-weight="700" fill="#0f172a">Recommendations</text>
{recommendation_text}
</svg>
"""
    output_path.write_text(svg, encoding="utf-8")
    return output_path
