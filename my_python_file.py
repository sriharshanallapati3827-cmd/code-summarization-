import ast
import os
from pathlib import Path

MPL_CONFIG_DIR = Path(".matplotlib").resolve()
MPL_CONFIG_DIR.mkdir(exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(MPL_CONFIG_DIR))

import matplotlib.pyplot as plt


INPUT_DIR = Path("input_codes/graph_15_inputs")
OUTPUT_DIR = Path("green_graphs")
CARBON_INTENSITY_KG_PER_KWH = 0.475


class CodeEnergyVisitor(ast.NodeVisitor):
    def __init__(self):
        self.loops = 0
        self.conditionals = 0
        self.function_calls = 0
        self.recursive_calls = 0
        self.file_operations = 0
        self.network_calls = 0
        self.max_loop_depth = 0
        self._loop_depth = 0
        self._function_stack = []

    def visit_FunctionDef(self, node):
        self._function_stack.append(node.name)
        self.generic_visit(node)
        self._function_stack.pop()

    def visit_For(self, node):
        self._visit_loop(node)

    def visit_While(self, node):
        self._visit_loop(node)

    def visit_If(self, node):
        self.conditionals += 1
        self.generic_visit(node)

    def visit_Call(self, node):
        self.function_calls += 1
        call_name = self._call_name(node)

        if self._function_stack and call_name == self._function_stack[-1]:
            self.recursive_calls += 1
        if call_name == "open" or call_name.endswith(".open"):
            self.file_operations += 1
        if call_name.startswith(("requests.", "urllib.", "httpx.", "aiohttp.")):
            self.network_calls += 1

        self.generic_visit(node)

    def _visit_loop(self, node):
        self.loops += 1
        self._loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self._loop_depth)
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


def analyze_code_file(path):
    source_code = path.read_text(encoding="utf-8")
    tree = ast.parse(source_code)
    visitor = CodeEnergyVisitor()
    visitor.visit(tree)

    code_lines = [
        line
        for line in source_code.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    energy_kwh = (
        0.10
        + len(code_lines) * 0.012
        + visitor.loops * 0.18
        + visitor.max_loop_depth * 0.24
        + visitor.conditionals * 0.04
        + visitor.function_calls * 0.025
        + visitor.recursive_calls * 0.35
        + visitor.file_operations * 0.22
        + visitor.network_calls * 0.50
    )

    return {
        "name": format_code_label(path.stem),
        "category": path.stem.split("_")[1].title(),
        "energy_kwh": round(energy_kwh, 3),
        "co2_kg": round(energy_kwh * CARBON_INTENSITY_KG_PER_KWH, 3),
        "lines": len(code_lines),
        "loops": visitor.loops,
        "max_loop_depth": visitor.max_loop_depth,
    }


def format_code_label(stem):
    parts = stem.split("_")
    number = parts[0]
    category = parts[1].title()
    title = " ".join(parts[2:]).title()
    return f"{number}\n{category}\n{title}"


def build_green_computing_data():
    code_files = sorted(INPUT_DIR.glob("*.py"))
    if not code_files:
        raise FileNotFoundError(f"No Python files found in {INPUT_DIR}")

    results = [analyze_code_file(path) for path in code_files]
    code_names = [result["name"] for result in results]
    energy_kwh = [result["energy_kwh"] for result in results]
    co2_kg = [result["co2_kg"] for result in results]
    return code_names, energy_kwh, co2_kg, results


def colors_for_inputs(code_names):
    colors = []
    for name in code_names:
        if "Simple" in name:
            colors.append("#2ca02c")
        elif "Medium" in name:
            colors.append("#1f77b4")
        else:
            colors.append("#d62728")
    return colors


def save_energy_consumption_graph(code_names, energy_kwh):
    plt.figure(figsize=(18, 7))
    bars = plt.bar(code_names, energy_kwh, color=colors_for_inputs(code_names))

    plt.title(f"Energy Consumption for {len(code_names)} Input Codes")
    plt.xlabel("Input Code")
    plt.ylabel("Estimated Energy Consumption (kWh)")
    plt.grid(True, axis="y", linestyle="--", alpha=0.35)
    plt.bar_label(bars, fmt="%.3f")
    plt.xticks(rotation=35, ha="right")
    plt.tight_layout()

    output_path = OUTPUT_DIR / "energy_consumption.png"
    plt.savefig(output_path, dpi=180)
    plt.close()
    return output_path


def save_co2_and_energy_graph(code_names, energy_kwh, co2_kg):
    x_positions = range(len(code_names))
    bar_width = 0.38

    fig, energy_axis = plt.subplots(figsize=(18, 7))
    co2_axis = energy_axis.twinx()

    energy_bars = energy_axis.bar(
        [x - bar_width / 2 for x in x_positions],
        energy_kwh,
        width=bar_width,
        label="Energy (kWh)",
        color="#2ca02c",
    )
    co2_bars = co2_axis.bar(
        [x + bar_width / 2 for x in x_positions],
        co2_kg,
        width=bar_width,
        label="CO2 Emission (kg)",
        color="#ff7f0e",
    )

    energy_axis.set_title("CO2 Emission and Energy Consumption by Input Code")
    energy_axis.set_xlabel("Input Code")
    energy_axis.set_ylabel("Estimated Energy Consumption (kWh)")
    co2_axis.set_ylabel("Estimated CO2 Emission (kg)")
    energy_axis.set_xticks(list(x_positions), code_names)
    energy_axis.grid(True, axis="y", linestyle="--", alpha=0.35)
    energy_axis.bar_label(energy_bars, fmt="%.3f")
    co2_axis.bar_label(co2_bars, fmt="%.3f")
    energy_axis.tick_params(axis="x", rotation=35)
    for label in energy_axis.get_xticklabels():
        label.set_horizontalalignment("right")

    handles = [energy_bars, co2_bars]
    labels = [handle.get_label() for handle in handles]
    energy_axis.legend(handles, labels, loc="upper right")

    fig.tight_layout()
    output_path = OUTPUT_DIR / "co2_and_energy.png"
    fig.savefig(output_path, dpi=180)
    plt.close(fig)
    return output_path


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)
    code_names, energy_kwh, co2_kg, results = build_green_computing_data()

    saved_files = [
        save_energy_consumption_graph(code_names, energy_kwh),
        save_co2_and_energy_graph(code_names, energy_kwh, co2_kg),
    ]

    print("Green computing graph images generated:")
    for path in saved_files:
        print(f"- {path}")

    print("\nCode analysis used for the graphs:")
    for result in results:
        print(
            f"- {result['name'].replace(chr(10), ' ')}: {result['energy_kwh']} kWh, "
            f"{result['co2_kg']} kg CO2, {result['lines']} code lines, "
            f"{result['loops']} loops, max loop depth {result['max_loop_depth']}"
        )


if __name__ == "__main__":
    main()
