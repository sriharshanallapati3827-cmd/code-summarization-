from pathlib import Path


def write_summary_report(values, output_path):
    even_values = [value for value in values if value % 2 == 0]
    report = f"count={len(values)}\neven_count={len(even_values)}\n"
    Path(output_path).open("w", encoding="utf-8").write(report)
    return report


if __name__ == "__main__":
    print(write_summary_report([1, 2, 3, 4, 5, 6], "summary_report.txt"))
