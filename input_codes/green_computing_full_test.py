import json
import requests
from pathlib import Path


class DataProcessor:
    def __init__(self, values):
        self.values = values

    def recursive_sum(self, index=0):
        if index >= len(self.values):
            return 0
        return self.values[index] + self.recursive_sum(index + 1)

    def find_duplicate_pairs(self):
        duplicate_pairs = []

        for left_index in range(len(self.values)):
            for right_index in range(left_index + 1, len(self.values)):
                if self.values[left_index] == self.values[right_index]:
                    duplicate_pairs.append((left_index, right_index))

        return duplicate_pairs

    def filter_even_values(self):
        return [value for value in self.values if value % 2 == 0]

    def sum_large_values(self):
        return sum(value for value in self.values if value > 10)

    def save_report(self, output_path):
        report = {
            "total": self.recursive_sum(),
            "duplicates": self.find_duplicate_pairs(),
            "even_values": self.filter_even_values(),
            "large_value_sum": self.sum_large_values(),
        }

        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(report, file, indent=2)

        return report


def fetch_remote_config(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return {}


def process_matrix(matrix):
    results = []

    for row in matrix:
        row_total = 0

        for value in row:
            if value > 0:
                row_total += value

        if row_total > 20:
            results.append(row_total)

    return results


if __name__ == "__main__":
    numbers = [4, 9, 2, 4, 7, 9, 1, 4, 15, 21]
    processor = DataProcessor(numbers)

    config = fetch_remote_config("https://example.com/config.json")
    report = processor.save_report("green_test_report.json")

    matrix = [
        [1, 2, 3],
        [10, 15, 20],
        [5, -1, 8],
    ]

    matrix_result = process_matrix(matrix)

    print("Config:", config)
    print("Report:", report)
    print("Matrix result:", matrix_result)
