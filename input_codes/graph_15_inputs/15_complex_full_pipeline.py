import json
import requests


class Pipeline:
    def __init__(self, records):
        self.records = records

    def recursive_count(self, index=0):
        if index >= len(self.records):
            return 0
        return 1 + self.recursive_count(index + 1)

    def build_matrix_scores(self):
        scores = []
        for record in self.records:
            row = []
            for value in record["values"]:
                if value > 0:
                    row.append(value * record["weight"])
            scores.append(row)
        return scores

    def save(self, output_path):
        payload = {"count": self.recursive_count(), "scores": self.build_matrix_scores()}
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(payload, file)
        return payload


def fetch_config():
    response = requests.get("https://example.com/config.json")
    if response.status_code == 200:
        return response.json()
    return {}


if __name__ == "__main__":
    data = [
        {"values": [1, -2, 3], "weight": 2},
        {"values": [4, 5, -6], "weight": 3},
    ]
    pipeline = Pipeline(data)
    print(fetch_config())
    print(pipeline.save("pipeline_report.json"))
