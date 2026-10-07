def load_multiple_files(paths):
    combined_lines = []
    for path in paths:
        with open(path, "r", encoding="utf-8") as file:
            for line in file:
                if line.strip():
                    combined_lines.append(line.strip())
    return combined_lines


if __name__ == "__main__":
    print(load_multiple_files(["data_a.txt", "data_b.txt"]))
