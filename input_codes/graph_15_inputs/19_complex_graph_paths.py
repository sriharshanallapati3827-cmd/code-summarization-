def count_paths(graph, start, target, visited=None):
    if visited is None:
        visited = set()
    if start == target:
        return 1

    visited.add(start)
    total_paths = 0
    for neighbor in graph.get(start, []):
        if neighbor not in visited:
            total_paths += count_paths(graph, neighbor, target, visited.copy())
    return total_paths


if __name__ == "__main__":
    network = {
        "A": ["B", "C"],
        "B": ["C", "D"],
        "C": ["D"],
        "D": [],
    }
    print(count_paths(network, "A", "D"))
