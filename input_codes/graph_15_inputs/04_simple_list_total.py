def list_total(values):
    total = 0
    for value in values:
        total += value
    return total


if __name__ == "__main__":
    print(list_total([2, 4, 6, 8]))
