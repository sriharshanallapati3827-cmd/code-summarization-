def find_duplicate_pairs(values):
    duplicate_pairs = []
    for left_index in range(len(values)):
        for right_index in range(left_index + 1, len(values)):
            if values[left_index] == values[right_index]:
                duplicate_pairs.append((left_index, right_index))
    return duplicate_pairs


if __name__ == "__main__":
    numbers = [4, 9, 2, 4, 7, 9, 1, 4]
    print(find_duplicate_pairs(numbers))
