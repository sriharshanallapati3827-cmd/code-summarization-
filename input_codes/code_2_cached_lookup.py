def group_duplicate_indexes(values):
    indexes_by_value = {}
    for index, value in enumerate(values):
        if value not in indexes_by_value:
            indexes_by_value[value] = []
        indexes_by_value[value].append(index)

    return {
        value: indexes
        for value, indexes in indexes_by_value.items()
        if len(indexes) > 1
    }


if __name__ == "__main__":
    numbers = [4, 9, 2, 4, 7, 9, 1, 4]
    print(group_duplicate_indexes(numbers))
