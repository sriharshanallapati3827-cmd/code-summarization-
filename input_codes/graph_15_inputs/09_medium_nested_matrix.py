def matrix_positive_total(matrix):
    total = 0
    for row in matrix:
        for value in row:
            if value > 0:
                total += value
    return total


if __name__ == "__main__":
    numbers = [[1, -2, 3], [4, 5, -6], [7, 8, 9]]
    print(matrix_positive_total(numbers))
