def sum_even_squares(values):
    return sum(value * value for value in values if value % 2 == 0)


if __name__ == "__main__":
    print(sum_even_squares(range(1, 12)))
