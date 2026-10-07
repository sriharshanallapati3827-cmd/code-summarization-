def total_even_squares(values):
    return sum(value * value for value in values if value % 2 == 0)


if __name__ == "__main__":
    numbers = range(1, 25)
    print(total_even_squares(numbers))
