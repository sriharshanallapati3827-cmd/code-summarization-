def fibonacci(number):
    if number <= 1:
        return number
    return fibonacci(number - 1) + fibonacci(number - 2)


def build_fibonacci_sequence(limit):
    sequence = []
    for number in range(limit):
        sequence.append(fibonacci(number))
    return sequence


if __name__ == "__main__":
    print(build_fibonacci_sequence(10))
