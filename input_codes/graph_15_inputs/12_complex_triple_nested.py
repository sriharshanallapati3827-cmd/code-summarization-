def count_matching_triplets(values):
    matches = 0
    for first in values:
        for second in values:
            for third in values:
                if first + second == third:
                    matches += 1
    return matches


if __name__ == "__main__":
    print(count_matching_triplets([1, 2, 3, 4, 5]))
