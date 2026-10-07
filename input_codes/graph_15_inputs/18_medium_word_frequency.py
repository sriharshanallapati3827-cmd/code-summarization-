def word_frequency(sentence):
    counts = {}
    for word in sentence.lower().split():
        cleaned = word.strip(".,!?")
        if cleaned not in counts:
            counts[cleaned] = 0
        counts[cleaned] += 1
    return counts


if __name__ == "__main__":
    text = "Green code saves energy, and green design saves cost."
    print(word_frequency(text))
