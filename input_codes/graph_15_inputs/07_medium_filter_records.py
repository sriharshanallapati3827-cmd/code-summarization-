def filter_active_high_scores(records):
    selected = []
    for record in records:
        if record["active"] and record["score"] >= 70:
            selected.append(record["name"])
    return selected


if __name__ == "__main__":
    users = [
        {"name": "Asha", "active": True, "score": 91},
        {"name": "Dev", "active": False, "score": 86},
        {"name": "Mira", "active": True, "score": 62},
    ]
    print(filter_active_high_scores(users))
