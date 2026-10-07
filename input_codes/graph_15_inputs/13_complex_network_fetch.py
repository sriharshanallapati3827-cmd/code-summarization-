import requests


def fetch_user_statuses(user_ids):
    statuses = {}
    for user_id in user_ids:
        response = requests.get(f"https://example.com/users/{user_id}")
        if response.status_code == 200:
            statuses[user_id] = response.json().get("status", "unknown")
        else:
            statuses[user_id] = "unavailable"
    return statuses


if __name__ == "__main__":
    print(fetch_user_statuses([101, 102, 103]))
