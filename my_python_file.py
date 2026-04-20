def parse_orders(raw_orders):
    cleaned = []
    for order in raw_orders:
        if "id" not in order or "items" not in order or "status" not in order:
            continue
        cleaned.append(
            {
                "id": order["id"],
                "items": order["items"],
                "status": order["status"].lower(),
                "discount": float(order.get("discount", 0)),
            }
        )
    return cleaned


def compute_order_total(items, discount=0.0):
    subtotal = 0.0
    for item in items:
        price = float(item.get("price", 0))
        qty = int(item.get("qty", 1))
        subtotal += price * qty
    final_total = subtotal - discount
    return round(max(final_total, 0.0), 2)


def summarize_orders(orders):
    summary = {"completed": 0, "pending": 0, "cancelled": 0, "revenue": 0.0}
    for order in orders:
        status = order["status"]
        if status in summary:
            summary[status] += 1
        if status == "completed":
            summary["revenue"] += compute_order_total(order["items"], order["discount"])
    summary["revenue"] = round(summary["revenue"], 2)
    return summary


def find_high_value_orders(orders, threshold=500.0):
    high_value = []
    for order in orders:
        total = compute_order_total(order["items"], order["discount"])
        if total >= threshold:
            high_value.append({"id": order["id"], "total": total, "status": order["status"]})
    return high_value


if __name__ == "__main__":
    sample_orders = [
        {
            "id": "O-1001",
            "status": "Completed",
            "discount": 20,
            "items": [{"name": "Laptop", "price": 700, "qty": 1}, {"name": "Mouse", "price": 25, "qty": 2}],
        },
        {
            "id": "O-1002",
            "status": "Pending",
            "items": [{"name": "Keyboard", "price": 60, "qty": 1}],
        },
        {
            "id": "O-1003",
            "status": "Completed",
            "discount": 15,
            "items": [{"name": "Monitor", "price": 220, "qty": 2}],
        },
        {
            "id": "O-1004",
            "status": "Cancelled",
            "items": [{"name": "USB Hub", "price": 35, "qty": 1}],
        },
    ]

    orders = parse_orders(sample_orders)
    report = summarize_orders(orders)
    high_value = find_high_value_orders(orders, threshold=400.0)

    print("Order Summary:", report)
    print("High Value Orders:", high_value)
