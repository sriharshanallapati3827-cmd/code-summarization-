def calculate_inventory_value(items):
    total = 0
    low_stock = []
    for item in items:
        total += item["price"] * item["quantity"]
        if item["quantity"] < 5:
            low_stock.append(item["name"])
    return {"total_value": total, "low_stock": low_stock}


if __name__ == "__main__":
    inventory = [
        {"name": "Laptop", "price": 700, "quantity": 3},
        {"name": "Mouse", "price": 25, "quantity": 20},
        {"name": "Keyboard", "price": 60, "quantity": 4},
    ]
    print(calculate_inventory_value(inventory))
