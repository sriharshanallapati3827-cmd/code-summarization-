def summarize_top_products(products):
    sorted_products = sorted(products, key=lambda product: product["sales"], reverse=True)
    top_names = [product["name"] for product in sorted_products[:3]]
    total_sales = sum(product["sales"] for product in sorted_products)
    return {"top_products": top_names, "total_sales": total_sales}


if __name__ == "__main__":
    inventory = [
        {"name": "Laptop", "sales": 25},
        {"name": "Keyboard", "sales": 18},
        {"name": "Monitor", "sales": 20},
        {"name": "Mouse", "sales": 12},
    ]
    print(summarize_top_products(inventory))
