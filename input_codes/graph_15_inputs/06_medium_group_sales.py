def group_sales_by_region(sales):
    totals = {}
    for sale in sales:
        region = sale["region"]
        if region not in totals:
            totals[region] = 0
        totals[region] += sale["amount"]
    return totals


if __name__ == "__main__":
    sample_sales = [
        {"region": "north", "amount": 120},
        {"region": "south", "amount": 80},
        {"region": "north", "amount": 40},
    ]
    print(group_sales_by_region(sample_sales))
