import csv
import requests


def fetch_rates(symbols):
    rates = {}
    for symbol in symbols:
        response = requests.get(f"https://example.com/rates/{symbol}")
        if response.status_code == 200:
            rates[symbol] = response.json().get("rate", 0)
        else:
            rates[symbol] = 0
    return rates


def write_rate_matrix(symbols, rates, output_path):
    with open(output_path, "w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        for base in symbols:
            row = []
            for quote in symbols:
                if quote == base:
                    row.append(1)
                else:
                    row.append(rates.get(base, 0) / max(rates.get(quote, 1), 1))
            writer.writerow(row)


if __name__ == "__main__":
    currency_symbols = ["USD", "EUR", "INR"]
    currency_rates = fetch_rates(currency_symbols)
    write_rate_matrix(currency_symbols, currency_rates, "rates.csv")
