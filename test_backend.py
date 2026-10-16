from backend import investigate


def main():
    result = investigate("demo.example")

    print("Domain:", result["domain"])
    print("Found:", result["found"])
    print("Explanation:", result["explanation"])
    print("Evidence:")

    for item in result["evidence"]:
        print(item)


if __name__ == "__main__":
    main()