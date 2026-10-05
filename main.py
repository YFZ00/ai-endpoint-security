from collectors.linux import get_hostname


def main():
    print("=== AI Endpoint Security ===")
    print()

    hostname = get_hostname()

    print(f"Hostname : {hostname}")


if __name__ == "__main__":
    main()