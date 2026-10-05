from collectors.linux import (
    get_hostname,
    get_kernel_version,
    get_architecture,
    get_os_release,
    get_permit_root_login,
)

from engine.evaluator import evaluate_exact


def main():
    print("=== AI Endpoint Security ===")
    print()

    hostname = get_hostname()
    kernel = get_kernel_version()
    architecture = get_architecture()
    os_release = get_os_release()

    print(f"Hostname     : {hostname}")
    print(f"OS           : {os_release.get('NAME', 'Unknown')}")
    print(f"Version      : {os_release.get('VERSION_ID', 'Unknown')}")
    print(f"Kernel       : {kernel}")
    print(f"Architecture : {architecture}")

    print()
    print("=== Security Findings ===")
    print()

    actual = get_permit_root_login()
    expected = "no"

    result = evaluate_exact(actual, expected)

    print("[LINUX-SSH-001]")
    print("Title    : Disable direct SSH login for root")
    print(f"Expected : {expected}")
    print(f"Actual   : {actual}")
    print("Severity : HIGH")
    print(f"Result   : {result}")


if __name__ == "__main__":
    main()