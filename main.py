from collectors.linux import (
    get_hostname,
    get_kernel_version,
    get_architecture,
    get_os_release,
    get_permit_root_login,
    get_password_authentication,
)

from engine.evaluator import evaluate_exact
from engine.policy_loader import load_policies
from engine.finding import create_finding


COLLECTORS = {
    "permit_root_login": get_permit_root_login,
    "password_authentication": get_password_authentication,
}


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

    policies = load_policies("policies/linux.yaml")

    for policy in policies:
        collector_name = policy["collector"]
        collector = COLLECTORS.get(collector_name)

        if collector is None:
            print(f"[{policy['id']}]")
            print(f"Error    : Unknown collector '{collector_name}'")
            print()
            continue

        actual = collector()
        expected = policy["expected"]

        result = evaluate_exact(actual, expected)

        finding = create_finding(
            policy=policy,
            actual=actual,
            result=result,
        )

        print(f"[{finding['id']}]")
        print(f"Title    : {finding['title']}")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Severity : {finding['severity']}")
        print(f"Result   : {finding['result']}")
        print()


if __name__ == "__main__":
    main()