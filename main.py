import json

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

    # Endpoint 기본 정보 수집
    hostname = get_hostname()
    kernel = get_kernel_version()
    architecture = get_architecture()
    os_release = get_os_release()

    os_name = os_release.get("NAME", "Unknown")
    os_version = os_release.get("VERSION_ID", "Unknown")

    print(f"Hostname     : {hostname}")
    print(f"OS           : {os_name}")
    print(f"Version      : {os_version}")
    print(f"Kernel       : {kernel}")
    print(f"Architecture : {architecture}")

    print()
    print("=== Security Findings ===")
    print()

    # YAML 정책 불러오기
    policies = load_policies("policies/linux.yaml")

    # 점검 결과 저장
    findings = []

    # 정책별 점검
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

        result = evaluate_exact(
            actual,
            expected,
        )

        finding = create_finding(
            policy=policy,
            actual=actual,
            result=result,
        )

        findings.append(finding)

        print(f"[{finding['id']}]")
        print(f"Title    : {finding['title']}")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Severity : {finding['severity']}")
        print(f"Result   : {finding['result']}")
        print()

    # 자산 정보 + Finding을 하나의 Scan Report로 구성
    scan_report = {
        "asset": {
            "hostname": hostname,
            "os": os_name,
            "version": os_version,
            "kernel": kernel,
            "architecture": architecture,
        },
        "findings": findings,
    }

    # Scan Report를 JSON 파일로 저장
    with open("scan_report.json", "w", encoding="utf-8") as file:
        json.dump(
            scan_report,
            file,
            indent=2,
            ensure_ascii=False,
        )


if __name__ == "__main__":
    main()