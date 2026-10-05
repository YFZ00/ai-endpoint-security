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

from ai.analyzer import build_ai_input


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

    # 전체 점검 결과 저장
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

        # 실제 설정값 수집
        actual = collector()

        # YAML의 기대값
        expected = policy["expected"]

        # 정책 기반 PASS / FAIL 판단
        result = evaluate_exact(
            actual,
            expected,
        )

        # Finding 생성
        finding = create_finding(
            policy=policy,
            actual=actual,
            result=result,
        )

        findings.append(finding)

        # 화면 출력
        print(f"[{finding['id']}]")
        print(f"Title    : {finding['title']}")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Severity : {finding['severity']}")
        print(f"Result   : {finding['result']}")
        print()

    # 자산 정보와 Finding을 Scan Report로 구성
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

    # 전체 Scan Report 저장
    with open("scan_report.json", "w", encoding="utf-8") as file:
        json.dump(
            scan_report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # FAIL Finding만 AI 분석용 데이터로 변환
    ai_input = build_ai_input(scan_report)

    # AI 분석용 입력 저장
    with open("ai_input.json", "w", encoding="utf-8") as file:
        json.dump(
            ai_input,
            file,
            indent=2,
            ensure_ascii=False,
        )


if __name__ == "__main__":
    main()