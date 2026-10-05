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

from ai.analyzer import (
    build_ai_input,
    analyze_findings,
)


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

    findings = []

    # 정책별 보안점검
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

    # Scan Report 생성
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

    with open(
        "scan_report.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            scan_report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # FAIL Finding만 AI 입력으로 변환
    ai_input = build_ai_input(scan_report)

    with open(
        "ai_input.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            ai_input,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # 실제 AI 분석
    print("=== AI Security Analysis ===")
    print()

    ai_analysis = analyze_findings(ai_input)

    # AI 분석 결과 저장
    with open(
        "ai_analysis.json",
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            ai_analysis,
            file,
            indent=2,
            ensure_ascii=False,
        )

    # AI 분석 결과 화면 출력
    for analysis in ai_analysis.get("analyses", []):
        print(f"[{analysis['finding_id']}]")
        print(f"Cause              : {analysis['cause']}")
        print(f"Risk               : {analysis['risk']}")
        print(f"Recommendation     : {analysis['recommendation']}")
        print(f"Operational Impact : {analysis['operational_impact']}")
        print()


if __name__ == "__main__":
    main()