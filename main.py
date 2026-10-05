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
from engine.remediation import (
    build_remediation_plan,
    request_approval,
    execute_remediation,
)

from ai.analyzer import (
    build_ai_input,
    analyze_findings,
)


COLLECTORS = {
    "permit_root_login": get_permit_root_login,
    "password_authentication": get_password_authentication,
}


def save_json(file_name: str, data: dict) -> None:
    with open(
        file_name,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            data,
            file,
            indent=2,
            ensure_ascii=False,
        )


def scan_endpoint() -> dict:
    hostname = get_hostname()
    kernel = get_kernel_version()
    architecture = get_architecture()
    os_release = get_os_release()

    os_name = os_release.get("NAME", "Unknown")
    os_version = os_release.get("VERSION_ID", "Unknown")

    policies = load_policies("policies/linux.yaml")

    findings = []

    for policy in policies:
        collector_name = policy["collector"]
        collector = COLLECTORS.get(collector_name)

        if collector is None:
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

    return {
        "asset": {
            "hostname": hostname,
            "os": os_name,
            "version": os_version,
            "kernel": kernel,
            "architecture": architecture,
        },
        "findings": findings,
    }


def print_scan_report(scan_report: dict) -> None:
    asset = scan_report["asset"]

    print("=== AI Endpoint Security ===")
    print()
    print(f"Hostname     : {asset['hostname']}")
    print(f"OS           : {asset['os']}")
    print(f"Version      : {asset['version']}")
    print(f"Kernel       : {asset['kernel']}")
    print(f"Architecture : {asset['architecture']}")

    print()
    print("=== Security Findings ===")
    print()

    for finding in scan_report["findings"]:
        print(f"[{finding['id']}]")
        print(f"Title    : {finding['title']}")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Severity : {finding['severity']}")
        print(f"Result   : {finding['result']}")
        print()


def main():
    # 1. 최초 보안점검
    scan_report = scan_endpoint()

    print_scan_report(scan_report)

    save_json(
        "scan_report.json",
        scan_report,
    )

    # 2. FAIL Finding만 AI 분석
    ai_input = build_ai_input(scan_report)

    save_json(
        "ai_input.json",
        ai_input,
    )

    print("=== AI Security Analysis ===")
    print()

    ai_analysis = analyze_findings(ai_input)

    save_json(
        "ai_analysis.json",
        ai_analysis,
    )

    analyses = ai_analysis.get("analyses", [])

    if not analyses:
        print("No failed findings require AI analysis.")
        print()
    else:
        for analysis in analyses:
            print(f"[{analysis['finding_id']}]")
            print(f"Cause              : {analysis['cause']}")
            print(f"Risk               : {analysis['risk']}")
            print(f"Recommendation     : {analysis['recommendation']}")
            print(
                f"Operational Impact : "
                f"{analysis['operational_impact']}"
            )
            print()

    # 3. 자동조치 가능한 Finding으로 Plan 생성
    remediation_plan = build_remediation_plan(
        scan_report["findings"]
    )

    print("=== Remediation ===")
    print()

    if not remediation_plan:
        failed_findings = [
            finding
            for finding in scan_report["findings"]
            if finding["result"] == "FAIL"
        ]

        if failed_findings:
            print(
                "Failed findings exist, but no automated "
                "remediation is registered."
            )
        else:
            print("No remediation required. All policies passed.")

        return

    # 4. Human Approval 후 실제 조치
    remediation_executed = False

    for action in remediation_plan:
        print(f"Finding     : {action['finding_id']}")
        print(f"Action ID   : {action['action_id']}")
        print(f"Description : {action['description']}")

        approved = request_approval(action)

        if not approved:
            print("Remediation rejected.")
            print()
            continue

        execute_remediation(action)

        remediation_executed = True

    # 아무 조치도 승인되지 않았다면 종료
    if not remediation_executed:
        print("No remediation was executed.")
        return

    # 5. 실제 조치 후 재점검
    print()
    print("=== Verification Scan ===")
    print()

    verification_report = scan_endpoint()

    for finding in verification_report["findings"]:
        print(f"[{finding['id']}]")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Result   : {finding['result']}")
        print()

    save_json(
        "verification_report.json",
        verification_report,
    )

    # 6. 재점검 결과 요약
    remaining_failures = [
        finding
        for finding in verification_report["findings"]
        if finding["result"] == "FAIL"
    ]

    print("=== Verification Result ===")
    print()

    if not remaining_failures:
        print("All security policies passed after remediation.")
    else:
        print(
            f"{len(remaining_failures)} finding(s) "
            "remain unresolved."
        )


if __name__ == "__main__":
    main()