import json
import argparse

from collectors.linux import (
    get_hostname,
    get_kernel_version,
    get_architecture,
    get_os_release,
    get_permit_root_login,
    get_password_authentication,
    get_permit_empty_passwords,
    get_max_auth_tries,
    get_passwd_file_security,
    get_shadow_file_security,
    get_group_file_security,
    get_gshadow_file_security,
    get_pass_max_days,
    get_pass_min_days,
)

from collectors.windows import (
    get_windows_hostname,
    get_windows_os_name,
    get_windows_version,
    get_windows_build_number,
    get_windows_architecture,
    get_defender_realtime_protection,
    get_windows_firewall_all_enabled,
    get_guest_account_enabled,
    get_smb1_enabled,
    get_smb_signing_required,
    get_uac_enabled,
    get_defender_behavior_monitor,
    get_rdp_denied,
    get_rdp_nla_required,
    get_bitlocker_protection,
    get_tpm_ready,
    get_secure_boot_enabled,
    get_builtin_administrator_enabled,
    get_smb_client_signing_required,
)

from engine.evaluator import evaluate
from engine.policy_loader import load_policies
from engine.finding import create_finding
from engine.remediation import (
    build_remediation_plan,
    request_approval,
    execute_remediation,
)
from engine.audit import write_audit_event

from ai.analyzer import (
    build_ai_input,
    analyze_findings,
)


LINUX_COLLECTORS = {
    "permit_root_login": get_permit_root_login,
    "password_authentication": get_password_authentication,
    "permit_empty_passwords": get_permit_empty_passwords,
    "max_auth_tries": get_max_auth_tries,
    "passwd_file_security": get_passwd_file_security,
    "shadow_file_security": get_shadow_file_security,
    "group_file_security": get_group_file_security,
    "gshadow_file_security": get_gshadow_file_security,
    "pass_max_days": get_pass_max_days,
    "pass_min_days": get_pass_min_days,
}


WINDOWS_COLLECTORS = {
    "defender_realtime_protection": get_defender_realtime_protection,
    "windows_firewall_all_enabled": get_windows_firewall_all_enabled,
    "guest_account_enabled": get_guest_account_enabled,
    "smb1_enabled": get_smb1_enabled,
    "smb_signing_required": get_smb_signing_required,
    "uac_enabled": get_uac_enabled,
    "defender_behavior_monitor": get_defender_behavior_monitor,
    "rdp_denied": get_rdp_denied,
    "rdp_nla_required": get_rdp_nla_required,
    "bitlocker_protection": get_bitlocker_protection,
    "tpm_ready": get_tpm_ready,
    "secure_boot_enabled": get_secure_boot_enabled,
    "builtin_administrator_enabled": get_builtin_administrator_enabled,
    "smb_client_signing_required": get_smb_client_signing_required,
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


def evaluate_policies(
    policy_file: str,
    collectors: dict,
) -> list:
    policies = load_policies(policy_file)

    findings = []

    for policy in policies:
        collector_name = policy["collector"]
        collector = collectors.get(collector_name)

        if collector is None:
            print(
                f"[WARNING] Collector not registered: "
                f"{collector_name}"
            )
            continue

        actual = collector()
        expected = policy["expected"]
        comparator = policy["comparator"]

        result = evaluate(
            actual,
            expected,
            comparator,
        )

        finding = create_finding(
            policy=policy,
            actual=actual,
            result=result,
        )

        findings.append(finding)

    return findings


def scan_linux_endpoint() -> dict:
    hostname = get_hostname()
    kernel = get_kernel_version()
    architecture = get_architecture()
    os_release = get_os_release()

    os_name = os_release.get("NAME", "Unknown")
    os_version = os_release.get("VERSION_ID", "Unknown")

    findings = evaluate_policies(
        "policies/linux.yaml",
        LINUX_COLLECTORS,
    )

    return {
        "asset": {
            "platform": "linux",
            "hostname": hostname,
            "os": os_name,
            "version": os_version,
            "kernel": kernel,
            "architecture": architecture,
        },
        "findings": findings,
    }


def scan_windows_endpoint() -> dict:
    hostname = get_windows_hostname()
    os_name = get_windows_os_name()
    os_version = get_windows_version()
    build_number = get_windows_build_number()
    architecture = get_windows_architecture()

    findings = evaluate_policies(
        "policies/windows.yaml",
        WINDOWS_COLLECTORS,
    )

    return {
        "asset": {
            "platform": "windows",
            "hostname": hostname,
            "os": os_name,
            "version": os_version,
            "build": build_number,
            "architecture": architecture,
        },
        "findings": findings,
    }


def print_endpoint_report(
    endpoint_name: str,
    scan_report: dict,
) -> None:
    asset = scan_report["asset"]

    print(f"=== {endpoint_name} ===")
    print()

    print(f"Hostname     : {asset['hostname']}")
    print(f"OS           : {asset['os']}")
    print(f"Version      : {asset['version']}")

    if asset["platform"] == "linux":
        print(f"Kernel       : {asset['kernel']}")

    if asset["platform"] == "windows":
        print(f"Build        : {asset['build']}")

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


def analyze_endpoint(
    endpoint_name: str,
    scan_report: dict,
) -> tuple:
    print(f"=== AI Security Analysis: {endpoint_name} ===")
    print()

    ai_input = build_ai_input(scan_report)
    ai_analysis = analyze_findings(ai_input)

    analyses = ai_analysis.get("analyses", [])

    if not analyses:
        print("No failed findings require AI analysis.")
        print()

        return ai_input, ai_analysis

    for analysis in analyses:
        print(f"[{analysis['finding_id']}]")
        print(f"Cause              : {analysis['cause']}")
        print(f"Risk               : {analysis['risk']}")
        print(
            f"Recommendation     : "
            f"{analysis['recommendation']}"
        )
        print(
            f"Operational Impact : "
            f"{analysis['operational_impact']}"
        )
        print()

    return ai_input, ai_analysis


def remediate_endpoint(
    endpoint_name: str,
    scan_report: dict,
    scan_function,
):
    print(f"=== Remediation: {endpoint_name} ===")
    print()

    remediation_plan = build_remediation_plan(
        scan_report["findings"]
    )

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
            print(
                "No remediation required. "
                "All policies passed."
            )

        print()
        return None

    original_findings = {
        finding["id"]: finding
        for finding in scan_report["findings"]
    }

    executed_actions = []

    for action in remediation_plan:
        finding = original_findings[
            action["finding_id"]
        ]

        print(f"Finding     : {action['finding_id']}")
        print(f"Action ID   : {action['action_id']}")
        print(f"Description : {action['description']}")

        approved = request_approval(action)

        if not approved:
            print("Remediation rejected.")
            print()

            write_audit_event(
                {
                    "hostname": scan_report["asset"]["hostname"],
                    "platform": scan_report["asset"]["platform"],
                    "finding_id": action["finding_id"],
                    "before": finding["actual"],
                    "approved": False,
                    "action_id": action["action_id"],
                    "after": finding["actual"],
                    "verification": "NOT_EXECUTED",
                }
            )

            continue

        execute_remediation(action)

        executed_actions.append(
            {
                "finding_id": action["finding_id"],
                "action_id": action["action_id"],
                "before": finding["actual"],
            }
        )

    if not executed_actions:
        print("No remediation was executed.")
        print()
        return None

    print()
    print(f"=== Verification Scan: {endpoint_name} ===")
    print()

    verification_report = scan_function()

    verification_findings = {
        finding["id"]: finding
        for finding in verification_report["findings"]
    }

    for finding in verification_report["findings"]:
        print(f"[{finding['id']}]")
        print(f"Expected : {finding['expected']}")
        print(f"Actual   : {finding['actual']}")
        print(f"Result   : {finding['result']}")
        print()

    for action in executed_actions:
        verification = verification_findings.get(
            action["finding_id"]
        )

        if verification is None:
            continue

        write_audit_event(
            {
                "hostname": verification_report["asset"]["hostname"],
                "platform": verification_report["asset"]["platform"],
                "finding_id": action["finding_id"],
                "before": action["before"],
                "approved": True,
                "action_id": action["action_id"],
                "after": verification["actual"],
                "verification": verification["result"],
            }
        )

    remaining_failures = [
        finding
        for finding in verification_report["findings"]
        if finding["result"] == "FAIL"
    ]

    print(f"=== Verification Result: {endpoint_name} ===")
    print()

    if not remaining_failures:
        print(
            "All security policies passed "
            "after remediation."
        )
    else:
        print(
            f"{len(remaining_failures)} finding(s) "
            "remain unresolved."
        )

    print()

    return verification_report

def parse_args():
    parser = argparse.ArgumentParser(
        description="AI Endpoint Security"
    )

    parser.add_argument(
        "--endpoint",
        choices=["all", "linux", "windows"],
        default="all",
        help="Select endpoint to scan",
    )

    return parser.parse_args()

def main():
    args = parse_args()

    print("=== AI Endpoint Security ===")
    print()

    endpoints = []

    if args.endpoint in ("all", "linux"):
        linux_report = scan_linux_endpoint()

        print_endpoint_report(
            "Linux Endpoint",
            linux_report,
        )

        endpoints.append(
            {
                "name": "Linux Endpoint",
                "report": linux_report,
                "scan_function": scan_linux_endpoint,
            }
        )

    if args.endpoint in ("all", "windows"):
        windows_report = scan_windows_endpoint()

        print_endpoint_report(
            "Windows Endpoint",
            windows_report,
        )

        endpoints.append(
            {
                "name": "Windows Endpoint",
                "report": windows_report,
                "scan_function": scan_windows_endpoint,
            }
        )

    save_json(
        "scan_report.json",
        {
            "endpoints": [
                endpoint["report"]
                for endpoint in endpoints
            ]
        },
    )

    ai_inputs = []
    ai_analyses = []

    for endpoint in endpoints:
        ai_input, ai_analysis = analyze_endpoint(
            endpoint["name"],
            endpoint["report"],
        )

        ai_inputs.append(ai_input)

        ai_analyses.append(
            {
                "asset": endpoint["report"]["asset"],
                "analysis": ai_analysis,
            }
        )

    save_json(
        "ai_input.json",
        {
            "endpoints": ai_inputs
        },
    )

    save_json(
        "ai_analysis.json",
        {
            "endpoints": ai_analyses
        },
    )

    verification_reports = []

    for endpoint in endpoints:
        verification = remediate_endpoint(
            endpoint["name"],
            endpoint["report"],
            endpoint["scan_function"],
        )

        if verification is not None:
            verification_reports.append(
                verification
            )

    save_json(
        "verification_report.json",
        {
            "endpoints": verification_reports
        },
    )


if __name__ == "__main__":
    main()