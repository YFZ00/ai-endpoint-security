import argparse
import json

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
from engine.policy_loader import load_policy_set
from engine.finding import create_finding
from engine.remediation import (
    build_remediation_plan,
    request_approval,
    execute_remediation,
    validate_agent_proposals,
)
from engine.audit import write_audit_event
from engine.posture import calculate_posture
from engine.exception import apply_exceptions

from ai.agent import run_security_agent


LINUX_COLLECTORS = {
    "permit_root_login":
        get_permit_root_login,
    "password_authentication":
        get_password_authentication,
    "permit_empty_passwords":
        get_permit_empty_passwords,
    "max_auth_tries":
        get_max_auth_tries,
    "passwd_file_security":
        get_passwd_file_security,
    "shadow_file_security":
        get_shadow_file_security,
    "group_file_security":
        get_group_file_security,
    "gshadow_file_security":
        get_gshadow_file_security,
    "pass_max_days":
        get_pass_max_days,
    "pass_min_days":
        get_pass_min_days,
}


WINDOWS_COLLECTORS = {
    "defender_realtime_protection":
        get_defender_realtime_protection,
    "windows_firewall_all_enabled":
        get_windows_firewall_all_enabled,
    "guest_account_enabled":
        get_guest_account_enabled,
    "smb1_enabled":
        get_smb1_enabled,
    "smb_signing_required":
        get_smb_signing_required,
    "uac_enabled":
        get_uac_enabled,
    "defender_behavior_monitor":
        get_defender_behavior_monitor,
    "rdp_denied":
        get_rdp_denied,
    "rdp_nla_required":
        get_rdp_nla_required,
    "bitlocker_protection":
        get_bitlocker_protection,
    "tpm_ready":
        get_tpm_ready,
    "secure_boot_enabled":
        get_secure_boot_enabled,
    "builtin_administrator_enabled":
        get_builtin_administrator_enabled,
    "smb_client_signing_required":
        get_smb_client_signing_required,
}


def save_json(
    file_name: str,
    data: dict,
) -> None:
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
) -> tuple:
    policy_data = load_policy_set(
        policy_file
    )

    policy_set = policy_data[
        "metadata"
    ]

    policies = policy_data[
        "policies"
    ]

    findings = []

    for policy in policies:
        collector_name = policy[
            "collector"
        ]

        collector = collectors.get(
            collector_name
        )

        if collector is None:
            print(
                "[WARNING] Collector not "
                f"registered: {collector_name}"
            )

            continue

        actual = collector()

        result = evaluate(
            actual,
            policy["expected"],
            policy["comparator"],
        )

        finding = create_finding(
            policy=policy,
            actual=actual,
            result=result,
        )

        finding[
            "policy_set_version"
        ] = policy_set["version"]

        findings.append(
            finding
        )

    return (
        policy_set,
        findings,
    )


def scan_linux_endpoint() -> dict:
    os_release = get_os_release()

    policy_set, findings = (
        evaluate_policies(
            "policies/linux.yaml",
            LINUX_COLLECTORS,
        )
    )

    report = {
        "asset": {
            "platform": "linux",
            "hostname": get_hostname(),
            "os": os_release.get(
                "NAME",
                "Unknown",
            ),
            "version": os_release.get(
                "VERSION_ID",
                "Unknown",
            ),
            "kernel":
                get_kernel_version(),
            "architecture":
                get_architecture(),
        },
        "policy_set": policy_set,
        "findings": findings,
    }

    report = apply_exceptions(
        report
    )

    report["posture"] = (
        calculate_posture(
            report["findings"]
        )
    )

    return report


def scan_windows_endpoint() -> dict:
    policy_set, findings = (
        evaluate_policies(
            "policies/windows.yaml",
            WINDOWS_COLLECTORS,
        )
    )

    report = {
        "asset": {
            "platform": "windows",
            "hostname":
                get_windows_hostname(),
            "os":
                get_windows_os_name(),
            "version":
                get_windows_version(),
            "build":
                get_windows_build_number(),
            "architecture":
                get_windows_architecture(),
        },
        "policy_set": policy_set,
        "findings": findings,
    }

    report = apply_exceptions(
        report
    )

    report["posture"] = (
        calculate_posture(
            report["findings"]
        )
    )

    return report


def print_endpoint_report(
    endpoint_name: str,
    scan_report: dict,
) -> None:
    asset = scan_report["asset"]
    policy_set = scan_report[
        "policy_set"
    ]
    posture = scan_report["posture"]

    print(
        f"=== {endpoint_name} ==="
    )
    print()

    print(
        f"Hostname     : "
        f"{asset['hostname']}"
    )
    print(
        f"OS           : "
        f"{asset['os']}"
    )
    print(
        f"Version      : "
        f"{asset['version']}"
    )

    if asset["platform"] == "linux":
        print(
            f"Kernel       : "
            f"{asset['kernel']}"
        )

    if asset["platform"] == "windows":
        print(
            f"Build        : "
            f"{asset['build']}"
        )

    print(
        f"Architecture : "
        f"{asset['architecture']}"
    )

    print()
    print("=== Policy Set ===")
    print()

    print(
        f"Name         : "
        f"{policy_set['name']}"
    )
    print(
        f"Version      : "
        f"{policy_set['version']}"
    )
    print(
        f"Updated At   : "
        f"{policy_set['updated_at']}"
    )

    print()
    print("=== Endpoint Posture ===")
    print()

    print(
        f"Score        : "
        f"{posture['score']} / 100"
    )

    if (
        posture["raw_score"]
        != posture["score"]
    ):
        print(
            f"Raw Score    : "
            f"{posture['raw_score']} / 100"
        )

    print(
        f"Risk Level   : "
        f"{posture['risk_level']}"
    )

    if (
        posture["raw_risk_level"]
        != posture["risk_level"]
    ):
        print(
            f"Raw Risk     : "
            f"{posture['raw_risk_level']}"
        )

    print(
        f"Exceptions   : "
        f"{posture['exception_count']}"
    )

    counts = posture[
        "failure_counts"
    ]

    print(
        f"Failures     : "
        f"CRITICAL={counts['CRITICAL']} "
        f"HIGH={counts['HIGH']} "
        f"MEDIUM={counts['MEDIUM']} "
        f"LOW={counts['LOW']}"
    )

    print()
    print("=== Security Findings ===")
    print()

    for finding in scan_report[
        "findings"
    ]:
        print(
            f"[{finding['id']}]"
        )
        print(
            f"Title    : "
            f"{finding['title']}"
        )
        print(
            f"Expected : "
            f"{finding['expected']}"
        )
        print(
            f"Actual   : "
            f"{finding['actual']}"
        )
        print(
            f"Severity : "
            f"{finding['severity']}"
        )
        print(
            f"Result   : "
            f"{finding['result']}"
        )

        exception = finding.get(
            "exception"
        )

        if exception:
            print(
                f"Exception Status : "
                f"{exception['status']}"
            )
            print(
                f"Exception ID     : "
                f"{exception['id']}"
            )
            print(
                f"Reason           : "
                f"{exception['reason']}"
            )
            print(
                f"Expires          : "
                f"{exception['expires_at']}"
            )

        print()


def run_agent_for_endpoint(
    endpoint_name: str,
    scan_report: dict,
) -> tuple:
    print(
        f"=== AI Security Agent: "
        f"{endpoint_name} ==="
    )
    print()

    agent_result = run_security_agent(
        scan_report
    )

    analyses = agent_result.get(
        "analyses",
        [],
    )

    proposals = agent_result.get(
        "proposals",
        [],
    )

    tool_trace = agent_result.get(
        "tool_trace",
        [],
    )

    failed_findings = [
        finding
        for finding in scan_report[
            "findings"
        ]
        if finding["result"] == "FAIL"
    ]

    if not failed_findings:
        print(
            "No failed findings require "
            "agent investigation."
        )
        print()

        return (
            agent_result,
            [],
        )

    if tool_trace:
        tool_names = [
            trace["tool"]
            for trace in tool_trace
        ]

        print(
            "Read-only Tools Used : "
            + ", ".join(tool_names)
        )
        print()

    for analysis in analyses:
        print(
            f"[{analysis['finding_id']}]"
        )
        print(
            f"Cause              : "
            f"{analysis['cause']}"
        )
        print(
            f"Risk               : "
            f"{analysis['risk']}"
        )
        print(
            f"Recommendation     : "
            f"{analysis['recommendation']}"
        )
        print(
            f"Operational Impact : "
            f"{analysis['operational_impact']}"
        )
        print()

    print(
        "=== Agent Action Proposals ==="
    )
    print()

    if not proposals:
        print(
            "No remediation action proposed."
        )
        print()

    else:
        for proposal in proposals:
            print(
                f"Finding   : "
                f"{proposal['finding_id']}"
            )
            print(
                f"Action ID : "
                f"{proposal['action_id']}"
            )
            print(
                f"Reason    : "
                f"{proposal['reason']}"
            )
            print()

    validated = (
        validate_agent_proposals(
            scan_report["findings"],
            proposals,
        )
    )

    print(
        "=== Harness Validation ==="
    )
    print()

    if not validated:
        print(
            "No agent remediation proposal "
            "requires validation."
        )
        print()

    else:
        for validation in validated:
            status = (
                "ALLOW"
                if validation["allowed"]
                else "REJECT"
            )

            print(
                f"Finding : "
                f"{validation['finding_id']}"
            )
            print(
                f"Action  : "
                f"{validation['action_id']}"
            )
            print(
                f"Status  : {status}"
            )
            print(
                f"Reason  : "
                f"{validation['reason']}"
            )
            print()

    return (
        agent_result,
        validated,
    )


def remediate_endpoint(
    endpoint_name: str,
    scan_report: dict,
    scan_function,
    validated_proposals: list,
):
    print(
        f"=== Remediation: "
        f"{endpoint_name} ==="
    )
    print()

    remediation_plan = (
        build_remediation_plan(
            scan_report["findings"],
            validated_proposals=
                validated_proposals,
        )
    )

    if not remediation_plan:
        failed_findings = [
            finding
            for finding in scan_report[
                "findings"
            ]
            if finding["result"] == "FAIL"
        ]

        if failed_findings:
            print(
                "Failed findings exist, but "
                "no AI-proposed remediation "
                "passed the harness."
            )
        else:
            print(
                "No remediation required. "
                "All active policies passed "
                "or have approved exceptions."
            )

        print()

        return None

    original_findings = {
        finding["id"]: finding
        for finding in scan_report[
            "findings"
        ]
    }

    executed_actions = []

    for action in remediation_plan:
        finding = original_findings[
            action["finding_id"]
        ]

        print(
            f"Finding     : "
            f"{action['finding_id']}"
        )
        print(
            f"Action ID   : "
            f"{action['action_id']}"
        )
        print(
            f"Description : "
            f"{action['description']}"
        )

        approved = request_approval(
            action
        )

        if not approved:
            print(
                "Remediation rejected."
            )
            print()

            write_audit_event(
                {
                    "hostname":
                        scan_report[
                            "asset"
                        ]["hostname"],
                    "platform":
                        scan_report[
                            "asset"
                        ]["platform"],
                    "finding_id":
                        action[
                            "finding_id"
                        ],
                    "before":
                        finding["actual"],
                    "approved": False,
                    "action_id":
                        action[
                            "action_id"
                        ],
                    "after":
                        finding["actual"],
                    "verification":
                        "NOT_EXECUTED",
                    "policy_set_version":
                        finding[
                            "policy_set_version"
                        ],
                    "source":
                        "AI_AGENT_HARNESS",
                }
            )

            continue

        execute_remediation(
            action
        )

        executed_actions.append(
            {
                "finding_id":
                    action["finding_id"],
                "action_id":
                    action["action_id"],
                "before":
                    finding["actual"],
                "policy_set_version":
                    finding[
                        "policy_set_version"
                    ],
            }
        )

    if not executed_actions:
        print(
            "No remediation was executed."
        )
        print()

        return None

    print()
    print(
        f"=== Verification Scan: "
        f"{endpoint_name} ==="
    )
    print()

    verification_report = (
        scan_function()
    )

    verification_findings = {
        finding["id"]: finding
        for finding in verification_report[
            "findings"
        ]
    }

    for finding in verification_report[
        "findings"
    ]:
        print(
            f"[{finding['id']}]"
        )
        print(
            f"Expected : "
            f"{finding['expected']}"
        )
        print(
            f"Actual   : "
            f"{finding['actual']}"
        )
        print(
            f"Result   : "
            f"{finding['result']}"
        )
        print()

    for action in executed_actions:
        verification = (
            verification_findings.get(
                action["finding_id"]
            )
        )

        if verification is None:
            continue

        write_audit_event(
            {
                "hostname":
                    verification_report[
                        "asset"
                    ]["hostname"],
                "platform":
                    verification_report[
                        "asset"
                    ]["platform"],
                "finding_id":
                    action["finding_id"],
                "before":
                    action["before"],
                "approved": True,
                "action_id":
                    action["action_id"],
                "after":
                    verification["actual"],
                "verification":
                    verification["result"],
                "policy_set_version":
                    action[
                        "policy_set_version"
                    ],
                "source":
                    "AI_AGENT_HARNESS",
            }
        )

    remaining_failures = [
        finding
        for finding in verification_report[
            "findings"
        ]
        if finding["result"] == "FAIL"
    ]

    print(
        f"=== Verification Result: "
        f"{endpoint_name} ==="
    )
    print()

    if not remaining_failures:
        print(
            "All active security policies "
            "passed after remediation."
        )
    else:
        print(
            f"{len(remaining_failures)} "
            f"finding(s) remain unresolved."
        )

    print()

    return verification_report


def parse_args():
    parser = argparse.ArgumentParser(
        description="AI Endpoint Security"
    )

    parser.add_argument(
        "--endpoint",
        choices=[
            "all",
            "linux",
            "windows",
        ],
        default="all",
        help="Select endpoint to scan",
    )

    return parser.parse_args()


def main():
    args = parse_args()

    print(
        "=== AI Endpoint Security ==="
    )
    print()

    endpoints = []

    if args.endpoint in (
        "all",
        "linux",
    ):
        linux_report = (
            scan_linux_endpoint()
        )

        print_endpoint_report(
            "Linux Endpoint",
            linux_report,
        )

        endpoints.append(
            {
                "name":
                    "Linux Endpoint",
                "report":
                    linux_report,
                "scan_function":
                    scan_linux_endpoint,
            }
        )

    if args.endpoint in (
        "all",
        "windows",
    ):
        windows_report = (
            scan_windows_endpoint()
        )

        print_endpoint_report(
            "Windows Endpoint",
            windows_report,
        )

        endpoints.append(
            {
                "name":
                    "Windows Endpoint",
                "report":
                    windows_report,
                "scan_function":
                    scan_windows_endpoint,
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

    agent_reports = []

    for endpoint in endpoints:
        (
            agent_result,
            validated_proposals,
        ) = run_agent_for_endpoint(
            endpoint["name"],
            endpoint["report"],
        )

        endpoint[
            "validated_proposals"
        ] = validated_proposals

        agent_reports.append(
            {
                "asset":
                    endpoint[
                        "report"
                    ]["asset"],
                "policy_set":
                    endpoint[
                        "report"
                    ]["policy_set"],
                "agent":
                    agent_result,
                "harness":
                    validated_proposals,
            }
        )

    save_json(
        "ai_analysis.json",
        {
            "endpoints":
                agent_reports
        },
    )

    verification_reports = []

    for endpoint in endpoints:
        verification = (
            remediate_endpoint(
                endpoint["name"],
                endpoint["report"],
                endpoint[
                    "scan_function"
                ],
                endpoint[
                    "validated_proposals"
                ],
            )
        )

        if verification is not None:
            verification_reports.append(
                verification
            )

    save_json(
        "verification_report.json",
        {
            "endpoints":
                verification_reports
        },
    )


if __name__ == "__main__":
    main()