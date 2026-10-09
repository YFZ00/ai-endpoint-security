from engine.remediation import (
    validate_agent_proposals,
    build_remediation_plan,
)


def print_result(
    test_name: str,
    passed: bool,
) -> None:
    status = "PASS" if passed else "FAIL"

    print(
        f"[{status}] {test_name}"
    )


def test_valid_firewall_proposal():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "FAIL",
        }
    ]

    proposals = [
        {
            "finding_id":
                "WINDOWS-FIREWALL-001",
            "action_id":
                "enable_windows_firewall",
            "reason":
                "Firewall is disabled.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    passed = (
        len(result) == 1
        and result[0]["allowed"] is True
    )

    print_result(
        "Allow valid registered remediation",
        passed,
    )

    assert passed


def test_fake_action_rejected():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "FAIL",
        }
    ]

    proposals = [
        {
            "finding_id":
                "WINDOWS-FIREWALL-001",
            "action_id":
                "delete_system_files",
            "reason":
                "Malicious proposal.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    passed = (
        len(result) == 1
        and result[0]["allowed"] is False
    )

    print_result(
        "Reject unregistered action",
        passed,
    )

    assert passed


def test_pass_finding_rejected():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "PASS",
        }
    ]

    proposals = [
        {
            "finding_id":
                "WINDOWS-FIREWALL-001",
            "action_id":
                "enable_windows_firewall",
            "reason":
                "Attempt remediation on PASS.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    passed = (
        len(result) == 1
        and result[0]["allowed"] is False
    )

    print_result(
        "Reject remediation for PASS finding",
        passed,
    )

    assert passed


def test_exempt_finding_rejected():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "EXEMPT",
        }
    ]

    proposals = [
        {
            "finding_id":
                "WINDOWS-FIREWALL-001",
            "action_id":
                "enable_windows_firewall",
            "reason":
                "Attempt remediation on exception.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    passed = (
        len(result) == 1
        and result[0]["allowed"] is False
    )

    print_result(
        "Reject remediation for EXEMPT finding",
        passed,
    )

    assert passed


def test_wrong_action_for_finding_rejected():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "FAIL",
        }
    ]

    proposals = [
        {
            "finding_id":
                "WINDOWS-FIREWALL-001",
            "action_id":
                "disable_root_ssh_login",
            "reason":
                "Wrong action for finding.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    passed = (
        len(result) == 1
        and result[0]["allowed"] is False
    )

    print_result(
        "Reject mismatched allowlisted action",
        passed,
    )

    assert passed


def test_unknown_finding_rejected():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "FAIL",
        }
    ]

    proposals = [
        {
            "finding_id":
                "FAKE-POLICY-999",
            "action_id":
                "enable_windows_firewall",
            "reason":
                "Unknown finding.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    passed = (
        len(result) == 1
        and result[0]["allowed"] is False
    )

    print_result(
        "Reject unknown finding",
        passed,
    )

    assert passed


def test_plan_contains_only_validated_action():
    findings = [
        {
            "id": "WINDOWS-FIREWALL-001",
            "result": "FAIL",
        },
        {
            "id": "LINUX-SSH-001",
            "result": "FAIL",
        },
    ]

    validated = [
        {
            "finding_id":
                "WINDOWS-FIREWALL-001",
            "action_id":
                "enable_windows_firewall",
            "allowed":
                True,
        },
        {
            "finding_id":
                "LINUX-SSH-001",
            "action_id":
                "disable_root_ssh_login",
            "allowed":
                False,
        },
    ]

    plan = build_remediation_plan(
        findings,
        validated_proposals=validated,
    )

    passed = (
        len(plan) == 1
        and plan[0]["finding_id"]
        == "WINDOWS-FIREWALL-001"
        and plan[0]["action_id"]
        == "enable_windows_firewall"
    )

    print_result(
        "Build plan from ALLOW proposals only",
        passed,
    )

    assert passed


def main():
    print(
        "=== Agent Harness Safety Tests ==="
    )
    print()

    test_valid_firewall_proposal()
    test_fake_action_rejected()
    test_pass_finding_rejected()
    test_exempt_finding_rejected()
    test_wrong_action_for_finding_rejected()
    test_unknown_finding_rejected()
    test_plan_contains_only_validated_action()

    print()
    print(
        "All harness safety tests passed."
    )


if __name__ == "__main__":
    main()