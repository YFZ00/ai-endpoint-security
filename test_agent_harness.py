import json
from datetime import datetime
from pathlib import Path

from engine.remediation import (
    validate_agent_proposals,
    build_remediation_plan,
)


RESULT_FILE = Path(
    "eval_results/harness_safety.json"
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

    assert len(result) == 1
    assert result[0]["allowed"] is True


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

    assert len(result) == 1
    assert result[0]["allowed"] is False


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

    assert len(result) == 1
    assert result[0]["allowed"] is False


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
                "Attempt remediation on EXEMPT.",
        }
    ]

    result = validate_agent_proposals(
        findings,
        proposals,
    )

    assert len(result) == 1
    assert result[0]["allowed"] is False


def test_wrong_action_rejected():
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

    assert len(result) == 1
    assert result[0]["allowed"] is False


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

    assert len(result) == 1
    assert result[0]["allowed"] is False


def test_plan_uses_only_allowed_proposals():
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

    assert len(plan) == 1
    assert (
        plan[0]["finding_id"]
        == "WINDOWS-FIREWALL-001"
    )
    assert (
        plan[0]["action_id"]
        == "enable_windows_firewall"
    )


TESTS = [
    (
        "Allow valid registered remediation",
        test_valid_firewall_proposal,
    ),
    (
        "Reject unregistered action",
        test_fake_action_rejected,
    ),
    (
        "Reject remediation for PASS finding",
        test_pass_finding_rejected,
    ),
    (
        "Reject remediation for EXEMPT finding",
        test_exempt_finding_rejected,
    ),
    (
        "Reject mismatched allowlisted action",
        test_wrong_action_rejected,
    ),
    (
        "Reject unknown finding",
        test_unknown_finding_rejected,
    ),
    (
        "Build plan from ALLOW proposals only",
        test_plan_uses_only_allowed_proposals,
    ),
]


def run_test(
    name: str,
    test_function,
) -> dict:
    try:
        test_function()

        print(
            f"[PASS] {name}"
        )

        return {
            "name": name,
            "result": "PASS",
            "error": None,
        }

    except Exception as error:
        print(
            f"[FAIL] {name}"
        )

        print(
            f"       {error}"
        )

        return {
            "name": name,
            "result": "FAIL",
            "error": str(error),
        }


def save_results(
    results: list,
) -> dict:
    passed = sum(
        1
        for result in results
        if result["result"] == "PASS"
    )

    failed = len(results) - passed

    pass_rate = (
        passed / len(results) * 100
        if results
        else 0
    )

    report = {
        "suite": "agent-harness-safety",
        "generated_at": (
            datetime.now()
            .astimezone()
            .isoformat(
                timespec="seconds"
            )
        ),
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "pass_rate": round(
            pass_rate,
            2,
        ),
        "tests": results,
    }

    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with RESULT_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            report,
            file,
            indent=2,
            ensure_ascii=False,
        )

    return report


def main():
    print(
        "=== Agent Harness Safety Tests ==="
    )
    print()

    results = []

    for name, test_function in TESTS:
        result = run_test(
            name,
            test_function,
        )

        results.append(
            result
        )

    report = save_results(
        results
    )

    print()

    print(
        "=== Evaluation Summary ==="
    )

    print(
        f"Total     : "
        f"{report['total']}"
    )

    print(
        f"Passed    : "
        f"{report['passed']}"
    )

    print(
        f"Failed    : "
        f"{report['failed']}"
    )

    print(
        f"Pass Rate : "
        f"{report['pass_rate']}%"
    )

    print(
        f"Result    : "
        f"{RESULT_FILE}"
    )

    if report["failed"] > 0:
        raise SystemExit(1)

    print()
    print(
        "All harness safety tests passed."
    )


if __name__ == "__main__":
    main()