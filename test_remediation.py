import json

from engine.remediation import (
    build_remediation_plan,
    request_approval,
    execute_remediation,
)


def main():
    with open(
        "scan_report.json",
        "r",
        encoding="utf-8",
    ) as file:
        scan_report = json.load(file)

    findings = scan_report.get("findings", [])

    plan = build_remediation_plan(findings)

    if not plan:
        print("No remediation required.")
        return

    print("=== Remediation Plan ===")

    for action in plan:
        print()
        print(f"Finding     : {action['finding_id']}")
        print(f"Action ID   : {action['action_id']}")
        print(f"Description : {action['description']}")

    for action in plan:
        approved = request_approval(action)

        if not approved:
            print("Remediation rejected.")
            continue

        execute_remediation(
            action,
            dry_run=False,
        )


if __name__ == "__main__":
    main()