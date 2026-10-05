import subprocess


REMEDIATION_ACTIONS = {
    "LINUX-SSH-001": {
        "action_id": "disable_root_ssh_login",
        "description": "Disable direct SSH login for root.",
    },
    "LINUX-SSH-002": {
        "action_id": "disable_ssh_password_auth",
        "description": "Disable SSH password authentication.",
    },
}


REMOTE_COMMANDS = {
    "disable_root_ssh_login": [
        "ssh",
        "lab-01",
        "sudo",
        "-n",
        "/usr/local/sbin/ai-endpoint-remediate",
        "disable-root-ssh-login",
    ],
}


def build_remediation_plan(findings: list) -> list:
    plan = []

    for finding in findings:
        if finding.get("result") != "FAIL":
            continue

        policy_id = finding.get("id")
        action = REMEDIATION_ACTIONS.get(policy_id)

        if action is None:
            continue

        plan.append(
            {
                "finding_id": policy_id,
                "action_id": action["action_id"],
                "description": action["description"],
            }
        )

    return plan


def request_approval(action: dict) -> bool:
    print()
    print("=== Remediation Approval ===")
    print(f"Finding     : {action['finding_id']}")
    print(f"Action ID   : {action['action_id']}")
    print(f"Description : {action['description']}")
    print()

    answer = input("Approve remediation? [y/N]: ")

    return answer.strip().lower() == "y"


def execute_remediation(action: dict, dry_run: bool = True) -> None:
    action_id = action["action_id"]

    command = REMOTE_COMMANDS.get(action_id)

    if command is None:
        raise ValueError(
            f"Unsupported remediation action: {action_id}"
        )

    if dry_run:
        print()
        print("[DRY-RUN]")
        print(f"Approved action: {action_id}")
        print("No system changes were made.")
        return

    print()
    print("[EXECUTE]")
    print(f"Running approved action: {action_id}")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    if result.stdout:
        print(result.stdout.strip())

    print("[SUCCESS] Remediation completed.")