import subprocess


REMEDIATION_ACTIONS = {
    "LINUX-SSH-001": {
        "action_id": "disable_root_ssh_login",
        "description": "Disable direct SSH login for root.",
    },
    "LINUX-SSH-004": {
        "action_id": "limit_ssh_auth_tries",
        "description": "Limit SSH authentication attempts to 4.",
    },
    "LINUX-FILE-001": {
        "action_id": "secure_passwd_file",
        "description": "Restore /etc/passwd ownership and permissions.",
    },
    "WINDOWS-FIREWALL-001": {
        "action_id": "enable_windows_firewall",
        "description": "Enable Windows Firewall for all profiles.",
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
    "limit_ssh_auth_tries": [
        "ssh",
        "lab-01",
        "sudo",
        "-n",
        "/usr/local/sbin/ai-endpoint-remediate",
        "limit-ssh-auth-tries",
    ],
    "secure_passwd_file": [
        "ssh",
        "lab-01",
        "sudo",
        "-n",
        "/usr/local/sbin/ai-endpoint-remediate",
        "secure-passwd-file",
    ],
    "enable_windows_firewall": [
        "ssh",
        "lab-winpc-01",
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        "C:/ProgramData/AIEndpointSecurity/ai-endpoint-remediate.ps1",
        "-Action",
        "enable-firewall-all-profiles",
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


def execute_remediation(action: dict) -> None:
    action_id = action["action_id"]

    command = REMOTE_COMMANDS.get(action_id)

    if command is None:
        raise ValueError(
            f"Unsupported remediation action: {action_id}"
        )

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