import subprocess


REMEDIATION_ACTIONS = {
    "LINUX-SSH-001": {
        "action_id": "disable_root_ssh_login",
        "description": (
            "Disable direct SSH login for root."
        ),
    },
    "LINUX-SSH-004": {
        "action_id": "limit_ssh_auth_tries",
        "description": (
            "Limit SSH authentication attempts to 4."
        ),
    },
    "LINUX-FILE-001": {
        "action_id": "secure_passwd_file",
        "description": (
            "Restore /etc/passwd ownership "
            "and permissions."
        ),
    },
    "WINDOWS-FIREWALL-001": {
        "action_id": "enable_windows_firewall",
        "description": (
            "Enable Windows Firewall "
            "for all profiles."
        ),
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
        (
            "C:/ProgramData/AIEndpointSecurity/"
            "ai-endpoint-remediate.ps1"
        ),
        "-Action",
        "enable-firewall-all-profiles",
    ],
}


def get_remediation_capabilities(
    findings: list,
) -> list:
    capabilities = []

    for finding in findings:
        if finding.get("result") != "FAIL":
            continue

        finding_id = finding.get("id")

        action = REMEDIATION_ACTIONS.get(
            finding_id
        )

        if action is None:
            continue

        capabilities.append(
            {
                "finding_id": finding_id,
                "action_id":
                    action["action_id"],
                "description":
                    action["description"],
            }
        )

    return capabilities


def validate_agent_proposals(
    findings: list,
    proposals: list,
) -> list:
    current_failures = {
        finding["id"]: finding
        for finding in findings
        if finding.get("result") == "FAIL"
    }

    validated = []
    seen = set()

    for proposal in proposals:
        finding_id = proposal.get(
            "finding_id",
            "",
        )

        action_id = proposal.get(
            "action_id",
            "",
        )

        key = (
            finding_id,
            action_id,
        )

        if key in seen:
            continue

        seen.add(key)

        finding = current_failures.get(
            finding_id
        )

        registered_action = (
            REMEDIATION_ACTIONS.get(
                finding_id
            )
        )

        if finding is None:
            validated.append(
                {
                    "finding_id": finding_id,
                    "action_id": action_id,
                    "allowed": False,
                    "reason": (
                        "Finding is not currently "
                        "in FAIL state."
                    ),
                }
            )

            continue

        if registered_action is None:
            validated.append(
                {
                    "finding_id": finding_id,
                    "action_id": action_id,
                    "allowed": False,
                    "reason": (
                        "No automated remediation "
                        "is registered for this finding."
                    ),
                }
            )

            continue

        expected_action_id = (
            registered_action[
                "action_id"
            ]
        )

        if action_id != expected_action_id:
            validated.append(
                {
                    "finding_id": finding_id,
                    "action_id": action_id,
                    "allowed": False,
                    "reason": (
                        "Proposed action does not "
                        "match the platform allowlist."
                    ),
                }
            )

            continue

        validated.append(
            {
                "finding_id": finding_id,
                "action_id": action_id,
                "description":
                    registered_action[
                        "description"
                    ],
                "allowed": True,
                "reason": (
                    "Finding is FAIL and the "
                    "proposed action exactly matches "
                    "the platform allowlist."
                ),
            }
        )

    return validated


def build_remediation_plan(
    findings: list,
    validated_proposals=None,
) -> list:
    plan = []

    allowed_pairs = None

    if validated_proposals is not None:
        allowed_pairs = {
            (
                proposal["finding_id"],
                proposal["action_id"],
            )
            for proposal
            in validated_proposals
            if proposal.get("allowed") is True
        }

    for finding in findings:
        if finding.get("result") != "FAIL":
            continue

        policy_id = finding.get("id")

        action = REMEDIATION_ACTIONS.get(
            policy_id
        )

        if action is None:
            continue

        pair = (
            policy_id,
            action["action_id"],
        )

        if (
            allowed_pairs is not None
            and pair not in allowed_pairs
        ):
            continue

        plan.append(
            {
                "finding_id": policy_id,
                "action_id":
                    action["action_id"],
                "description":
                    action["description"],
            }
        )

    return plan


def request_approval(
    action: dict,
) -> bool:
    print()
    print("=== Remediation Approval ===")

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

    print()

    answer = input(
        "Approve remediation? [y/N]: "
    )

    return (
        answer.strip().lower() == "y"
    )


def execute_remediation(
    action: dict,
) -> None:
    action_id = action["action_id"]

    command = REMOTE_COMMANDS.get(
        action_id
    )

    if command is None:
        raise ValueError(
            "Unsupported remediation action: "
            f"{action_id}"
        )

    print()
    print("[EXECUTE]")

    print(
        f"Running approved action: "
        f"{action_id}"
    )

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=True,
    )

    if result.stdout:
        print(
            result.stdout.strip()
        )

    print(
        "[SUCCESS] Remediation completed."
    )