from engine.remediation import (
    get_remediation_capabilities,
)


AGENT_TOOLS = [
    {
        "type": "function",
        "name": "get_failed_findings",
        "description": (
            "Return the endpoint security findings that are "
            "currently in FAIL state. This tool is read-only."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "get_posture",
        "description": (
            "Return the endpoint posture score, risk level, "
            "failure counts, and exception information. "
            "This tool is read-only."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "get_remediation_capabilities",
        "description": (
            "Return only the predefined remediation actions "
            "registered by the platform for current FAIL findings. "
            "This tool does not execute remediation."
        ),
        "parameters": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "strict": True,
    },
]


def get_failed_findings(
    scan_report: dict,
) -> list:
    return [
        finding
        for finding in scan_report.get(
            "findings",
            [],
        )
        if finding.get("result") == "FAIL"
    ]


def get_posture(
    scan_report: dict,
) -> dict:
    return {
        "asset": scan_report.get(
            "asset",
            {},
        ),
        "policy_set": scan_report.get(
            "policy_set",
            {},
        ),
        "posture": scan_report.get(
            "posture",
            {},
        ),
    }


def execute_read_only_tool(
    tool_name: str,
    arguments: dict,
    scan_report: dict,
):
    if arguments:
        raise ValueError(
            f"Tool does not accept arguments: "
            f"{tool_name}"
        )

    if tool_name == "get_failed_findings":
        return get_failed_findings(
            scan_report
        )

    if tool_name == "get_posture":
        return get_posture(
            scan_report
        )

    if tool_name == "get_remediation_capabilities":
        return get_remediation_capabilities(
            scan_report.get(
                "findings",
                [],
            )
        )

    raise ValueError(
        f"Unsupported agent tool: {tool_name}"
    )