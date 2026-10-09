import json

from dotenv import load_dotenv
from openai import OpenAI

from ai.tools import (
    AGENT_TOOLS,
    execute_read_only_tool,
)


load_dotenv()

client = OpenAI()


REQUIRED_TOOLS = {
    "get_failed_findings",
    "get_posture",
    "get_remediation_capabilities",
}


AGENT_INSTRUCTIONS = """
You are the AI security agent inside an endpoint security
control platform.

The deterministic policy engine has already made the
PASS, FAIL, and EXEMPT decisions.

You must never override those decisions.

Before producing your final answer, inspect the endpoint
using all of the provided read-only tools:

1. get_failed_findings
2. get_posture
3. get_remediation_capabilities

You may call the tools in parallel.

Security boundaries:

- Never generate or execute shell commands.
- Never generate or execute PowerShell commands.
- Never directly modify an endpoint.
- Never invent a remediation action.
- Only propose action_id values explicitly returned by
  get_remediation_capabilities.
- A proposal is only a recommendation. The application
  harness and a human operator decide whether execution
  is allowed.
- Analyze only findings whose current result is FAIL.
- Respond in Korean.
"""


AGENT_OUTPUT_FORMAT = {
    "type": "json_schema",
    "name": "endpoint_security_agent_result",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "analyses": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string"
                        },
                        "cause": {
                            "type": "string"
                        },
                        "risk": {
                            "type": "string"
                        },
                        "recommendation": {
                            "type": "string"
                        },
                        "operational_impact": {
                            "type": "string"
                        },
                    },
                    "required": [
                        "finding_id",
                        "cause",
                        "risk",
                        "recommendation",
                        "operational_impact",
                    ],
                    "additionalProperties": False,
                },
            },
            "proposals": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "finding_id": {
                            "type": "string"
                        },
                        "action_id": {
                            "type": "string"
                        },
                        "reason": {
                            "type": "string"
                        },
                    },
                    "required": [
                        "finding_id",
                        "action_id",
                        "reason",
                    ],
                    "additionalProperties": False,
                },
            },
        },
        "required": [
            "analyses",
            "proposals",
        ],
        "additionalProperties": False,
    },
}


def build_agent_input(
    scan_report: dict,
) -> dict:
    return {
        "task": (
            "Investigate the current endpoint security "
            "failures and propose only platform-approved "
            "remediation actions when available."
        ),
        "asset": scan_report.get(
            "asset",
            {},
        ),
        "policy_set": scan_report.get(
            "policy_set",
            {},
        ),
        "constraints": [
            (
                "Use read-only tools to inspect "
                "the endpoint report."
            ),
            (
                "Do not change deterministic "
                "security results."
            ),
            (
                "Do not execute endpoint changes."
            ),
            (
                "Only propose remediation actions "
                "returned by the capability tool."
            ),
        ],
    }


def run_security_agent(
    scan_report: dict,
) -> dict:
    failed_findings = [
        finding
        for finding in scan_report.get(
            "findings",
            [],
        )
        if finding.get("result") == "FAIL"
    ]

    if not failed_findings:
        return {
            "analyses": [],
            "proposals": [],
            "tool_trace": [],
        }

    agent_input = build_agent_input(
        scan_report
    )

    input_items = [
        {
            "role": "user",
            "content": json.dumps(
                agent_input,
                ensure_ascii=False,
                indent=2,
            ),
        }
    ]

    called_tools = set()
    tool_trace = []

    for _ in range(6):
        require_tool = not REQUIRED_TOOLS.issubset(
            called_tools
        )

        response = client.responses.create(
            model="gpt-6-luna",
            instructions=AGENT_INSTRUCTIONS,
            input=input_items,
            tools=AGENT_TOOLS,
            tool_choice=(
                "required"
                if require_tool
                else "none"
            ),
            parallel_tool_calls=True,
            text={
                "format": AGENT_OUTPUT_FORMAT
            },
            store=False,
            include=[
                "reasoning.encrypted_content"
            ],
        )

        if response.status != "completed":
            raise RuntimeError(
                "Agent response did not complete: "
                f"{response.status}"
            )

        input_items.extend(
            item.model_dump(
                exclude_none=True
            )
            for item in response.output
        )

        function_calls = [
            item
            for item in response.output
            if item.type == "function_call"
        ]

        if function_calls:
            for call in function_calls:
                arguments = json.loads(
                    call.arguments or "{}"
                )

                if call.name in called_tools:
                    result = {
                        "status": "already_called"
                    }
                else:
                    result = execute_read_only_tool(
                        tool_name=call.name,
                        arguments=arguments,
                        scan_report=scan_report,
                    )

                    called_tools.add(
                        call.name
                    )

                    tool_trace.append(
                        {
                            "tool": call.name,
                            "result": result,
                        }
                    )

                input_items.append(
                    {
                        "type":
                            "function_call_output",
                        "call_id":
                            call.call_id,
                        "output":
                            json.dumps(
                                result,
                                ensure_ascii=False,
                            ),
                    }
                )

            continue

        if not REQUIRED_TOOLS.issubset(
            called_tools
        ):
            raise RuntimeError(
                "Agent finished before all required "
                "read-only tools were used."
            )

        if not response.output_text:
            raise RuntimeError(
                "Agent produced no final output."
            )

        result = json.loads(
            response.output_text
        )

        result["tool_trace"] = tool_trace

        return result

    raise RuntimeError(
        "Agent exceeded the maximum tool-call turns."
    )