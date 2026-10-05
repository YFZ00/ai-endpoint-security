import json

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

client = OpenAI()


def build_ai_input(scan_report: dict) -> dict:
    failed_findings = []

    for finding in scan_report.get("findings", []):
        if finding.get("result") == "FAIL":
            failed_findings.append(finding)

    return {
        "task": "Analyze failed endpoint security findings.",
        "constraints": [
            "Do not change the PASS or FAIL decision.",
            "Do not execute remediation automatically.",
            "Explain the security risk based on the provided finding.",
            "Recommend a remediation action.",
            "Describe possible operational impact before remediation.",
        ],
        "asset": scan_report.get("asset", {}),
        "findings": failed_findings,
    }


def analyze_findings(ai_input: dict) -> dict:
    if not ai_input.get("findings"):
        return {
            "analyses": []
        }

    response = client.responses.create(
        model="gpt-6-luna",

        instructions=(
            "You are a security analysis component inside an endpoint "
            "security control platform. "
            "The deterministic policy engine has already made the PASS/FAIL "
            "decision. Never override that decision. "
            "Analyze only the supplied failed findings. "
            "Respond in Korean. "
            "Provide concise, technically grounded analysis."
        ),

        input=json.dumps(
            ai_input,
            ensure_ascii=False,
            indent=2,
        ),

        text={
            "format": {
                "type": "json_schema",
                "name": "security_analysis",
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
                                    }
                                },
                                "required": [
                                    "finding_id",
                                    "cause",
                                    "risk",
                                    "recommendation",
                                    "operational_impact"
                                ],
                                "additionalProperties": False
                            }
                        }
                    },
                    "required": [
                        "analyses"
                    ],
                    "additionalProperties": False
                }
            }
        },

        store=False,
    )

    return json.loads(response.output_text)