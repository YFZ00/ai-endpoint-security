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
        "requested_analysis": [
            "cause",
            "risk",
            "recommendation",
            "operational_impact",
        ],
    }