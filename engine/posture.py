SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 6,
    "LOW": 3,
}


def calculate_risk_level(score: int) -> str:
    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MEDIUM"

    if score >= 50:
        return "HIGH"

    return "CRITICAL"


def calculate_posture(findings: list) -> dict:
    score = 100

    failure_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    failed_findings = []

    for finding in findings:
        if finding["result"] != "FAIL":
            continue

        severity = finding["severity"].upper()

        weight = SEVERITY_WEIGHTS.get(
            severity,
            0,
        )

        score -= weight

        if severity in failure_counts:
            failure_counts[severity] += 1

        failed_findings.append(
            {
                "id": finding["id"],
                "title": finding["title"],
                "severity": severity,
            }
        )

    score = max(score, 0)

    return {
        "score": score,
        "risk_level": calculate_risk_level(score),
        "failure_counts": failure_counts,
        "failed_findings": failed_findings,
    }