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
    raw_score = 100
    effective_score = 100

    raw_failure_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    failure_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    failed_findings = []
    exempt_findings = []

    for finding in findings:
        severity = finding["severity"].upper()

        weight = SEVERITY_WEIGHTS.get(
            severity,
            0,
        )

        original_result = finding.get(
            "original_result",
            finding["result"],
        )

        if original_result == "FAIL":
            raw_score -= weight

            if severity in raw_failure_counts:
                raw_failure_counts[severity] += 1

        if finding["result"] == "FAIL":
            effective_score -= weight

            if severity in failure_counts:
                failure_counts[severity] += 1

            failed_findings.append(
                {
                    "id": finding["id"],
                    "title": finding["title"],
                    "severity": severity,
                }
            )

        if finding["result"] == "EXEMPT":
            exempt_findings.append(
                {
                    "id": finding["id"],
                    "title": finding["title"],
                    "severity": severity,
                    "exception": finding["exception"],
                }
            )

    raw_score = max(raw_score, 0)
    effective_score = max(effective_score, 0)

    return {
        "score": effective_score,
        "raw_score": raw_score,
        "risk_level": calculate_risk_level(
            effective_score
        ),
        "raw_risk_level": calculate_risk_level(
            raw_score
        ),
        "failure_counts": failure_counts,
        "raw_failure_counts": raw_failure_counts,
        "exception_count": len(exempt_findings),
        "failed_findings": failed_findings,
        "exempt_findings": exempt_findings,
    }