def create_finding(
    policy: dict,
    actual: str,
    result: str,
) -> dict:
    return {
        "id": policy["id"],
        "title": policy["title"],
        "expected": policy["expected"],
        "actual": actual,
        "severity": policy["severity"],
        "result": result,
    }