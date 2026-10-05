def evaluate_exact(actual: str, expected: str) -> str:
    if actual == expected:
        return "PASS"

    return "FAIL"