def evaluate_exact(actual, expected) -> str:
    if actual == expected:
        return "PASS"

    return "FAIL"


def evaluate_less_than_or_equal(actual, expected) -> str:
    actual_number = int(actual)
    expected_number = int(expected)

    if actual_number <= expected_number:
        return "PASS"

    return "FAIL"


def evaluate(actual, expected, comparator: str) -> str:
    if comparator == "exact":
        return evaluate_exact(
            actual,
            expected,
        )

    if comparator == "less_than_or_equal":
        return evaluate_less_than_or_equal(
            actual,
            expected,
        )

    raise ValueError(
        f"Unsupported comparator: {comparator}"
    )