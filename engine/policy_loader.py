from pathlib import Path

import yaml


REQUIRED_POLICY_SET_FIELDS = (
    "name",
    "version",
    "updated_at",
)


def load_policy_set(file_path: str) -> dict:
    path = Path(file_path)

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file) or {}

    metadata = data.get("policy_set", {})
    policies = data.get("policies", [])

    missing_fields = [
        field
        for field in REQUIRED_POLICY_SET_FIELDS
        if field not in metadata
    ]

    if missing_fields:
        raise ValueError(
            "Missing policy_set metadata: "
            + ", ".join(missing_fields)
        )

    if not isinstance(policies, list):
        raise ValueError(
            "'policies' must be a list."
        )

    return {
        "metadata": metadata,
        "policies": policies,
    }


def load_policies(file_path: str) -> list:
    return load_policy_set(
        file_path
    )["policies"]