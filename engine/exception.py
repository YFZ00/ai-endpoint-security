from datetime import date, datetime
from pathlib import Path

import yaml


def load_exceptions(
    file_path: str = "exceptions.yaml",
) -> list:
    path = Path(file_path)

    if not path.exists():
        return []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file) or {}

    return data.get("exceptions", [])


def parse_date(value) -> date:
    if isinstance(value, date):
        return value

    return datetime.strptime(
        str(value),
        "%Y-%m-%d",
    ).date()


def hostname_matches(
    configured_hostname: str,
    actual_hostname: str,
) -> bool:
    if configured_hostname == "*":
        return True

    return (
        configured_hostname.strip().lower()
        == actual_hostname.strip().lower()
    )


def apply_exceptions(
    scan_report: dict,
    file_path: str = "exceptions.yaml",
) -> dict:
    exceptions = load_exceptions(file_path)

    hostname = scan_report["asset"]["hostname"]
    today = date.today()

    for finding in scan_report["findings"]:
        if finding["result"] != "FAIL":
            continue

        matching_exceptions = []

        for exception in exceptions:
            if exception.get("finding_id") != finding["id"]:
                continue

            exception_hostname = exception.get(
                "hostname",
                "*",
            )

            if not hostname_matches(
                exception_hostname,
                hostname,
            ):
                continue

            matching_exceptions.append(exception)

        if not matching_exceptions:
            continue

        active_exception = None
        expired_exception = None

        for exception in matching_exceptions:
            expires_at = parse_date(
                exception["expires_at"]
            )

            if today <= expires_at:
                active_exception = exception
                break

            expired_exception = exception

        if active_exception is not None:
            finding["original_result"] = "FAIL"
            finding["result"] = "EXEMPT"

            finding["exception"] = {
                "id": active_exception["id"],
                "status": "ACTIVE",
                "reason": active_exception["reason"],
                "approved_by": active_exception[
                    "approved_by"
                ],
                "approved_at": str(
                    active_exception["approved_at"]
                ),
                "expires_at": str(
                    active_exception["expires_at"]
                ),
            }

            continue

        if expired_exception is not None:
            finding["exception"] = {
                "id": expired_exception["id"],
                "status": "EXPIRED",
                "reason": expired_exception["reason"],
                "approved_by": expired_exception[
                    "approved_by"
                ],
                "approved_at": str(
                    expired_exception["approved_at"]
                ),
                "expires_at": str(
                    expired_exception["expires_at"]
                ),
            }

    return scan_report