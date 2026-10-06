import json

from datetime import datetime
from pathlib import Path


def write_audit_event(
    event: dict,
    file_path: str = "logs/remediation_audit.jsonl",
) -> None:
    path = Path(file_path)

    # logs 폴더가 없으면 자동 생성
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    record = {
        "timestamp": datetime.now()
        .astimezone()
        .isoformat(timespec="seconds"),
        **event,
    }

    with path.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )