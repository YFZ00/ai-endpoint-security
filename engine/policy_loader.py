from pathlib import Path

import yaml


def load_policies(file_path: str) -> list:
    path = Path(file_path)

    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    return data.get("policies", [])