import subprocess


def run_remote_command(command: str) -> str:
    result = subprocess.run(
        ["ssh", "lab-01", command],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip()


def get_hostname() -> str:
    return run_remote_command("hostname")