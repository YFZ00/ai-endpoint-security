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


def get_kernel_version() -> str:
    return run_remote_command("uname -r")


def get_architecture() -> str:
    return run_remote_command("uname -m")


def get_os_release() -> dict:
    raw_data = run_remote_command("cat /etc/os-release")

    os_info = {}

    for line in raw_data.splitlines():
        if "=" not in line:
            continue

        key, value = line.split("=", 1)

        value = value.strip('"')

        os_info[key] = value

    return os_info