import subprocess


def run_remote_powershell(command: str) -> str:
    remote_command = f'powershell -NoProfile -Command "{command}"'

    result = subprocess.run(
        ["ssh", "lab-winpc-01", remote_command],
        capture_output=True,
        text=True,
        check=True,
    )

    return result.stdout.strip()


def get_windows_hostname() -> str:
    return run_remote_powershell("$env:COMPUTERNAME")


def get_windows_os_name() -> str:
    return run_remote_powershell(
        "(Get-CimInstance Win32_OperatingSystem).Caption"
    )


def get_windows_version() -> str:
    return run_remote_powershell(
        "(Get-CimInstance Win32_OperatingSystem).Version"
    )


def get_windows_build_number() -> str:
    return run_remote_powershell(
        "(Get-CimInstance Win32_OperatingSystem).BuildNumber"
    )


def get_windows_architecture() -> str:
    return run_remote_powershell(
        "(Get-CimInstance Win32_OperatingSystem).OSArchitecture"
    )