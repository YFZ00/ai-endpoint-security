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


def get_defender_realtime_protection() -> str:
    return run_remote_powershell(
        "(Get-MpComputerStatus).RealTimeProtectionEnabled.ToString().ToLower()"
    )


def get_windows_firewall_all_enabled() -> str:
    return run_remote_powershell(
        "((Get-NetFirewallProfile).Enabled -notcontains $false).ToString().ToLower()"
    )


def get_guest_account_enabled() -> str:
    return run_remote_powershell(
        "(Get-LocalUser | Where-Object { $_.SID.Value -like '*-501' }).Enabled.ToString().ToLower()"
    )


def get_smb1_enabled() -> str:
    return run_remote_powershell(
        "(Get-SmbServerConfiguration).EnableSMB1Protocol.ToString().ToLower()"
    )


def get_smb_signing_required() -> str:
    return run_remote_powershell(
        "(Get-SmbServerConfiguration).RequireSecuritySignature.ToString().ToLower()"
    )


def get_uac_enabled() -> str:
    return run_remote_powershell(
        "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA.ToString()"
    )


def get_defender_behavior_monitor() -> str:
    return run_remote_powershell(
        "(Get-MpComputerStatus).BehaviorMonitorEnabled.ToString().ToLower()"
    )


def get_rdp_denied() -> str:
    return run_remote_powershell(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections.ToString()"
    )


def get_rdp_nla_required() -> str:
    return run_remote_powershell(
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication.ToString()"
    )