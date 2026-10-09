param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("enable-firewall-all-profiles")]
    [string]$Action
)

$ErrorActionPreference = "Stop"


switch ($Action) {

    "enable-firewall-all-profiles" {

        Write-Output "[INFO] Applying remediation: enable Windows Firewall"

        Set-NetFirewallProfile `
            -Profile Domain,Private,Public `
            -Enabled True

        $disabledProfiles = Get-NetFirewallProfile |
            Where-Object { $_.Enabled -eq $false }

        if ($disabledProfiles) {
            Write-Output "[ERROR] Firewall verification failed."
            exit 1
        }

        Write-Output "[SUCCESS] All Windows Firewall profiles enabled."
    }

    default {
        Write-Output "[ERROR] Unsupported remediation action: $Action"
        exit 2
    }
}