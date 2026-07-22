<#
.SYNOPSIS
    Windows equivalent of provision-hosts-acl.sh: grants a dedicated
    service account write access to the hosts file, without making that
    account an Administrator.

.DESCRIPTION
    There is no Windows equivalent of dnsmasq/systemctl (that path is
    Linux-only already, see DnsDomainBlockingService.getDnsInstructions()
    in the main app), so this script only covers the hosts-file side.
    Uses icacls to grant Modify rights to a specific user on a specific
    file, the same "narrow DAC grant, not a blanket elevation" principle
    as the Linux setfacl approach.

.PARAMETER HostsFilePath
    Defaults to the real Windows hosts file path. Override for testing
    against a throwaway file.

.PARAMETER AgentUser
    The local user or service account the agent runs as. Must already
    exist (create via New-LocalUser or your organization's standard
    service-account provisioning first).

.EXAMPLE
    .\provision-hosts-acl.ps1 -AgentUser "antivirus-agent"

.EXAMPLE
    # For testing against a throwaway file:
    .\provision-hosts-acl.ps1 -HostsFilePath "C:\temp\test-hosts.txt" -AgentUser "antivirus-agent-ci"
#>
param(
    [string]$HostsFilePath = "$env:SystemRoot\System32\drivers\etc\hosts",
    [Parameter(Mandatory = $true)]
    [string]$AgentUser
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $HostsFilePath)) {
    Write-Error "Hosts file not found at $HostsFilePath"
    exit 1
}

# Verify the target account exists before granting anything to it.
$null = Get-LocalUser -Name $AgentUser -ErrorAction Stop

# Modify (not FullControl): read, write, delete the file's own content,
# but not change its permissions or ownership. Narrower than the
# FullControl grant mentioned as a simpler starting point in the plan;
# Modify is sufficient for what HostsFileWriter actually does (read,
# backup-copy, rewrite) and is the tighter of the two.
icacls "$HostsFilePath" /grant "${AgentUser}:(M)"

if ($LASTEXITCODE -ne 0) {
    Write-Error "icacls failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "Granted Modify rights on $HostsFilePath to $AgentUser."
Write-Host "Verify with: Get-Acl `"$HostsFilePath`" | Format-List, or icacls `"$HostsFilePath`""
