<#
.SYNOPSIS
    Removes FwGpoWeb from Windows Server 2025 (website, app pool, files,
    data, and optionally the gMSA).

.PARAMETER RemoveGmsa
    Also uninstall + remove the gMSA (pass the gMSA name WITHOUT trailing $).

.PARAMETER RemoveData
    Delete C:\ProgramData\FwGpoWeb (MFA secrets, FIDO2 credentials, audit
    logs). Back it up first if you may need it!
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$RemoveGmsa = "",
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run from an elevated prompt." }

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

Step "Stopping and removing website + app pool"
if (Get-Website -Name FwGpoWeb -ErrorAction SilentlyContinue) {
    Stop-Website -Name FwGpoWeb
    Remove-Website -Name FwGpoWeb
}
if (Get-WebAppPool -Name FwGpoWebPool -ErrorAction SilentlyContinue) {
    Stop-WebAppPool -Name FwGpoWebPool
    Remove-WebAppPool -Name FwGpoWebPool
}

Step "Removing installed files"
if (Test-Path 'C:\Program Files\FwGpoWeb') { Remove-Item 'C:\Program Files\FwGpoWeb' -Recurse -Force }

if ($RemoveData) {
    Step "Removing data directory (MFA secrets, FIDO2 credentials, audit logs)"
    if (Test-Path 'C:\ProgramData\FwGpoWeb') { Remove-Item 'C:\ProgramData\FwGpoWeb' -Recurse -Force }
} else {
    Write-Warning "Keeping C:\ProgramData\FwGpoWeb (use -RemoveData to delete)."
}

if ($RemoveGmsa) {
    Step "Uninstalling + removing gMSA '$RemoveGmsa'"
    try {
        Uninstall-ADServiceAccount -Identity $RemoveGmsa -ErrorAction Stop
        Remove-ADServiceAccount -Identity $RemoveGmsa -Confirm:$false
        Write-Host "    removed." -ForegroundColor Green
    } catch {
        Write-Warning "gMSA removal: $($_.Exception.Message)"
    }
}

Write-Host "`nUninstall complete." -ForegroundColor Green
