#Requires -Version 5.1
<#
stubs.ps1 - Simulates a Windows Server 2025 environment for the deploy scripts,
so they can be exercised end-to-end on any OS (CI / dev machines).

Behavior is controlled by environment variables:
  FwGpoWebStubLogDir      = dir for the call log
  FwGpoWebStubKds         = present|missing   kdsroot availability
  FwGpoWebStubGmsaTest    = installed|notinstalled   Test-ADServiceAccount result
  FwGpoWebStubGmsaExists  = true|false     Get-ADServiceAccount: account present?
  FwGpoWebStubNewAdSaErr  = <msg>          make New-ADServiceAccount throw (SPN conflict sim)
  FwGpoWebStubIisMissing  = true|false     Get-WindowsFeature: IIS present?
  FwGpoWebStubRsatMissing = true|false     Get-WindowsCapability: RSAT present?
  FwGpoWebStubHealth      = ok|fail        Invoke-WebRequest smoke test result
  FwGpoWebStubPoolExists  = true|false     Get-WebAppPool: pool pre-exists (simulates installed state)
  FwGpoWebStubSiteExists  = true|false     Get-Website: site pre-exists (simulates installed state)

State is recorded in $env:FwGpoWebStubLogDir/calls.log: one line per stubbed call,
so the test harness can assert WHAT happened (calls + args).
#>

if (-not $env:FwGpoWebStubLogDir) { $env:FwGpoWebStubLogDir = Join-Path ([System.IO.Path]::GetTempPath()) "fwgpo-stubs-$PID" }
New-Item -ItemType Directory -Force -Path $env:FwGpoWebStubLogDir | Out-Null
function Stub-Log([string]$what, [string]$detail = '') {
    Add-Content -Path (Join-Path $env:FwGpoWebStubLogDir "calls.log") -Value "$what`t$detail"
}

# --- Windows OS / features ----------------------------------------------------
function Get-CimInstance {
    param([string]$ClassName)
    if ($ClassName -eq 'Win32_OperatingSystem') {
        return [pscustomobject]@{ Caption = 'Microsoft Windows Server 2025 Datacenter' }
    }
    if ($ClassName -eq 'Win32_ComputerSystem') {
        return [pscustomobject]@{ DNSHostName = "$($env:COMPUTERNAME).rfkarami.ir" }
    }
    throw "stub Get-CimInstance: unknown class $ClassName"
}
function Get-WindowsFeature {
    param([string]$Name)
    $missing = ($env:FwGpoWebStubIisMissing -eq 'true')
    if ($missing) { return $null }
    Stub-Log "Get-WindowsFeature" $Name
    return [pscustomobject]@{ Name = $Name; Installed = $true }
}
function Install-WindowsFeature {
    param([string[]]$Name, [string]$Source, [switch]$LimitAccess, [switch]$IncludeManagementTools)
    Stub-Log "Install-WindowsFeature" (($Name -join ',') + " source=$Source limitAccess=$LimitAccess")
    return [pscustomobject]@{ Installed = $true }
}
function Get-WindowsCapability {
    param([switch]$Online, [string]$Name)
    $missing = ($env:FwGpoWebStubRsatMissing -eq 'true')
    return [pscustomobject]@{ Name = $Name; State = $(if ($missing) { 'NotPresent' } else { 'Installed' }) }
}
function Add-WindowsCapability {
    param([switch]$Online, [string]$Name, [string]$Source, [switch]$LimitAccess)
    Stub-Log "Add-WindowsCapability" "$Name source=$Source limitAccess=$LimitAccess"
}

# --- modules -------------------------------------------------------------------
function Import-Module {
    param([string[]]$Name, [switch]$DisableNameChecking, [switch]$Force)
    Stub-Log "Import-Module" (($Name -join ','))
}

# --- AD ------------------------------------------------------------------------
function Get-ADDomain {
    return [pscustomobject]@{ DNSRoot = 'rfkarami.ir'; PDCEmulator = 'dc1.rfkarami.ir'; PDC = 'dc1.rfkarami.ir' }
}
function Get-ADServiceAccount {
    param([string]$Identity)
    if ($env:FwGpoWebStubGmsaExists -eq 'true') { return [pscustomobject]@{ Name = $Identity } }
    return $null
}
function New-ADServiceAccount {
    param([string]$Name, [string]$DNSName, [string]$ServicePrincipalName, [string]$Description)
    if ($env:FwGpoWebStubNewAdSaErr) { throw $env:FwGpoWebStubNewAdSaErr }
    Stub-Log "New-ADServiceAccount" "name=$Name dns=$DNSName spn=$ServicePrincipalName"
    $env:FwGpoWebStubGmsaExists = 'true'
}
function Set-ADServiceAccount {
    param([string]$Identity, [string]$ServicePrincipalName)
    Stub-Log "Set-ADServiceAccount" "identity=$Identity spn=$ServicePrincipalName"
}
function Install-ADServiceAccount {
    param([string]$Identity)
    Stub-Log "Install-ADServiceAccount" $Identity
}
function Test-ADServiceAccount {
    param([string]$Identity)
    $installed = ($env:FwGpoWebStubGmsaTest -ne 'notinstalled')
    Stub-Log "Test-ADServiceAccount" "$Identity installed=$installed"
    return [pscustomobject]@{ Identity = $Identity; Installed = $installed }
}
function Get-ADGroup {
    param([string]$Identity, [switch]$ErrorAction)
    Stub-Log "Get-ADGroup" $Identity
    return [pscustomobject]@{ SamAccountName = $Identity; DistinguishedName = "CN=$Identity,CN=Users,DC=rfkarami,DC=ir" }
}
function Add-ADGroupMember {
    param([string]$Identity, [string]$Members)
    Stub-Log "Add-ADGroupMember" "$Identity += $Members"
}
function New-ADGroup {
    param([string]$Name, [string]$GroupScope, [string]$SamAccountName, [string]$Description)
    Stub-Log "New-ADGroup" $Name
}
function Get-ADUser {
    param([string]$Identity)
    Stub-Log "Get-ADUser" $Identity
    return [pscustomobject]@{ SamAccountName = $Identity }
}
function Uninstall-ADServiceAccount {
    param([string]$Identity)
    Stub-Log "Uninstall-ADServiceAccount" $Identity
}
function Remove-ADServiceAccount {
    param([string]$Identity, [switch]$Confirm)
    Stub-Log "Remove-ADServiceAccount" $Identity
}
function Get-Credential {
    param([string]$Message)
    Stub-Log "Get-Credential" $Message
    return $null
}
function Invoke-Command {
    param([string]$ComputerName, $Credential, [scriptblock]$ScriptBlock, [string[]]$ArgumentList)
    Stub-Log "Invoke-Command" "computer=$ComputerName"
    return [pscustomobject]@{ Installed = $true }
}
function kdsroot {
    param([switch]$Get, [string]$KeyType)
    if ($env:FwGpoWebStubKds -eq 'missing') { throw "command not found (simulated)" }
    Stub-Log "kdsroot" "get=$Get keyType=$KeyType"
    Write-Output "Root Key Version: 0x0, Root Key Version TimeStamp: 2026-01-01"
}

# --- Windows services (standalone/Kestrel mode) ---------------------------------
# Env controls:
#   FwGpoWebStubSvcExists    = true|false   service pre-exists (installed state)
#   FwGpoWebStubSvcState     = Running|Stopped|Failed   forced state after start
#   FwGpoWebStubSvcStartName = account shown by Win32_Service StartName
$global:StubServices = @{}
function New-Service {
    param([string]$Name, [string]$BinaryPathName, [string]$DisplayName, $StartupType)
    Stub-Log "New-Service" "$Name binPath=$BinaryPathName start=$StartupType"
    $global:StubServices[$Name] = [pscustomobject]@{ Name = $Name; Status = 'Stopped' }
}
function Get-Service {
    param([string]$Name, [switch]$ErrorAction)
    if ($env:FwGpoWebStubSvcExists -eq 'true' -and $Name -eq 'FwGpoWeb') {
        $global:StubServices[$Name] = [pscustomobject]@{ Name = $Name; Status = 'Running' }
    }
    if ($global:StubServices.ContainsKey($Name)) { return $global:StubServices[$Name] }
    return $null
}
function Start-Service {
    param([string]$Name)
    Stub-Log "Start-Service" $Name
    if ($global:StubServices.ContainsKey($Name)) {
        $global:StubServices[$Name].Status = if ($env:FwGpoWebStubSvcState) { $env:FwGpoWebStubSvcState } else { 'Running' }
    }
}
function Stop-Service {
    param([string]$Name)
    Stub-Log "Stop-Service" $Name
    if ($global:StubServices.ContainsKey($Name)) { $global:StubServices[$Name].Status = 'Stopped' }
}
function sc.exe {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$ScArgs)
    Stub-Log "sc.exe" (($ScArgs -join ' '))
    return 0
}
function Export-PfxCertificate {
    param($Cert, [string]$FilePath, $Password)
    Stub-Log "Export-PfxCertificate" "file=$FilePath"
    'stub-pfx-bytes' | Set-Content -Path $FilePath
    return $null
}
# (re)defines Get-CimInstance to add Win32_Service support (later definition wins)
function Get-CimInstance {
    param([string]$ClassName, [string]$Filter)
    if ($ClassName -eq 'Win32_Service') {
        Stub-Log "Get-CimInstance" "Win32_Service $Filter"
        return [pscustomobject]@{ Name = 'FwGpoWeb'; StartName = $(if ($env:FwGpoWebStubSvcStartName) { $env:FwGpoWebStubSvcStartName } else { 'CORP\FWGPO$' }) }
    }
    if ($ClassName -eq 'Win32_OperatingSystem') {
        return [pscustomobject]@{ Caption = 'Microsoft Windows Server 2025 Datacenter' }
    }
    if ($ClassName -eq 'Win32_ComputerSystem') {
        return [pscustomobject]@{ DNSHostName = "$($env:COMPUTERNAME).rfkarami.ir" }
    }
    throw "stub Get-CimInstance: unknown class $ClassName"
}

# --- IIS -----------------------------------------------------------------------
$global:StubAppPools = @{}
$global:StubWebsites = @{}
function Get-WebAppPool {
    param([string]$Name)
    if ($env:FwGpoWebStubPoolExists -eq 'true' -and $Name -eq 'FwGpoWebPool') { return [pscustomobject]@{ Name = $Name } }
    return $global:StubAppPools[$Name]
}
function New-WebAppPool {
    param([string]$Name)
    Stub-Log "New-WebAppPool" $Name
    $global:StubAppPools[$Name] = [pscustomobject]@{ Name = $Name }
}
function Start-WebAppPool {
    param([string]$Name)
    Stub-Log "Start-WebAppPool" $Name
}
function Stop-WebAppPool {
    param([string]$Name)
    Stub-Log "Stop-WebAppPool" $Name
}
function Remove-WebAppPool {
    param([string]$Name)
    Stub-Log "Remove-WebAppPool" $Name
    $global:StubAppPools.Remove($Name)
}
function Set-ItemProperty {
    param([string]$Path, [string]$Name, $Value)
    Stub-Log "Set-ItemProperty" "$Path / $Name = $Value"
}
function Get-Item {
    param([string]$Path, [string]$Name, [switch]$ErrorAction)
    if ($Path -like 'IIS:*') {
        Stub-Log "Get-Item" $Path
        return [pscustomobject]@{
            processModel = [pscustomobject]@{ username = 'CORP\FWGPO$' }
            managedRuntimeVersion = ''
        }
    }
    # delegate to the real cmdlet for everything else
    return & Microsoft.PowerShell.Management\Get-Item -Path $Path
}
function Get-Website {
    param([string]$Name)
    if ($env:FwGpoWebStubSiteExists -eq 'true' -and $Name -eq 'FwGpoWeb') { return [pscustomobject]@{ Name = $Name } }
    return $global:StubWebsites[$Name]
}
function New-Website {
    param([string]$Name, [int]$Port, [switch]$Secure, [string]$CertificateThumbprint, [string]$AppPool, [string]$PhysicalPath)
    Stub-Log "New-Website" "name=$Name port=$Port secure=$Secure cert=$CertificateThumbprint appPool=$AppPool path=$PhysicalPath"
    $global:StubWebsites[$Name] = [pscustomobject]@{ Name = $Name }
}
function Add-WebBinding {
    param([string]$Name, [string]$Protocol, [int]$Port, [string]$CertificateThumbprint)
    Stub-Log "Add-WebBinding" "$Name ${Protocol}:${Port} cert=$CertificateThumbprint"
}
function Start-Website {
    param([string]$Name)
    Stub-Log "Start-Website" $Name
}
function Stop-WebApp {
    param([string]$Name)
    Stub-Log "Stop-WebApp" $Name
}
function Remove-Website {
    param([string]$Name)
    Stub-Log "Remove-Website" $Name
    $global:StubWebsites.Remove($Name)
}
function Set-WebConfigurationProperty {
    param([string]$Filter, [string]$Name, $Value, [string]$PSPath, [string]$Location)
    Stub-Log "Set-WebConfigurationProperty" "$Filter / $Name = $Value (loc=$Location)"
}
function Get-WebConfigurationProperty {
    param([string]$Filter, [string]$Name, [string]$PSPath, [string]$Location, [switch]$ErrorAction)
    if ($Filter -like '*windowsAuthentication*') { return $true }
    return $null
}
function New-SelfSignedCertificate {
    param([string]$DnsName, [string]$CertStoreLocation, [string]$KeyUsage, [int]$KeyLength)
    Stub-Log "New-SelfSignedCertificate" $DnsName
    return [pscustomobject]@{ Thumbprint = 'STUBTHUMBPRINT0000' }
}

# --- ACL (simulated Windows ACL entry for the service identity) -----------------
function Get-Acl {
    param([string]$Path)
    Stub-Log "Get-Acl" $Path
    $ident = if ($env:FwGpoWebStubAclIdentity) { $env:FwGpoWebStubAclIdentity } else { 'CORP\FWGPO' }
    return [pscustomobject]@{
        Access = @(
            [pscustomobject]@{ IdentityReference = $ident; AccessControlType = 'Allow' }
            [pscustomobject]@{ IdentityReference = 'BUILTIN\Administrators'; AccessControlType = 'Allow' }
        )
    }
}
function Set-Acl {
    param([string]$Path, $AclObject)
    Stub-Log "Set-Acl" $Path
}

# --- dotnet (simulates an already-installed .NET 8 runtime) -------------------
function dotnet {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$DotnetArgs)
    Stub-Log "dotnet" (($DotnetArgs -join ' '))
    if ($DotnetArgs -contains '--list-runtimes') {
        Write-Output "Microsoft.AspNetCore.App 8.0.11"
        Write-Output "Microsoft.NETCore.App 8.0.11"
    }
}

# --- Invoke-WebRequest (simulates the app health endpoint) -------------------
function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile, [switch]$UseBasicParsing, [switch]$SkipCertificateCheck)
    Stub-Log "Invoke-WebRequest" $Uri
    if ($env:FwGpoWebStubHealth -eq 'fail') {
        throw "Connection refused (simulated)"
    }
    if ($OutFile) {
        'fake-runtime-installer' | Set-Content -Path $OutFile
    }
    return [pscustomobject]@{ StatusCode = 200; Content = '{"status":"ok","version":"1.0.0"}' }
}


# --- the PowerShell layer CLI (simulate powershell.exe Invoke-FwGpoOp ping-dc) ---
function powershell.exe {
    param([switch]$NoProfile, [switch]$NonInteractive, [string]$ExecutionPolicy, [string]$File, [string]$RequestFile, [string]$ResponseFile)
    Stub-Log "powershell.exe" $File
    if ($File -and $File -like '*Invoke-FwGpoOp*') {
        '{"ok":true,"data":{"domain":"rfkarami.ir","pdc":"dc1.rfkarami.ir","serviceUser":"CORP\\FWGPO"}}' | Set-Content -Path $ResponseFile -Encoding utf8
    }
    return 0
}
