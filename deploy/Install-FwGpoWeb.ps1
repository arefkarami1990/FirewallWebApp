<#
.SYNOPSIS
    Installs FwGpoWeb (Firewall GPO web console) on Windows Server 2025:
    .NET 8 ASP.NET Runtime, IIS + Windows Authentication, RSAT GPO/AD modules,
    the published app, and an app pool running under the service identity
    (gMSA or domain user).

.PARAMETER ServiceIdentity
    Account the IIS app pool runs as: "DOMAIN\GMSA$" (gMSA - trailing $) or
    "DOMAIN\username" (domain admin user).

.PARAMETER AppUrl
    Public origin of the site, WITHOUT scheme+port if using 443, e.g.
    "https://fwgpo.corp.local" (WebAuthn origin) - must be exact.

.PARAMETER Port
    HTTPS port (default 443).

.PARAMETER CertThumbprint
    Thumbprint of the HTTPS certificate in the local Personal store.
    If omitted, a self-signed cert is created (dev only - browsers will warn;
    for production use a PKI/CA-issued cert with SAN = SpnHost).

.PARAMETER PublishDir
    Directory containing the published app (default: <repo>\backend\FwGpoWeb
    - the script runs `dotnet publish` into C:\Program Files\FwGpoWeb).

.EXAMPLE
    .\Install-FwGpoWeb.ps1 -ServiceIdentity "CORP\FWGPO$" -AppUrl "https://fwgpo.corp.local" -CertThumbprint AB12...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServiceIdentity,
    [Parameter(Mandatory = $true)][string]$AppUrl,
    [int]$Port = 443,
    [string]$CertThumbprint = "",
    [string]$PublishDir = ""
)

$ErrorActionPreference = 'Stop'
$installPath = 'C:\Program Files\FwGpoWeb'
$dataPath = 'C:\ProgramData\FwGpoWeb'
$siteName = 'FwGpoWeb'
$appPool = 'FwGpoWebPool'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# --- 0. preconditions --------------------------------------------------------
if (-not (Get-ExecutionPolicy -Scope LocalMachine)) { }
$os = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "Target OS: $os"
if ($os -notmatch 'Windows Server 20(22|25)') {
    Write-Warning "This script targets Windows Server 2022/2025; continuing anyway."
}
# admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw "Run this script from an elevated (Administrator) prompt." }

# --- 1. .NET 8 ASP.NET Core Runtime ------------------------------------------
Step "Checking .NET 8 ASP.NET Core Runtime"
$needDotnet = $true
if (Get-Command dotnet -ErrorAction SilentlyContinue) {
    $runtimes = dotnet --list-runtimes 2>$null
    if ($runtimes -match 'Microsoft.AspNetCore.App 8\.') { $needDotnet = $false }
}
if ($needDotnet) {
    $url = 'https://download.visualstudio.microsoft.com/download/pr/00c65e5d-2f71-4695-9cfa-3b9f8ecb0ea9/59e9536f69b3f4a2389a15b3386885e1/aspnetcore-runtime-8.0.11-win-x64.exe'
    $msi = Join-Path $env:TEMP 'aspnetcore-runtime-8.0.11-win-x64.exe'
    Write-Host "    downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
    & $msi /quiet /norestart
    if ($LASTEXITCODE -ne 0) { throw ".NET 8 ASP.NET Runtime installer failed (exit $LASTEXITCODE). Install it manually from https://dotnet.microsoft.com/download and re-run." }
    Write-Host "    installed." -ForegroundColor Green
}

# --- 2. IIS + Windows Authentication -----------------------------------------
Step "Installing IIS with Windows Authentication"
$features = @(
    'Web-Server','Web-Common-Http','Web-Static-Content','Web-Default-Doc',
    'Web-Dir-Browsing','Web-Http-Errors','Web-Log-Libraries','Web-Request-Filters',
    'Web-Stat-Logging','Web-Mgmt-Console','Web-Mgmt-Service','Web-Http-Compression',
    'IIS-WindowsAuth','IIS-ASPNET5'
)
$missing = $features | Where-Object { -not (Get-WindowsFeature -Name $_ -ErrorAction SilentlyContinue) }
if ($missing) {
    Install-WindowsFeature -Name $missing -IncludeManagementTools -ErrorAction Stop | Out-Null
    Write-Host "    installed: $($missing -join ', ')" -ForegroundColor Green
} else {
    Write-Host "    IIS features already present." -ForegroundColor Green
}

# --- 3. RSAT: Group Policy + AD modules (needed by the PowerShell layer) -----
Step "Installing RSAT Group Policy Management + AD PowerShell"
$cap = @('Rsat.GroupPolicy.Management~~~~0.0.1.0','Rsat.AdPowerShell~~~~0.0.1.0')
foreach ($c in $cap) {
    $state = Get-WindowsCapability -Online -Name $c -ErrorAction SilentlyContinue
    if ($state -and $state.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $c | Out-Null
        Write-Host "    installed $c" -ForegroundColor Green
    }
}
Import-Module GroupPolicy, ActiveDirectory -DisableNameChecking -ErrorAction Stop
Write-Host "    GroupPolicy + ActiveDirectory modules load OK." -ForegroundColor Green

# --- 4. publish ----------------------------------------------------------------
Step "Publishing the application to $installPath"
$repoRoot = Split-Path -Parent $PSScriptRoot
if ($PublishDir) {
    if (-not (Test-Path (Join-Path $PublishDir 'FwGpoWeb.dll'))) { throw "PublishDir does not contain FwGpoWeb.dll (run `dotnet publish` first)." }
    $source = $PublishDir
} else {
    $proj = Join-Path $repoRoot 'backend\FwGpoWeb\FwGpoWeb.csproj'
    if (-not (Test-Path $proj)) { throw "Project not found at $proj - run this script from the repository's deploy folder." }
    & dotnet publish $proj -c Release -o $installPath --self-contained false
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }
    $source = $installPath
}
# make sure the PowerShell module ships next to the app
$psDst = Join-Path $installPath 'powershell\FwGpoBuilder'
if (-not (Test-Path $psDst)) {
    New-Item -ItemType Directory -Path $psDst -Force | Out-Null
    Copy-Item (Join-Path $repoRoot 'powershell\FwGpoBuilder\*') $psDst -Recurse -Force
}

# --- 5. production configuration ----------------------------------------------
Step "Writing appsettings.Production.json"
$uri = [Uri]$AppUrl
$rpId = $uri.Host
$prod = [ordered]@{
    App = [ordered]@{
        AuthMode          = 'Windows'
        Hosting           = 'Iis'
        SessionIdleMinutes = 30
        SessionAbsoluteHours = 8
        AdminGroups       = @('Domain Admins')
        DataDir           = $dataPath
    }
    Ad  = [ordered]@{ Mock = $false; Domain = $env:USERDNSDOMAIN; DcEndpoint = ''; UseLdapSsl = $false; TimeoutSeconds = 10 }
    WebAuthn = [ordered]@{ RpId = $rpId; RpName = 'FW-GPO Builder'; Origins = @($AppUrl) }
    Pwsh = [ordered]@{ Exe = 'powershell.exe'; ModuleDir = $psDst; TimeoutSeconds = 300 }
    Security = [ordered]@{ MfaMaxAttempts = 5; MfaLockoutMinutes = 15; RateLimitPerMinute = 300 }
}
$prod | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $installPath 'appsettings.Production.json') -Encoding UTF8
Write-Host "    RpId=$rpId Origin=$AppUrl" -ForegroundColor Green

# --- 6. data directory + ACLs ---------------------------------------------------
Step "Preparing $dataPath and ACLs for the service identity"
New-Item -ItemType Directory -Path $dataPath -Force | Out-Null
$acl = Get-Acl $dataPath
$rule = New-Object System.AccessControl.FileSystemAccessRule($ServiceIdentity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$rule2 = New-Object System.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
$acl.SetAccessRule($rule); $acl.SetAccessRule($rule2)
Set-Acl $dataPath $acl

# --- 7. IIS app pool (service identity: gMSA$ or domain user) -------------------
Step "Creating app pool '$appPool' with identity $ServiceIdentity"
if (Get-WebAppPool -Name $appPool -ErrorAction SilentlyContinue) {
    Set-ItemProperty "IIS:\AppPools\$appPool" -Name processModel.username -Value $ServiceIdentity
    Set-ItemProperty "IIS:\AppPools\$appPool" -Name managedRuntimeVersion -Value ""
} else {
    New-WebAppPool -Name $appPool | Out-Null
    Set-ItemProperty "IIS:\AppPools\$appPool" -Name processModel.username -Value $ServiceIdentity
    Set-ItemProperty "IIS:\AppPools\$appPool" -Name managedRuntimeVersion -Value ""
    # .NET 8 (ANCM)
    Set-WebConfigurationProperty -Filter "system.applicationHost/applicationPools/[@name='$appPool']/processModel" -Name identityType -Value specificUser
    Set-WebConfigurationProperty -Filter "system.applicationHost/applicationPools/[@name='$appPool']" -Name managedRuntimeVersion -Value ""
}
Start-WebAppPool -Name $appPool

# --- 8. website + HTTPS binding ---------------------------------------------------
Step "Creating website '$siteName' on port $Port (HTTPS)"
if (-not $CertThumbprint) {
    Write-Host "    no -CertThumbprint given: creating a SELF-SIGNED cert (dev only!)" -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate -DnsName $rpId -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature -KeyLength 2048
    $CertThumbprint = $cert.Thumbprint
}
if (Get-Website -Name $siteName -ErrorAction SilentlyContinue) {
    Stop-WebApp -Name $siteName
    Remove-WebSite -Name $siteName
}
New-Website -Name $siteName -Port $Port -AppPool $appPool -PhysicalPath $installPath | Out-Null
Add-WebBinding -Name $siteName -Protocol https -Port $Port -CertificateThumbprint $CertThumbprint
Start-Website -Name $siteName

# --- 9. Windows Authentication (Kerberos/NTLM) for SSO ---------------------------
Step "Enabling IIS Windows Authentication"
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name enabled -Value $true -PSPath 'IIS:\' -Location $siteName
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled -Value $false -PSPath 'IIS:\' -Location $siteName

# --- 10. smoke test ---------------------------------------------------------------
Step "Smoke test: GET /api/health"
try {
    $r = Invoke-WebRequest -Uri "https://localhost:api/health" -SkipCertificateCheck -UseBasicParsing
    Write-Host "    $($r.StatusCode): $($r.Content)" -ForegroundColor Green
} catch {
    Write-Warning "Health check failed: $($_.Exception.Message) - check IIS logs (log files) and the app pool identity."
}

Write-Host @"

DONE.
  Site:        https://$rpId$(if ($Port -ne 443) { ":$Port" } else { '' })
  App pool:    $appPool  (identity: $ServiceIdentity)
  Data:        $dataPath
  PowerShell:  $psDst

Next steps:
  1. On the DC, verify the identity:  Test-ADServiceAccount -Identity (gMSA)
  2. Open the site from a domain-joined browser (intranet zone) - Windows SSO
     should authenticate automatically; then complete MFA (TOTP or FIDO2).
  3. Run: .\Verify-Deployment.ps1 -ServiceIdentity $ServiceIdentity
  4. Back up $dataPath (contains MFA secrets, FIDO2 credentials, audit logs).
"@ -ForegroundColor Green
