<#
.SYNOPSIS
    Installs FwGpoWeb in STANDALONE mode: self-contained .NET app + Kestrel
    self-hosted + Windows Service. NO IIS, NO ASP.NET Core Module, NO .NET
    runtime download — the publish in -PublishDir carries its own runtime.

.DESCRIPTION
    Steps performed:
      1. RSAT Group Policy Management + AD PowerShell (from -CapabilitySource
         ISO root when offline; skipped when already installed)
      2. Copy the published app + FwGpoBuilder module to $InstallPath
      3. Provision the HTTPS certificate as a PFX inside the ACL-restricted
         data dir (from -CertPfx, or -CertThumbprint, or a generated
         self-signed cert) — the PFX password is stored in the data dir,
         never in the world-readable settings file
      4. Write appsettings.Production.json (Hosting=Kestrel, exact WebAuthn
         origin, PFX paths)
      5. Data dir ACLs (service identity + Administrators)
      6. Register Windows service 'FwGpoWeb' running under $ServiceIdentity
         (gMSA$ or domain user) and start it
      7. Smoke test GET /api/health over HTTPS

    Windows SSO works because the app uses the ASP.NET Core Negotiate
    handler (Kerberos/NTLM) directly under Kestrel — no IIS involved.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServiceIdentity,
    [Parameter(Mandatory = $true)][string]$AppUrl,
    [int]$Port = 443,
    [string]$CertPfx = "",
    [string]$CertPfxPassword = "",
    [string]$CertThumbprint = "",
    [string]$ServicePassword = "",
    [string]$CapabilitySource = "",
    [Parameter(Mandatory = $true)][string]$PublishDir,
    [string]$InstallPath = 'C:\Program Files\FwGpoWeb',
    [string]$DataPath = 'C:\ProgramData\FwGpoWeb'
)

$ErrorActionPreference = 'Stop'
$svcName = 'FwGpoWeb'

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# --- 0. preconditions ---------------------------------------------------------
$os = (Get-CimInstance Win32_OperatingSystem).Caption
Write-Host "Target OS: $os"
if ($os -notmatch 'Windows Server 20(22|25)') {
    Write-Warning "This script targets Windows Server 2022/2025; continuing anyway."
}
$isAdmin = $false
try { $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) } catch { }
if (-not $isAdmin -and -not $env:FwGpoWebTestMode) { throw "Run this script from an elevated (Administrator) prompt." }

$uri = [Uri]$AppUrl
if ($uri.Scheme -ne 'https') {
    throw "AppUrl must be HTTPS (Windows SSO + FIDO2/WebAuthn require a secure context): use e.g. https://fwgpo.yourdomain.local"
}
$rpId = $uri.Host

# --- 1. RSAT: Group Policy + AD modules (needed by the PowerShell layer) ------
Step "Checking RSAT (Group Policy Management + AD PowerShell)"
$cap = @('Rsat.GroupPolicy.Management~~~~0.0.1.0', 'Rsat.AdPowerShell~~~~0.0.1.0')
$capMissing = @($cap | Where-Object {
    $state = Get-WindowsCapability -Online -Name $_ -ErrorAction SilentlyContinue
    -not ($state -and $state.State -eq 'Installed')
})
if ($capMissing) {
    if (-not $CapabilitySource) {
        throw "RSAT capabilities missing ($($capMissing -join ', ')) and no -CapabilitySource given (offline server).`nMount the Windows Server 2022/2025 ISO and re-run with -CapabilitySource D:\ (drive letter root of the mounted ISO)."
    }
    foreach ($c in $capMissing) {
        Add-WindowsCapability -Online -Name $c -Source $CapabilitySource -LimitAccess | Out-Null
        Write-Host "    installed $c from $CapabilitySource" -ForegroundColor Green
    }
} else {
    Write-Host "    RSAT capabilities already present." -ForegroundColor Green
}
Import-Module GroupPolicy, ActiveDirectory -DisableNameChecking -ErrorAction Stop
Write-Host "    GroupPolicy + ActiveDirectory modules load OK." -ForegroundColor Green

# --- 2. publish (copy the pre-published self-contained app) --------------------
Step "Publishing the application to $InstallPath"
if (-not (Test-Path (Join-Path $PublishDir 'FwGpoWeb.dll'))) { throw "PublishDir does not contain FwGpoWeb.dll (run `dotnet publish` first)." }
if (-not (Test-Path (Join-Path $PublishDir 'FwGpoWeb.exe'))) { throw "PublishDir does not contain FwGpoWeb.exe — the standalone installer needs a SELF-CONTAINED win-x64 publish: dotnet publish -c Release -r win-x64 --self-contained true" }
$repoRoot = Split-Path -Parent $PSScriptRoot
New-Item -ItemType Directory -Path $installPath -Force | Out-Null
Copy-Item (Join-Path $PublishDir '*') $installPath -Recurse -Force
$psDst = Join-Path $installPath 'powershell\FwGpoBuilder'
if (-not (Test-Path $psDst)) {
    New-Item -ItemType Directory -Path $psDst -Force | Out-Null
    Copy-Item (Join-Path $repoRoot 'powershell\FwGpoBuilder\*') $psDst -Recurse -Force
}
Write-Host "    app + PowerShell module in place." -ForegroundColor Green

# --- 3. data directory + ACLs ---------------------------------------------------
Step "Preparing $DataPath and ACLs for the service identity"
New-Item -ItemType Directory -Path $DataPath -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $DataPath 'certs') -Force | Out-Null
try {
    $acl = Get-Acl $DataPath
    $acl.SetAccessRule((New-Object System.AccessControl.FileSystemAccessRule($ServiceIdentity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    $acl.SetAccessRule((New-Object System.AccessControl.FileSystemAccessRule('BUILTIN\Administrators', 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    Set-Acl $DataPath $acl
} catch {
    Write-Warning "Could not apply ACLs on $DataPath automatically: $($_.Exception.Message)`nApply manually: icacls `"$dataPath`" /grant `"${ServiceIdentity}:(OI)(CI)F`" /grant `"`BUILTIN\Administrators:(OI)(CI)F`""
}

# --- 4. certificate -> PFX inside the data dir ---------------------------------
Step "Provisioning the HTTPS certificate (PFX in $DataPath\certs)"
$pfxDst = Join-Path $DataPath 'certs\app.pfx'
$passFile = Join-Path $DataPath 'certs\app.pass'
if ($CertPfx) {
    if (-not (Test-Path $CertPfx)) { throw "CertPfx not found: $CertPfx" }
    Copy-Item $CertPfx $pfxDst -Force
    if (-not $CertPfxPassword) { throw "A -CertPfxPassword is required when -CertPfx is given." }
    Set-Content -Path $passFile -Value $CertPfxPassword -Encoding UTF8
    Write-Host "    using provided certificate: $CertPfx" -ForegroundColor Green
}
elseif ($CertThumbprint) {
    Write-Host "    exporting store certificate $CertThumbprint to PFX"
    $genPwd = [guid]::NewGuid().ToString('N')
    try {
        Export-PfxCertificate -Cert "Cert:\LocalMachine\My\$CertThumbprint" -FilePath $pfxDst -Password (ConvertTo-SecureString $genPwd -AsPlainText -Force) -ErrorAction Stop
        Set-Content -Path $passFile -Value $genPwd -Encoding UTF8
    } catch {
        throw "Could not export the certificate (private key not exportable?): $($_.Exception.Message)`nRe-run with -CertPfx <path> -CertPfxPassword <pwd> instead."
    }
}
else {
    Write-Warning "No -CertPfx/-CertThumbprint given: creating a SELF-SIGNED certificate (dev only! Browsers will warn; for production use a CA-issued certificate with SAN = $rpId)."
    $genPwd = [guid]::NewGuid().ToString('N')
    $cert = New-SelfSignedCertificate -DnsName $rpId -CertStoreLocation Cert:\LocalMachine\My -KeyUsage DigitalSignature -KeyLength 2048
    try {
        Export-PfxCertificate -Cert $cert -FilePath $pfxDst -Password (ConvertTo-SecureString $genPwd -AsPlainText -Force) -ErrorAction Stop
        Set-Content -Path $passFile -Value $genPwd -Encoding UTF8
    } catch {
        throw "Could not export the self-signed certificate to PFX: $($_.Exception.Message)"
    }
}
Write-Host "    PFX ready: $pfxDst (password kept in $passFile, ACL-restricted)" -ForegroundColor Green

# --- 5. production configuration ------------------------------------------------
Step "Writing appsettings.Production.json"
$prod = [ordered]@{
    App = [ordered]@{
        AuthMode           = 'Windows'
        Hosting            = 'Kestrel'
        KestrelUrl         = "https://0.0.0.0:$Port"
        KestrelCert        = [ordered]@{
            Path          = $pfxDst
            PasswordFile  = $passFile
        }
        SessionIdleMinutes = 30
        SessionAbsoluteHours = 8
        AdminGroups        = @('Domain Admins')
        DataDir            = $DataPath
    }
    Ad = [ordered]@{ Mock = $false; Domain = $env:USERDNSDOMAIN; DcEndpoint = ''; UseLdapSsl = $false; TimeoutSeconds = 10 }
    WebAuthn = [ordered]@{ RpId = $rpId; RpName = 'FW-GPO Builder'; Origins = @($AppUrl) }
    Pwsh = [ordered]@{ Exe = 'powershell.exe'; ModuleDir = $psDst; TimeoutSeconds = 300 }
    Security = [ordered]@{ MfaMaxAttempts = 5; MfaLockoutMinutes = 15; RateLimitPerMinute = 300 }
}
$prod | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $installPath 'appsettings.Production.json') -Encoding UTF8
Write-Host "    RpId=$rpId Origin=$AppUrl Port=$Port Hosting=Kestrel" -ForegroundColor Green

# --- 6. gMSA presence check ------------------------------------------------------
$isGmsa = $ServiceIdentity -match '\\([^\\]+)\$$'
if ($isGmsa) {
    Step "Checking gMSA is installed on this machine"
    $gmsaName = $Matches[1]
    $test = Test-ADServiceAccount -Identity $gmsaName
    if (-not $test.Installed) {
        throw "gMSA '$gmsaName' is not installed on this machine. Run Install-ADServiceAccount -Identity $gmsaName (e.g. from the DC after replication: repadmin /syncall /APD) and re-run."
    }
    Write-Host "    gMSA '$gmsaName' is installed and can obtain a password." -ForegroundColor Green
}

# --- 7. Windows service -----------------------------------------------------------
Step "Registering Windows service '$svcName' (identity: $ServiceIdentity)"
$exePath = Join-Path $installPath 'FwGpoWeb.exe'
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "    service exists — updating binary path + identity"
    & sc.exe config $svcName "binPath=`"$exePath`""
} else {
    New-Service -Name $svcName -BinaryPathName $exePath -DisplayName 'FwGpoWeb - Firewall GPO Console' -StartupType Automatic | Out-Null
    Write-Host "    service created"
}
if ($isGmsa) {
    # gMSA: no password (the domain manages it); sc requires the password= token.
    & sc.exe config $svcName "obj=$ServiceIdentity" "password="
} else {
    if (-not $ServicePassword) { throw "A -ServicePassword is required for a domain user identity (or use a gMSA: DOMAIN\NAME$)." }
    & sc.exe config $svcName "obj=$ServiceIdentity" "password=$ServicePassword"
}
Write-Host "    service account set to $ServiceIdentity" -ForegroundColor Green

# --- 8. start + smoke test -----------------------------------------------------------
Step "Starting service '$svcName'"
Start-Service -Name $svcName
Start-Sleep -Seconds 5
$svcState = (Get-Service -Name $svcName).Status
if ($svcState -ne 'Running') {
    throw "Service '$svcName' did not reach Running (state: $svcState). Check the Application event log and the service account permissions."
}
Write-Host "    service is Running." -ForegroundColor Green

Step "Smoke test: GET /api/health"
try {
    $r = Invoke-WebRequest -Uri "https://localhost:$Port/api/health" -SkipCertificateCheck -UseBasicParsing
    Write-Host "    $($r.StatusCode): $($r.Content)" -ForegroundColor Green
} catch {
    Write-Warning "Health check failed: $($_.Exception.Message) - check the service logs and the certificate binding."
    throw "Smoke test failed — see message above."
}

Write-Host @"

DONE.
  Site:          https://$rpId$(if ($Port -ne 443) { ":$Port" } else { '' })
  Service:       $svcName  (identity: $ServiceIdentity)
  App:           $installPath
  Data:          $dataPath

Next steps:
  1. Open the site from a domain-joined browser (intranet zone) - Windows SSO
     should authenticate automatically; then complete MFA (TOTP or FIDO2).
  2. Run: .\Verify-FwGpoWeb-Service.ps1 -ServiceIdentity $ServiceIdentity -AppUrl "$AppUrl"
  3. Back up $dataPath (contains MFA secrets, FIDO2 credentials, cert, audit logs).
"@ -ForegroundColor Green

exit 0
