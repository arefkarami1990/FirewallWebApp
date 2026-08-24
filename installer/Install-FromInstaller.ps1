<#
.SYNOPSIS
    Orchestration entry point invoked by the FwGpoWeb-Setup EXE (NSIS).
    Runs the full standalone installation from the files staged by the EXE:
      stage 1: (optional) create the gMSA
      stage 2: install the app (Kestrel + Windows Service)
      stage 3: verify the deployment
    Writes setup-result.txt for the installer UI and exits 0/1.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$StageDir,
    [Parameter(Mandatory = $true)][string]$ArgsFile
)

$ErrorActionPreference = 'Stop'
$resultFile = Join-Path $StageDir 'setup-result.txt'
$logFile = Join-Path $StageDir 'install.log'

function Write-Result([string]$Status, [string]$Stage, [string]$Summary) {
    $lines = @(
        "STATUS=$Status",
        "STAGE=$Stage",
        "SUMMARY=$Summary"
    )
    if ($script:Site) { $lines += "SITE=$script:Site" }
    $lines += "LOG=$logFile"
    $lines += "STAGEDIR=$StageDir"
    Set-Content -Path $resultFile -Value $lines -Encoding UTF8
}

function Die([string]$Stage, [string]$Msg) {
    Write-Host "FATAL [$Stage] $Msg" -ForegroundColor Red
    Write-Result 'FAIL' $Stage $Msg
    exit 1
}

# --- load installer arguments (KEY=VALUE lines, written by the NSIS installer) ----
$script:Site = ''
if (-not (Test-Path $ArgsFile)) { Die 'args' "Installer args file not found: $ArgsFile" }
$parsed = @{}
foreach ($line in (Get-Content $ArgsFile)) {
    $i = $line.IndexOf('=')
    if ($i -gt 0) { $parsed[$line.Substring(0, $i).Trim()] = $line.Substring($i + 1) }
}

$serviceIdentity = [string]$parsed['ServiceIdentity']
$appUrl = [string]$parsed['AppUrl']
$port = 443
if ($parsed['Port']) { $port = [int]$parsed['Port'] }
$certPfx = [string]$parsed['CertPfx']
$certPfxPassword = [string]$parsed['CertPfxPassword']
$servicePassword = [string]$parsed['ServicePassword']
$capabilitySource = [string]$parsed['CapabilitySource']
$createGmsa = ($parsed['CreateGmsa'] -eq 'true')
$gmsaName = if ($parsed['GmsaName']) { $parsed['GmsaName'] } else { 'FWGPO' }
$installPath = if ($parsed['InstallPath']) { $parsed['InstallPath'] } else { 'C:\Program Files\FwGpoWeb' }
$dataPath = if ($parsed['DataPath']) { $parsed['DataPath'] } else { 'C:\ProgramData\FwGpoWeb' }
if (-not $serviceIdentity) { Die 'args' 'ServiceIdentity is required (e.g. CORP\FWGPO$)' }
if (-not $appUrl) { Die 'args' 'AppUrl is required (e.g. https://fwgpo.yourdomain.local)' }

$script:Site = $appUrl

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " FwGpoWeb standalone installer" -ForegroundColor Cyan
Write-Host "   ServiceIdentity : $serviceIdentity" -ForegroundColor Cyan
Write-Host "   AppUrl          : $appUrl" -ForegroundColor Cyan
Write-Host "   Port            : $port" -ForegroundColor Cyan
Write-Host "   Create gMSA     : $createGmsa ($gmsaName)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# --- stage 1: gMSA (optional) ------------------------------------------------------
if ($createGmsa) {
    Write-Host "`n[1/3] Creating gMSA '$gmsaName' (SPN from AppUrl host)" -ForegroundColor Yellow
    $spnHost = ([Uri]$appUrl).Host
    try {
        & (Join-Path (Join-Path $StageDir 'deploy') 'New-Gmsa.ps1') -GmsaName $gmsaName -SpnHost $spnHost -GrantDomainAdmin *>&1 | Tee-Object -FilePath (Join-Path $StageDir 'gmsa.log') -Append
        if ($LASTEXITCODE -ne 0) { Die 'gmsa' "New-Gmsa.ps1 exited with code $LASTEXITCODE" }
    } catch {
        Die 'gmsa' $_.Exception.Message
    }
    Write-Host "[1/3] gMSA created." -ForegroundColor Green
} else {
    Write-Host "`n[1/3] gMSA creation skipped (identity: $serviceIdentity)" -ForegroundColor Yellow
}

# --- stage 2: install ----------------------------------------------------------------
Write-Host "`n[2/3] Installing FwGpoWeb (Kestrel + Windows Service)" -ForegroundColor Yellow
try {
    # Hashtable splatting (string-array splatting passes values positionally).
    $installParams = @{
        ServiceIdentity = $serviceIdentity
        AppUrl          = $appUrl
        Port            = $port
        PublishDir      = (Join-Path $StageDir 'app')
        InstallPath     = $installPath
        DataPath        = $dataPath
    }
    if ($certPfx) { $installParams.CertPfx = $certPfx; $installParams.CertPfxPassword = $certPfxPassword }
    if ($capabilitySource) { $installParams.CapabilitySource = $capabilitySource }
    if (-not $serviceIdentity.EndsWith('$')) { $installParams.ServicePassword = $servicePassword }
    & (Join-Path (Join-Path $StageDir 'installer') 'Install-FwGpoWeb-Service.ps1') @installParams
    if ($LASTEXITCODE -ne 0) { Die 'install' "Install-FwGpoWeb-Service.ps1 exited with code $LASTEXITCODE" }
} catch {
    Die 'install' $_.Exception.Message
}
Write-Host "[2/3] Install complete." -ForegroundColor Green

# --- stage 3: verify --------------------------------------------------------------------
Write-Host "`n[3/3] Verifying deployment" -ForegroundColor Yellow
$verifyParams = @{
    ServiceIdentity = $serviceIdentity
    AppUrl          = $appUrl
    Port            = $port
    InstallPath     = $installPath
    DataPath        = $dataPath
}
$verifyExit = 0
try {
    & (Join-Path (Join-Path $StageDir 'installer') 'Verify-FwGpoWeb-Service.ps1') @verifyParams
    $verifyExit = $LASTEXITCODE
} catch {
    $verifyExit = 1
    Write-Host "Verify crashed: $($_.Exception.Message)" -ForegroundColor Red
}

if ($verifyExit -ne 0) {
    Write-Result 'FAIL' 'verify' "Deployment finished but $verifyExit verification check(s) failed - see $logFile"
    exit 1
}

Write-Result 'OK' 'done' "FwGpoWeb installed and verified at $appUrl"
exit 0
