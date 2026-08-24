<#
.SYNOPSIS
    Verifies a STANDALONE (Kestrel + Windows Service) FwGpoWeb installation.
    Prints PASS/FAIL per check; exit code = number of failed checks.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServiceIdentity,
    [Parameter(Mandatory = $true)][string]$AppUrl,
    [int]$Port = 443,
    [string]$InstallPath = 'C:\Program Files\FwGpoWeb',
    [string]$DataPath = 'C:\ProgramData\FwGpoWeb'
)

$ErrorActionPreference = 'Stop'
$svcName = 'FwGpoWeb'
$script:Pass = 0; $script:Fail = 0

function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    if ($Ok) { $script:Pass++; Write-Host "PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "FAIL  $Name  $Detail" -ForegroundColor Red }
}

$uri = [Uri]$AppUrl
$rpId = $uri.Host
$isGmsa = $ServiceIdentity -match '\\([^\\]+)\$$'

Write-Host "FwGpoWeb standalone verification (identity: $ServiceIdentity)"
Write-Host ""

# 1. app files
Check "app files present (FwGpoWeb.dll + .exe)" `
    ((Test-Path (Join-Path $InstallPath 'FwGpoWeb.dll')) -and (Test-Path (Join-Path $InstallPath 'FwGpoWeb.exe'))) `
    "looked in $InstallPath"

# 2. PowerShell module
Check "FwGpoBuilder module present" `
    (Test-Path (Join-Path $InstallPath 'powershell\FwGpoBuilder\FwGpoBuilder.psm1'))

# 3. service exists
$svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
Check "Windows service '$svcName' exists" ($null -ne $svc)

# 4. service running
$running = ($null -ne $svc -and $svc.Status -eq 'Running')
Check "service is Running" $running ($(if ($svc) { "state=$($svc.Status)" } else { 'service missing' }))

# 5. service identity
$svcStartName = ''
try { $svcStartName = (Get-CimInstance Win32_Service -Filter "Name='$svcName'").StartName } catch { }
Check "service runs as $ServiceIdentity" ($svcStartName -ceq $ServiceIdentity) "StartName='$svcStartName'"

# 6. gMSA installed (gMSA identities only)
if ($isGmsa) {
    $gmsaName = $Matches[1]
    $t = $null
    try { $t = Test-ADServiceAccount -Identity $gmsaName } catch { }
    Check "gMSA '$gmsaName' installed on this machine" ($null -ne $t -and $t.Installed)
}

# 7. production config
$cfgFile = Join-Path $InstallPath 'appsettings.Production.json'
$cfgOk = $false; $cfgDetail = 'missing'
if (Test-Path $cfgFile) {
    try {
        $cfg = Get-Content $cfgFile -Raw | ConvertFrom-Json
        $cfgOk = ($cfg.App.Hosting -eq 'Kestrel') -and
                 ($cfg.WebAuthn.Origins -contains $AppUrl) -and
                 ($cfg.WebAuthn.RpId -eq $rpId) -and
                 ($cfg.App.KestrelUrl -like "*:$Port")
        if (-not $cfgOk) { $cfgDetail = "Hosting=$($cfg.App.Hosting) Origins=$($cfg.WebAuthn.Origins -join ',') RpId=$($cfg.WebAuthn.RpId) KestrelUrl=$($cfg.App.KestrelUrl)" }
    } catch { $cfgDetail = $_.Exception.Message }
}
Check "appsettings.Production.json (Hosting=Kestrel, exact origin/RpId/port)" $cfgOk $cfgDetail

# 8. certificate PFX + password file present in data dir
$pfx = Join-Path $DataPath 'certs\app.pfx'
$passFile = Join-Path $DataPath 'certs\app.pass'
Check "certificate PFX + password file in data dir" ((Test-Path $pfx) -and (Test-Path $passFile)) "looked for $pfx"

# 9. data dir ACL includes the service identity
$aclOk = $false; $aclDetail = 'acl read failed'
try {
    $acl = Get-Acl $DataPath
    $ident = ($acl.Access | Where-Object { $_.IdentityReference -like "$($ServiceIdentity -replace '\$$','$')*" }).Count
    $aclOk = ($acl.Access | Where-Object { $_.IdentityReference.ToString().TrimEnd('$') -eq $ServiceIdentity.TrimEnd('$') }).Count -gt 0
} catch { $aclDetail = $_.Exception.Message }
Check "data dir ACL grants access to the service identity" $aclOk $aclDetail

# 10. HTTPS health
try {
    $r = Invoke-WebRequest -Uri "https://localhost:$Port/api/health" -SkipCertificateCheck -UseBasicParsing
    Check "HTTPS health endpoint 200" ($r.StatusCode -eq 200) "status=$($r.StatusCode)"
} catch {
    Check "HTTPS health endpoint 200" $false "$($_.Exception.Message)"
}

# 11. DC reachability through the PowerShell bridge (service identity context)
$dcOk = $false; $dcDetail = 'bridge not run'
try {
    $bridgeDir = Join-Path $InstallPath 'powershell\FwGpoBuilder'
    $reqFile = Join-Path $DataPath "verify-ping-$([guid]::NewGuid().ToString('N')).json"
    $respFile = "$reqFile.resp"
    @{ op = 'ping-dc' } | ConvertTo-Json | Set-Content $reqFile -Encoding UTF8
    & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File (Join-Path $bridgeDir 'Invoke-FwGpoOp.ps1') -RequestFile $reqFile -ResponseFile $respFile
    $resp = Get-Content $respFile -Raw | ConvertFrom-Json
    $dcOk = $resp.ok -eq $true
    if (-not $dcOk) { if ($null -ne $resp.error) { $dcDetail = $resp.error } else { $dcDetail = 'unknown' } }
    Remove-Item $reqFile, $respFile -ErrorAction SilentlyContinue
} catch { $dcDetail = $_.Exception.Message }
Check "DC reachable via PowerShell bridge (service identity)" $dcOk $dcDetail

Write-Host ""
Write-Host "RESULT: $script:Pass passed, $script:Fail failed" -ForegroundColor $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })
exit $script:Fail
