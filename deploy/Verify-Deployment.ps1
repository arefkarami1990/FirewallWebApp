<#
.SYNOPSIS
    Post-install verification for FwGpoWeb on Windows Server 2025.
    Checks runtime, IIS, service identity, AD/GPO access and the web API.

.PARAMETER ServiceIdentity
    The app pool identity that was used at install time (e.g. CORP\FWGPO$).

.PARAMETER AppUrl
    Public origin of the site (e.g. https://fwgpo.corp.local).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ServiceIdentity,
    [Parameter(Mandatory = $true)][string]$AppUrl
)

$ErrorActionPreference = 'Continue'
$pass = 0; $fail = 0
function Check($name, [bool]$ok, $detail = '') {
    if ($ok) { $script:pass++; Write-Host "  [PASS] $name" -ForegroundColor Green }
    else     { $script:fail++; Write-Host "  [FAIL] $name  $detail" -ForegroundColor Red }
}

Write-Host "`n== FwGpoWeb deployment verification ==" -ForegroundColor Cyan

# 1. .NET runtime (or self-contained app - no runtime needed)
$rt = if (Get-Command dotnet -ErrorAction SilentlyContinue) { dotnet --list-runtimes 2>$null } else { '' }
$selfContained = Test-Path 'C:\Program Files\FwGpoWeb\FwGpoWeb.dll'
Check ".NET 8 ASP.NET Core Runtime installed (or self-contained app)" (($rt -match 'Microsoft.AspNetCore.App 8\.') -or $selfContained)

# 2. PowerShell AD/GPO modules
$m1 = $false; $m2 = $false
try { Import-Module GroupPolicy -DisableNameChecking -ErrorAction Stop; $m1 = $true } catch {}
try { Import-Module ActiveDirectory -DisableNameChecking -ErrorAction Stop; $m2 = $true } catch {}
Check "GroupPolicy module loads" $m1
Check "ActiveDirectory module loads" $m2

# 3. service identity is valid
$identOk = $false
try {
    $acct = Get-ADUser -Identity ($ServiceIdentity -replace '\$$','') -ErrorAction Stop
    $identOk = $true
} catch {
    try { $acct = Get-ADServiceAccount -Identity ($ServiceIdentity -replace '\$$','') -ErrorAction Stop; $identOk = $true } catch {}
}
Check "Service identity resolves in AD" $identOk "identity=$ServiceIdentity"

# 4. gMSA test (only if identity looks like a gMSA)
if ($ServiceIdentity -match '\$$') {
    $gmsaName = ($ServiceIdentity -split '\\')[-1]
    $t = $null
    try { $t = Test-ADServiceAccount -Identity $gmsaName -ErrorAction Stop } catch {}
    Check "gMSA installed on this machine (Test-ADServiceAccount)" ($t -and $t.Installed)
}

# 5. IIS objects
$pool = Get-WebAppPool -Name FwGpoWebPool -ErrorAction SilentlyContinue
Check "App pool FwGpoWebPool exists" ($null -ne $pool)
if ($pool) {
    $identity = (Get-ItemProperty "IIS:\AppPools\FwGpoWebPool" -Name processModel.username -ErrorAction SilentlyContinue).processModel.username
    Check "App pool identity = $ServiceIdentity" ($identity -eq $ServiceIdentity) "actual=$identity"
    $rtVer = (Get-ItemProperty "IIS:\AppPools\FwGpoWebPool" -Name managedRuntimeVersion -ErrorAction SilentlyContinue).managedRuntimeVersion
    Check "App pool runs .NET Core (empty managedRuntimeVersion)" ([string]::IsNullOrEmpty($rtVer)) "actual='$rtVer'"
}
$site = Get-Website -Name FwGpoWeb -ErrorAction SilentlyContinue
Check "Website FwGpoWeb exists" ($null -ne $site)
$winAuth = (Get-WebConfigurationProperty -Filter "system.webServer/security/authentication/windowsAuthentication" -Name enabled -PSPath 'IIS:\' -Location FwGpoWeb -ErrorAction SilentlyContinue)
Check "IIS Windows Authentication enabled" ($winAuth -eq $true)

# 6. ACLs on data dir
$daclOk = $false
if (Test-Path 'C:\ProgramData\FwGpoWeb') {
    $acl = Get-Acl 'C:\ProgramData\FwGpoWeb'
    $daclOk = $acl.Access | Where-Object { $_.IdentityReference -match [regex]::Escape($ServiceIdentity -split '\\' | Select-Object -Last 1) -and $_.AccessControlType -eq 'Allow' } | ForEach-Object { $true }
}
Check "Data dir ACL includes service identity" $daclOk

# 7. API smoke tests (as the browser would, via SSO)
try {
    $h = Invoke-WebRequest -Uri "https://localhost/api/health" -SkipCertificateCheck -UseBasicParsing
    Check "GET /api/health -> 200" ($h.StatusCode -eq 200) $h.Content
} catch { Check "GET /api/health -> 200" $false $_.Exception.Message }

try {
    $s = Invoke-WebRequest -Uri "https://localhost/api/auth/status" -SkipCertificateCheck -UseBasicParsing -MaximumRedirection 0 -ErrorAction Stop
    Check "GET /api/auth/status -> SSO handshake works (200 with identity)" ($s.StatusCode -eq 200)
} catch [System.Net.WebException] {
    # 401 with a WWW-Authenticate: Negotiate header is the SSO challenge - OK
    $resp = $_.Exception.Response
    $chal = [string]$resp.Headers['WWW-Authenticate']
    Check "GET /api/auth/status -> SSO challenge (401 Negotiate)" ($resp.StatusCode.value__ -eq 401 -and $chal -match 'Negotiate|NTLM') "challenge=$chal"
} catch {
    Check "GET /api/auth/status" $false $_.Exception.Message
}

# 8. direct DC test via the shipped CLI (runs as the CURRENT user, not the
#    service identity - a sanity check that the DC is reachable from this box)
$cli = 'C:\Program Files\FwGpoWeb\powershell\FwGpoBuilder\Invoke-FwGpoOp.ps1'
if (Test-Path $cli) {
    $reqFile = Join-Path $env:TEMP "fwgpo-verify-$([guid]::NewGuid().ToString('N')).json"
    $respFile = "$reqFile.resp"
    '{"op":"ping-dc","params":{}}' | Set-Content $reqFile -Encoding UTF8
    $okCli = $false
    try {
        & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $cli -RequestFile $reqFile -ResponseFile $respFile
        $r = Get-Content $respFile -Raw | ConvertFrom-Json
        $okCli = ($r.ok -eq $true) -and $r.data.domain
        if ($okCli) { Write-Host "         DC: $($r.data.domain)  PDC: $($r.data.pdc)  as $($r.data.serviceUser)" -ForegroundColor DarkGray }
    } catch { }
    finally { Remove-Item $reqFile, $respFile -ErrorAction SilentlyContinue }
    Check "DC reachable via PowerShell bridge (ping-dc)" $okCli
} else {
    Check "Shipped CLI found" $false "not at $cli"
}

Write-Host "`nRESULT: $pass passed, $fail failed" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
exit $(if ($fail -eq 0) { 0 } else { 1 })
