#Requires -Version 5.1
<#
Run-DeployScriptTests.ps1
End-to-end tests for the deploy scripts, running them against a simulated
Windows Server 2025 (stubbed Windows cmdlets, see stubs.ps1). Works on any OS.

Exit code 0 = all scenarios passed.
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot          # .../tests
$deployDir = Join-Path (Split-Path -Parent $root) 'deploy'   # .../deploy
$stubPath = Join-Path $PSScriptRoot 'stubs.ps1'
$pwshPath = (Get-Process -Id $PID).Path
$tempRoot = [System.IO.Path]::GetTempPath()

$script:Pass = 0; $script:Fail = 0
function Assert([bool]$Cond, [string]$Name, [string]$Detail = '') {
    if ($Cond) { $script:Pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "  FAIL  $Name  $Detail" -ForegroundColor Red }
}
function Call-Matched([string[]]$Calls, [string]$Pattern) {
    return @($Calls | Where-Object { $_ -match $Pattern }).Count -gt 0
}

$script:RunId = 0
function Invoke-DeployChild {
    param([string]$Script, [string]$ArgString = '', [hashtable]$Env = @{})
    $script:RunId++
    $dir = Join-Path $tempRoot "fwgpo-deploytest-$PID-$($script:RunId)"
    New-Item -ItemType Directory -Force $dir | Out-Null
    $envLines = ($Env.GetEnumerator() | ForEach-Object { "Set-Item Env:\$($_.Key) '$($_.Value)'" }) -join "`n"
    $isPS7 = ($PSVersionTable.PSVersion.Major -ge 7)
    $boolStr = if ($isPS7) { '$true' } else { '$false' }
    $childFile = Join-Path $dir 'child.ps1'
    $child = @"
$envLines
Set-Item Env:FwGpoWebTestMode '1'
Set-Item Env:TEMP '$dir'
Set-Item Env:USERDNSDOMAIN 'rfkarami.ir'
Set-Item Env:FwGpoWebStubLogDir '$dir'
. '$stubPath'
if ($boolStr) { Start-Transcript -Path '$dir/transcript.txt' -Append | Out-Null } else { Start-Transcript -FilePath '$dir/transcript.txt' -Append | Out-Null }
`$out = & '$Script' $ArgString *>&1
`$out | Out-File -FilePath '$dir/child.out' -Encoding utf8
Stop-Transcript | Out-Null
`$bad = 0
if (`$null -ne `$LASTEXITCODE -and `$LASTEXITCODE -ne 0) { `$bad = 1 }
else { if (@(`$out | Where-Object { `$_ -is [System.Management.Automation.ErrorRecord] }).Count -gt 0) { `$bad = 1 } }
exit `$bad
"@
    Set-Content -Path $childFile -Value $child -Encoding utf8
    $proc = Start-Process -FilePath $pwshPath -ArgumentList @('-NoProfile','-File',$childFile) -NoNewWindow -Wait -PassThru
    $transcript = if (Test-Path (Join-Path $dir 'transcript.txt')) { (Get-Content (Join-Path $dir 'transcript.txt') -Raw) } else { '' }
    $childOut = if (Test-Path (Join-Path $dir 'child.out')) { (Get-Content (Join-Path $dir 'child.out') -Raw) } else { '' }
    $outText = (($transcript + "`n" + $childOut) -as [string])
    if (-not $outText) { $outText = '' }
    $calls = if (Test-Path (Join-Path $dir 'calls.log')) { @(Get-Content (Join-Path $dir 'calls.log')) } else { @() }
    [pscustomobject]@{ Dir = $dir; ExitCode = $proc.ExitCode; Out = $outText; Calls = $calls }
}

# ============================================================================
Write-Host "`n== New-Gmsa.ps1 ==" -ForegroundColor Cyan

# S1: happy path (local computer, KDS present, grant Domain Admins)
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    "-GmsaName FWGPO -DnsDomain rfkarami.ir -SpnHost fwgpo.rfkarami.ir -GrantDomainAdmin" `
    @{ COMPUTERNAME='web01'; FwGpoWebStubKds='present' }
Assert ($r.ExitCode -eq 0) "S1 gMSA happy path exits 0" "exit=$($r.ExitCode) $($r.Out.Substring(0,[Math]::Min(300,$r.Out.Length)))"
Assert ($r.Out -match 'KDS root key present') "S1 KDS present detected"
Assert (Call-Matched $r.Calls '^New-ADServiceAccount.*spn=HTTP/fwgpo.rfkarami.ir') "S1 account created with HTTP SPN" "calls=$($r.Calls -join ' | ')"
Assert (Call-Matched $r.Calls '^Install-ADServiceAccount') "S1 gMSA installed on local computer"
Assert (Call-Matched $r.Calls '^Add-ADGroupMember.*Domain Admins') "S1 granted to Domain Admins"

# S2: KDS missing -> warning, still succeeds
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    "-GmsaName FWGPO -DnsDomain rfkarami.ir -SpnHost fwgpo.rfkarami.ir -GrantDomainAdmin" `
    @{ COMPUTERNAME='web01'; FwGpoWebStubKds='missing' }
Assert ($r.ExitCode -eq 0) "S2 KDS missing is non-fatal" "exit=$($r.ExitCode)"
Assert ($r.Out -match 'Could not verify KDS root key') "S2 KDS warning shown"

# S3: Test-ADServiceAccount reports not installed -> hard error with replication hint
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    "-GmsaName FWGPO -DnsDomain rfkarami.ir -SpnHost fwgpo.rfkarami.ir" `
    @{ COMPUTERNAME='web01'; FwGpoWebStubKds='present'; FwGpoWebStubGmsaTest='notinstalled' }
Assert ($r.ExitCode -ne 0) "S3 not-installed gMSA -> failure" "exit=$($r.ExitCode)"
Assert ($r.Out -match 'repl') "S3 replication hint shown"

# S4: invalid name
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    '-GmsaName "MY GMSA" -DnsDomain rfkarami.ir -SpnHost fwgpo.rfkarami.ir' `
    @{ COMPUTERNAME='web01' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'start with a letter') "S4 invalid gMSA name rejected" "out=$($r.Out)"

# S4b: no DNS domain resolvable -> clear error
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    "-GmsaName FWGPO -DnsDomain '' -SpnHost fwgpo.rfkarami.ir" `
    @{ COMPUTERNAME='web01' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'Cannot determine DNS domain') "S4b missing domain -> clear error" "out=$($r.Out)"

# S5: SPN conflict -> actionable error
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    "-GmsaName FWGPO -DnsDomain rfkarami.ir -SpnHost fwgpo.rfkarami.ir" `
    @{ COMPUTERNAME='web01'; FwGpoWebStubNewAdSaErr='The service principal name is already in use' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'SPN conflict') "S5 SPN conflict -> actionable error" "out=$($r.Out)"

# S6: existing account -> SPN update path
$r = Invoke-DeployChild (Join-Path $deployDir 'New-Gmsa.ps1') `
    "-GmsaName FWGPO -DnsDomain rfkarami.ir -SpnHost fwgpo.rfkarami.ir" `
    @{ COMPUTERNAME='web01'; FwGpoWebStubGmsaExists='true' }
Assert ($r.ExitCode -eq 0) "S6 existing account re-run ok" "exit=$($r.ExitCode)"
Assert ($r.Out -match 'already exists') "S6 update-SPN path taken"

# ============================================================================
Write-Host "`n== Install-FwGpoWeb.ps1 ==" -ForegroundColor Cyan

$tmpBase = Join-Path $tempRoot "fwgpo-deploytest-work-$PID"
New-Item -ItemType Directory -Force $tmpBase | Out-Null
$pubDir = Join-Path $tmpBase 'publish'
New-Item -ItemType Directory -Force $pubDir | Out-Null
'fake-dll' | Set-Content (Join-Path $pubDir 'FwGpoWeb.dll')
'fake'     | Set-Content (Join-Path $pubDir 'web.config')
'{}'       | Set-Content (Join-Path $pubDir 'appsettings.json')
$installDir = Join-Path $tmpBase 'install'
$dataDir = Join-Path $tmpBase 'data'

$installArgs = "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -CertThumbprint ABC123 -PublishDir '$pubDir' -InstallPath '$installDir' -DataPath '$dataDir'"

# I1: full offline install
$r = Invoke-DeployChild (Join-Path $deployDir 'Install-FwGpoWeb.ps1') $installArgs `
    @{ FwGpoWebStubIisMissing='false'; FwGpoWebStubRsatMissing='false' }
Assert ($r.ExitCode -eq 0) "I1 offline install exits 0" "exit=$($r.ExitCode) $($r.Out.Substring(0,[Math]::Min(400,$r.Out.Length)))"
Assert (Test-Path (Join-Path $installDir 'FwGpoWeb.dll')) "I1 publish copied into install path"
Assert (Test-Path (Join-Path $installDir 'powershell' 'FwGpoBuilder' 'FwGpoBuilder.psm1')) "I1 PowerShell module shipped"
$prod = Join-Path $installDir 'appsettings.Production.json'
Assert (Test-Path $prod) "I1 appsettings.Production.json written"
if (Test-Path $prod) {
    $cfg = Get-Content $prod -Raw | ConvertFrom-Json
    Assert ($cfg.App.AuthMode -eq 'Windows') "I1 config AuthMode=Windows"
    Assert ($cfg.App.Hosting -eq 'Iis') "I1 config Hosting=Iis"
    Assert ($cfg.WebAuthn.RpId -eq 'fwgpo.rfkarami.ir') "I1 config RpId from AppUrl host" "got=$($cfg.WebAuthn.RpId)"
    Assert (($cfg.WebAuthn.Origins -join ',') -eq 'https://fwgpo.rfkarami.ir') "I1 config Origin exact" "got=$($cfg.WebAuthn.Origins -join ',')"
    $expectedModuleDir = (Join-Path (Join-Path $installDir 'powershell') 'FwGpoBuilder')
    Assert (($cfg.Pwsh.ModuleDir -replace '/', '\') -eq ($expectedModuleDir -replace '/', '\')) "I1 config ModuleDir" "got=$($cfg.Pwsh.ModuleDir) want=$expectedModuleDir"
    Assert ($cfg.Ad.Mock -eq $false) "I1 config Ad.Mock=false"
    Assert ($cfg.Security.MfaMaxAttempts -eq 5) "I1 config lockout defaults"
}
Assert (Call-Matched $r.Calls '^New-Website.*secure=True') "I1 site created with HTTPS binding (-Secure)"
Assert (-not (Call-Matched $r.Calls '^Add-WebBinding')) "I1 no stray http binding (Add-WebBinding not used)"
Assert (Call-Matched $r.Calls 'processModel.username = CORP.*FWGPO') "I1 app pool identity = service identity"
Assert (Call-Matched $r.Calls 'windowsAuthentication.*= True') "I1 IIS Windows Auth enabled"
Assert (Call-Matched $r.Calls 'anonymousAuthentication.*= False') "I1 anonymous auth disabled"
Assert (Call-Matched $r.Calls '^Invoke-WebRequest.*https://localhost:443/api/health') "I1 smoke test URL correct" "calls=$($r.Calls -join ' | ')"

# I2: PublishDir without the DLL
$badPub = Join-Path $tmpBase 'badpub'; New-Item -ItemType Directory -Force $badPub | Out-Null
$r = Invoke-DeployChild (Join-Path $deployDir 'Install-FwGpoWeb.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -CertThumbprint ABC123 -PublishDir '$badPub' -InstallPath '$installDir' -DataPath '$dataDir'" `
    @{ FwGpoWebStubIisMissing='false'; FwGpoWebStubRsatMissing='false' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'FwGpoWeb.dll') "I2 empty PublishDir -> clear error" "out=$($r.Out)"

# I3: IIS missing + no FeatureSource -> ISO hint
$r = Invoke-DeployChild (Join-Path $deployDir 'Install-FwGpoWeb.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -CertThumbprint ABC123 -PublishDir '$pubDir' -InstallPath '$installDir' -DataPath '$dataDir'" `
    @{ FwGpoWebStubIisMissing='true'; FwGpoWebStubRsatMissing='false' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'FeatureSource' -and $r.Out -match 'ISO') "I3 missing IIS + no source -> ISO hint" "out=$($r.Out)"

# I3b: IIS missing + FeatureSource given -> installed from source
$r = Invoke-DeployChild (Join-Path $deployDir 'Install-FwGpoWeb.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -CertThumbprint ABC123 -PublishDir '$pubDir' -InstallPath '$installDir' -DataPath '$dataDir' -FeatureSource 'E:\sources\sxs' -CapabilitySource 'E:\'" `
    @{ FwGpoWebStubIisMissing='true'; FwGpoWebStubRsatMissing='true' }
Assert ($r.ExitCode -eq 0) "I3b offline IIS+RSAT from ISO exits 0" "exit=$($r.ExitCode) $($r.Out.Substring(0,[Math]::Min(300,$r.Out.Length)))"
Assert (Call-Matched $r.Calls '^Install-WindowsFeature.*source=E:.sources.sxs') "I3b features installed from ISO source"
Assert (Call-Matched $r.Calls '^Add-WindowsCapability.*source=E:.') "I3b RSAT from ISO source"

# I4: SelfContained + IIS warning
$r = Invoke-DeployChild (Join-Path $deployDir 'Install-FwGpoWeb.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -CertThumbprint ABC123 -PublishDir '$pubDir' -InstallPath '$installDir' -DataPath '$dataDir' -SelfContained" `
    @{ FwGpoWebStubIisMissing='false'; FwGpoWebStubRsatMissing='false' }
Assert ($r.ExitCode -eq 0 -and $r.Out -match 'AspNetCoreModuleV2') "I4 self-contained IIS warning shown" "out=$($r.Out.Substring(0,[Math]::Min(300,$r.Out.Length)))"

# ============================================================================
Write-Host "`n== Verify-Deployment.ps1 ==" -ForegroundColor Cyan

# V1: simulated good install -> all checks PASS (exit 0)
$r = Invoke-DeployChild (Join-Path $deployDir 'Verify-Deployment.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -Port 443 -InstallPath '$installDir' -DataPath '$dataDir'" `
    @{ FwGpoWebStubHealth='ok'; FwGpoWebStubPoolExists='true'; FwGpoWebStubSiteExists='true' }
$passCount = ([regex]::Matches($r.Out, '\[PASS\]')).Count
$failCount = ([regex]::Matches($r.Out, '\[FAIL\]')).Count
Assert ($r.ExitCode -eq 0) "V1 verify all green on good install" "exit=$($r.ExitCode) PASS=$passCount FAIL=$failCount`n$($r.Out)"
Assert ($passCount -ge 12 -and $failCount -eq 0) "V1 >=12 checks, zero failures" "PASS=$passCount FAIL=$failCount"
Assert ($r.Out -match '\[PASS\] gMSA installed') "V1 gMSA check ran (trailing-$ identity handled)"

# ============================================================================
Write-Host "`n== Uninstall-FwGpoWeb.ps1 ==" -ForegroundColor Cyan

# U1: uninstall with -RemoveData + gMSA removal (uses the dirs from the install test)
$r = Invoke-DeployChild (Join-Path $deployDir 'Uninstall-FwGpoWeb.ps1') `
    "-RemoveGmsa FWGPO -RemoveData -InstallPath '$installDir' -DataPath '$dataDir'" `
    @{ FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -eq 0) "U1 uninstall exits 0" "exit=$($r.ExitCode) out=$($r.Out)"
Assert (-not (Test-Path $installDir)) "U1 install dir removed"
Assert (-not (Test-Path $dataDir)) "U1 data dir removed (-RemoveData)"
Assert ((Call-Matched $r.Calls '^Uninstall-ADServiceAccount') -and (Call-Matched $r.Calls '^Remove-ADServiceAccount')) "U1 gMSA uninstalled + removed"
Assert ($r.Out -match 'Uninstall complete') "U1 completion message"

# U2: uninstall WITHOUT -RemoveData keeps the data dir
New-Item -ItemType Directory -Force $dataDir | Out-Null
$r = Invoke-DeployChild (Join-Path $deployDir 'Uninstall-FwGpoWeb.ps1') `
    "-InstallPath '$installDir' -DataPath '$dataDir'" @{}
Assert ($r.ExitCode -eq 0 -and (Test-Path $dataDir) -and ($r.Out -match 'Keeping')) "U2 data dir kept without -RemoveData"

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })
exit $(if ($script:Fail -eq 0) { 0 } else { 1 })
