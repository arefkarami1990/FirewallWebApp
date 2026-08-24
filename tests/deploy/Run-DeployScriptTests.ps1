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
# ============================================================================
Write-Host "`n== Installer (EXE orchestration: Install-FromInstaller.ps1) ==" -ForegroundColor Cyan

$installerDir = Join-Path (Split-Path -Parent $root) 'installer'
$stageBase = Join-Path $tempRoot "fwgpo-installer-$PID"
New-Item -ItemType Directory -Force $stageBase | Out-Null

function New-InstallerStage {
    param([string]$Tag, [hashtable]$PubFiles = @{})
    $stage = Join-Path $stageBase $Tag
    if (Test-Path $stage) { Remove-Item $stage -Recurse -Force }
    $app = Join-Path $stage 'app'
    New-Item -ItemType Directory -Force $app | Out-Null
    foreach ($kv in $PubFiles.GetEnumerator()) { Set-Content (Join-Path $app $kv.Key) $kv.Value }
    Copy-Item (Join-Path $deployDir 'New-Gmsa.ps1') (Join-Path $stage 'deploy.tmp') -Force
    New-Item -ItemType Directory -Force (Join-Path $stage 'deploy') | Out-Null
    Move-Item (Join-Path $stage 'deploy.tmp') (Join-Path $stage 'deploy\New-Gmsa.ps1') -Force
    New-Item -ItemType Directory -Force (Join-Path $stage 'installer') | Out-Null
    Copy-Item (Join-Path $installerDir 'Install-FwGpoWeb-Service.ps1') (Join-Path $stage 'installer\') -Force
    Copy-Item (Join-Path $installerDir 'Verify-FwGpoWeb-Service.ps1') (Join-Path $stage 'installer\') -Force
    New-Item -ItemType Directory -Force (Join-Path $stage 'powershell\FwGpoBuilder') | Out-Null
    Copy-Item (Join-Path (Split-Path -Parent $root) 'powershell\FwGpoBuilder\*') (Join-Path $stage 'powershell\FwGpoBuilder\') -Recurse -Force
    return $stage
}
function New-ArgsFile {
    param([string]$Stage, [hashtable]$Override = @{})
    $base = [ordered]@{
        ServiceIdentity = 'CORP\FWGPO$'
        AppUrl = 'https://fwgpo.rfkarami.ir'
        Port = 443
        CertPfx = ''
        CertPfxPassword = ''
        ServicePassword = ''
        CapabilitySource = ''
        CreateGmsa = 'false'
        GmsaName = 'FWGPO'
        InstallPath = ''
        DataPath = ''
    }
    foreach ($kv in $Override.GetEnumerator()) { $base[[string]$kv.Key] = $kv.Value }
    $lines = $base.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }
    $file = Join-Path $Stage 'installer-args.txt'
    Set-Content -Path $file -Value $lines -Encoding utf8
    return $file
}

# T1: full happy path — create gMSA + install (self-signed cert) + verify
$t1stage = New-InstallerStage 't1' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t1install = Join-Path $t1stage 'install'; $t1data = Join-Path $t1stage 'data'
$t1file = New-ArgsFile $t1stage @{ CreateGmsa = 'true'; InstallPath = $t1install; DataPath = $t1data }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t1stage' -ArgsFile '$t1file'" `
    @{ FwGpoWebStubKds='present'; FwGpoWebStubRsatMissing='false'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -eq 0) "T1 full install exits 0" "exit=$($r.ExitCode) out=$($r.Out.Substring(0,[Math]::Min(500,$r.Out.Length)))"
$t1result = if (Test-Path (Join-Path $t1stage 'setup-result.txt')) { (Get-Content (Join-Path $t1stage 'setup-result.txt') -Raw) } else { '' }
Assert ($t1result -match 'STATUS=OK') "T1 result file STATUS=OK" "result=$t1result"
Assert (Call-Matched $r.Calls '^New-ADServiceAccount.*spn=HTTP/fwgpo.rfkarami.ir') "T1 gMSA created with SPN from AppUrl host" "calls=$($r.Calls -join ' | ')"
Assert (Call-Matched $r.Calls '^Add-ADGroupMember.*Domain Admins') "T1 gMSA granted to Domain Admins"
Assert (Call-Matched $r.Calls '^New-Service') "T1 Windows service created"
Assert (Call-Matched $r.Calls '^sc\.exe.*obj=CORP.*FWGPO') "T1 service account set to gMSA (sc config obj=)"
Assert (Call-Matched $r.Calls '^Start-Service.*FwGpoWeb') "T1 service started"
Assert (Call-Matched $r.Calls '^New-SelfSignedCertificate.*fwgpo.rfkarami.ir') "T1 self-signed cert created (no cert given)"
Assert (Call-Matched $r.Calls '^Export-PfxCertificate') "T1 cert exported to PFX"
Assert (Call-Matched $r.Calls '^Invoke-WebRequest.*https://localhost:443/api/health') "T1 smoke test ran (install + verify)" "calls=$($r.Calls -join ' | ')"
$t1prod = Join-Path $t1install 'appsettings.Production.json'
Assert (Test-Path $t1prod) "T1 production config written"
if (Test-Path $t1prod) {
    $cfg = Get-Content $t1prod -Raw | ConvertFrom-Json
    Assert ($cfg.App.Hosting -eq 'Kestrel') "T1 config Hosting=Kestrel" "got=$($cfg.App.Hosting)"
    Assert ($cfg.App.KestrelUrl -eq 'https://0.0.0.0:443') "T1 config KestrelUrl" "got=$($cfg.App.KestrelUrl)"
    Assert (($cfg.WebAuthn.Origins -join ',') -eq 'https://fwgpo.rfkarami.ir') "T1 config exact WebAuthn origin"
    Assert ([bool]$cfg.App.KestrelCert.Path) "T1 config KestrelCert:Path set"
    Assert ([bool]$cfg.App.KestrelCert.PasswordFile) "T1 config KestrelCert:PasswordFile set"
    Assert (-not (($cfg | ConvertTo-Json) -match 'app\.pass.*[A-Za-z0-9]{16,}')) "T1 no PFX password in world-readable config"
}

# T2: gMSA already exists — creation skipped, install-only
$t2stage = New-InstallerStage 't2' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t2file = New-ArgsFile $t2stage @{ InstallPath = (Join-Path $t2stage 'install'); DataPath = (Join-Path $t2stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t2stage' -ArgsFile '$t2file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -eq 0) "T2 install-only exits 0" "exit=$($r.ExitCode)"
Assert (-not (Call-Matched $r.Calls '^New-ADServiceAccount')) "T2 no gMSA created when CreateGmsa=false"
Assert (Call-Matched $r.Calls '^Test-ADServiceAccount.*FWGPO') "T2 gMSA install-state checked"

# T3: gMSA not installed on machine -> hard stop with clear error
$t3stage = New-InstallerStage 't3' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t3file = New-ArgsFile $t3stage @{ InstallPath = (Join-Path $t3stage 'install'); DataPath = (Join-Path $t3stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t3stage' -ArgsFile '$t3file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubGmsaTest='notinstalled'; FwGpoWebStubHealth='ok' }
$t3result = if (Test-Path (Join-Path $t3stage 'setup-result.txt')) { (Get-Content (Join-Path $t3stage 'setup-result.txt') -Raw) } else { '' }
Assert ($r.ExitCode -ne 0) "T3 uninstalled gMSA -> non-zero exit" "exit=$($r.ExitCode)"
Assert ($t3result -match 'STATUS=FAIL' -and $t3result -match 'install') "T3 result file STATUS=FAIL at install stage" "result=$t3result"
Assert ($r.Out -match 'not installed on this machine') "T3 clear gMSA error message"

# T4: RSAT missing + no CapabilitySource -> ISO hint
$t4stage = New-InstallerStage 't4' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t4file = New-ArgsFile $t4stage @{ InstallPath = (Join-Path $t4stage 'install'); DataPath = (Join-Path $t4stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t4stage' -ArgsFile '$t4file'" `
    @{ FwGpoWebStubRsatMissing='true'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'CapabilitySource' -and $r.Out -match 'ISO') "T4 missing RSAT + no source -> ISO hint" "out=$($r.Out.Substring(0,[Math]::Min(400,$r.Out.Length)))"

# T5: RSAT missing + CapabilitySource -> installed from ISO, install succeeds
$t5stage = New-InstallerStage 't5' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t5file = New-ArgsFile $t5stage @{ CapabilitySource = 'E:\'; InstallPath = (Join-Path $t5stage 'install'); DataPath = (Join-Path $t5stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t5stage' -ArgsFile '$t5file'" `
    @{ FwGpoWebStubRsatMissing='true'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -eq 0) "T5 offline RSAT from ISO exits 0" "exit=$($r.ExitCode) out=$($r.Out.Substring(0,[Math]::Min(400,$r.Out.Length)))"
Assert (Call-Matched $r.Calls '^Add-WindowsCapability.*Rsat\.GroupPolicy\.Management') "T5 GPMC capability installed from ISO"
Assert (Call-Matched $r.Calls '^Add-WindowsCapability.*Rsat\.AdPowerShell') "T5 AD PowerShell capability installed from ISO"

# T6: user-provided PFX is used (no self-signed generated)
$t6stage = New-InstallerStage 't6' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t6pfx = Join-Path $t6stage 'mycert.pfx'; 'real-pfx' | Set-Content $t6pfx
$t6file = New-ArgsFile $t6stage @{ CertPfx = $t6pfx; CertPfxPassword = 'hunter2'; InstallPath = (Join-Path $t6stage 'install'); DataPath = (Join-Path $t6stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t6stage' -ArgsFile '$t6file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -eq 0) "T6 provided PFX install exits 0" "exit=$($r.ExitCode)"
Assert (-not (Call-Matched $r.Calls '^New-SelfSignedCertificate')) "T6 no self-signed cert when PFX provided"
$t6pfxDst = (Join-Path (Join-Path (Join-Path $t6stage 'data') 'certs') 'app.pfx')
Assert ((Test-Path $t6pfxDst) -and ((Get-Content $t6pfxDst -Raw).Trim() -eq 'real-pfx')) "T6 PFX copied into ACL-restricted data dir"

# T7: smoke test failure -> install fails (service starts but app unhealthy)
$t7stage = New-InstallerStage 't7' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t7file = New-ArgsFile $t7stage @{ InstallPath = (Join-Path $t7stage 'install'); DataPath = (Join-Path $t7stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t7stage' -ArgsFile '$t7file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubHealth='fail' }
Assert ($r.ExitCode -ne 0) "T7 unhealthy app -> non-zero exit" "exit=$($r.ExitCode)"
$t7result = if (Test-Path (Join-Path $t7stage 'setup-result.txt')) { (Get-Content (Join-Path $t7stage 'setup-result.txt') -Raw) } else { '' }
Assert ($t7result -match 'STATUS=FAIL') "T7 result file STATUS=FAIL"

# T8: service fails to reach Running -> clear error
$t8stage = New-InstallerStage 't8' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t8file = New-ArgsFile $t8stage @{ InstallPath = (Join-Path $t8stage 'install'); DataPath = (Join-Path $t8stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t8stage' -ArgsFile '$t8file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubSvcState='Failed'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'did not reach Running') "T8 service not running -> clear error" "out=$($r.Out.Substring(0,[Math]::Min(400,$r.Out.Length)))"

# T9: domain user identity (no gMSA) — password required, no gMSA checks
$t9stage = New-InstallerStage 't9' @{ 'FwGpoWeb.dll' = 'fake-dll'; 'FwGpoWeb.exe' = 'fake-exe' }
$t9file = New-ArgsFile $t9stage @{ ServiceIdentity = 'CORP\jdoe'; ServicePassword = 'pw123'; InstallPath = (Join-Path $t9stage 'install'); DataPath = (Join-Path $t9stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t9stage' -ArgsFile '$t9file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubHealth='ok'; FwGpoWebStubSvcStartName='CORP\jdoe'; FwGpoWebStubAclIdentity='CORP\jdoe' }
Assert ($r.ExitCode -eq 0) "T9 domain user identity exits 0" "exit=$($r.ExitCode) out=$($r.Out.Substring(0,[Math]::Min(400,$r.Out.Length)))"
Assert (Call-Matched $r.Calls '^sc\.exe.*obj=CORP\\jdoe.*password=pw123') "T9 sc config obj= + password= for domain user"
Assert (-not (Call-Matched $r.Calls '^Test-ADServiceAccount')) "T9 no gMSA check for user identity"

# T10: publish dir without FwGpoWeb.exe (not self-contained) -> clear error
$t10stage = New-InstallerStage 't10' @{ 'FwGpoWeb.dll' = 'fake-dll' }
$t10file = New-ArgsFile $t10stage @{ InstallPath = (Join-Path $t10stage 'install'); DataPath = (Join-Path $t10stage 'data') }
$r = Invoke-DeployChild (Join-Path $installerDir 'Install-FromInstaller.ps1') `
    "-StageDir '$t10stage' -ArgsFile '$t10file'" `
    @{ FwGpoWebStubRsatMissing='false'; FwGpoWebStubHealth='ok' }
Assert ($r.ExitCode -ne 0 -and $r.Out -match 'SELF-CONTAINED') "T10 non-self-contained publish rejected with hint" "out=$($r.Out.Substring(0,[Math]::Min(400,$r.Out.Length)))"

# T11: standalone verify script on T1's good install state -> all PASS, exit 0
$r = Invoke-DeployChild (Join-Path $installerDir 'Verify-FwGpoWeb-Service.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -Port 443 -InstallPath '$t1install' -DataPath '$t1data'" `
    @{ FwGpoWebStubHealth='ok'; FwGpoWebStubSvcExists='true' }
Assert ($r.ExitCode -eq 0) "T11 verify on good install exits 0" "exit=$($r.ExitCode) out=$($r.Out)"
$passCount = @(($r.Out -split "`n") | Where-Object { $_ -match '^PASS' }).Count
Assert ($passCount -ge 9) "T11 verify runs >=9 checks all PASS" "passCount=$passCount"
Assert ($r.Out -match 'PASS.*DC reachable via PowerShell bridge') "T11 DC ping check passed"

# T12: verify on a BAD install state (unhealthy app) -> non-zero exit with FAIL lines
$r = Invoke-DeployChild (Join-Path $installerDir 'Verify-FwGpoWeb-Service.ps1') `
    "-ServiceIdentity 'CORP\FWGPO`$' -AppUrl 'https://fwgpo.rfkarami.ir' -Port 443 -InstallPath '$t1install' -DataPath '$t1data'" `
    @{ FwGpoWebStubHealth='fail' }
Assert ($r.ExitCode -ne 0) "T12 verify with failing health exits non-zero" "exit=$($r.ExitCode)"
Assert (@(($r.Out -split "`n") | Where-Object { $_ -match '^FAIL.*HTTPS health' }).Count -gt 0) "T12 failing check reported as FAIL" 

Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail) -ForegroundColor $(if ($script:Fail -eq 0) { 'Green' } else { 'Red' })
exit $(if ($script:Fail -eq 0) { 0 } else { 1 })
