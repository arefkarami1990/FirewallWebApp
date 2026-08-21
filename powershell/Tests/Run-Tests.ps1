#requires -Version 5.1
<#
    Run-Tests.ps1 - Unit tests for the FwGpoBuilder pure-logic module.
    Runs on ANY PowerShell (Windows PowerShell 5.1+ or pwsh 7+) including Linux.
    Exit code 0 = all passed.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path $PSScriptRoot '..\FwGpoBuilder\FwGpoBuilder.psm1'
Import-Module $modulePath -Force -DisableNameChecking

$script:Pass = 0
$script:Fail = 0

function Assert {
    param([bool]$Cond, [string]$Name)
    if ($Cond) { $script:Pass++; Write-Host "  PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "  FAIL  $Name" -ForegroundColor Red }
}

function AssertEqual {
    param($Expected, $Actual, [string]$Name)
    $ok = ($Expected -ceq $Actual)
    if (-not $ok) { Write-Host "        expected=[$Expected] actual=[$Actual]" -ForegroundColor Yellow }
    Assert $ok $Name
}

Write-Host "`n== Test-ValidIp =="
Assert (Test-ValidIp '10.0.0.1') '10.0.0.1 valid'
Assert (Test-ValidIp '0.0.0.0') '0.0.0.0 valid'
Assert (Test-ValidIp '255.255.255.255') '255.255.255.255 valid'
Assert (-not (Test-ValidIp '256.1.1.1')) '256.1.1.1 invalid'
Assert (-not (Test-ValidIp '1.2.3')) '1.2.3 invalid'
Assert (-not (Test-ValidIp '')) 'empty invalid'
Assert (-not (Test-ValidIp '1.2.3.4.5')) '1.2.3.4.5 invalid'
Assert (-not (Test-ValidIp 'abc')) 'abc invalid'
# Test-ValidIp is a normalizer (v6.2 behaviour): it strips junk chars. The
# security gate is Parse-AddressListWithInvalid, which tokenizes first and
# only accepts pure [0-9./-] tokens. Proven below in the list-parser test.
$injParsed = Parse-AddressListWithInvalid -Lines @('1.2.3.4; rm -rf /')
Assert ((@($injParsed.Valid) -contains '1.2.3.4')) 'injection: IP part accepted'
Assert (-not (@($injParsed.Valid) -contains '1.2.3.4; rm -rf /')) 'injection: raw shell string never valid'
Assert (@($injParsed.Valid) -notcontains 'rm' -and (@($injParsed.Valid) -notcontains '-rf')) 'injection: shell words never valid'

Write-Host "`n== Test-IpOrCidr =="
Assert (Test-IpOrCidr '10.0.0.0/24') 'CIDR /24 valid'
Assert (Test-IpOrCidr '10.0.0.0/32') 'CIDR /32 valid'
Assert (Test-IpOrCidr '10.0.0.0/0') 'CIDR /0 valid'
Assert (-not (Test-IpOrCidr '10.0.0.0/33')) 'CIDR /33 invalid'
Assert (Test-IpOrCidr '10.0.0.1-10.0.0.9') 'range valid'
Assert (Test-IpOrCidr '10.0.0.9-10.0.0.1 ') 'trailing space normalized (v6.2 behaviour)'
Assert (Test-IpOrCidr '10.0.0.0/255.255.255.0') 'FIX F1: dotted netmask valid'
Assert (Test-IpOrCidr '10.0.0.0/255.255.255.128') 'dotted netmask /25 valid'
Assert (-not (Test-IpOrCidr '10.0.0.0/255.0.255.0')) 'non-contiguous mask invalid'
Assert (-not (Test-IpOrCidr 'Any')) 'keyword Any not a list entry (v6.2 behaviour)'
Assert (-not (Test-IpOrCidr 'garbage')) 'garbage invalid'
Assert (-not (Test-IpOrCidr '')) 'empty invalid'

Write-Host "`n== Convert-SubnetMaskToPrefixLength (FIX F1) =="
AssertEqual '24' ([string](Convert-SubnetMaskToPrefixLength '255.255.255.0')) '255.255.255.0 -> 24'
AssertEqual '16' ([string](Convert-SubnetMaskToPrefixLength '255.255.0.0')) '255.255.0.0 -> 16'
AssertEqual '8'  ([string](Convert-SubnetMaskToPrefixLength '255.0.0.0')) '255.0.0.0 -> 8'
AssertEqual '25' ([string](Convert-SubnetMaskToPrefixLength '255.255.255.128')) '255.255.255.128 -> 25'
AssertEqual '10' ([string](Convert-SubnetMaskToPrefixLength '255.192.0.0')) '255.192.0.0 -> 10'
AssertEqual '9'  ([string](Convert-SubnetMaskToPrefixLength '255.128.0.0')) '255.128.0.0 -> 9'
AssertEqual '0'  ([string](Convert-SubnetMaskToPrefixLength '0.0.0.0')) '0.0.0.0 -> 0'
AssertEqual '32' ([string](Convert-SubnetMaskToPrefixLength '255.255.255.255')) '255.255.255.255 -> 32'
Assert ($null -eq (Convert-SubnetMaskToPrefixLength '255.0.255.0')) '255.0.255.0 -> null (non-contiguous)'
Assert ($null -eq (Convert-SubnetMaskToPrefixLength '255.255.254.255')) '255.255.254.255 -> null'

Write-Host "`n== Get-RangeFromCidr =="
$r = Get-RangeFromCidr '10.0.0.0/24'
AssertEqual '10.0.0.0' (Convert-Uint32ToIp $r.Start) '10.0.0.0/24 start'
AssertEqual '10.0.0.255' (Convert-Uint32ToIp $r.End) '10.0.0.0/24 end'
$r = Get-RangeFromCidr '10.0.5.7/24'
AssertEqual '10.0.5.0' (Convert-Uint32ToIp $r.Start) 'host bits zeroed (network)'
AssertEqual '10.0.5.255' (Convert-Uint32ToIp $r.End) 'host bits set (broadcast)'
$r = Get-RangeFromCidr '0.0.0.0/0'
AssertEqual '0.0.0.0' (Convert-Uint32ToIp $r.Start) '/0 start'
AssertEqual '255.255.255.255' (Convert-Uint32ToIp $r.End) '/0 end'
$r = Get-RangeFromCidr '10.0.0.0/255.255.255.0'
Assert ($r -and ($r.Start -eq (Convert-IpToUint32 '10.0.0.0'))) 'dotted mask parses (FIX F1)'
Assert ($null -eq (Get-RangeFromCidr '10.0.0.0/255.0.255.0')) 'bad dotted mask -> null'
$r = Get-RangeFromIpOrHyphen '192.168.1.10-192.168.1.20'
AssertEqual '192.168.1.10' (Convert-Uint32ToIp $r.Start) 'hyphen start'
AssertEqual '192.168.1.20' (Convert-Uint32ToIp $r.End) 'hyphen end'

Write-Host "`n== Merge-IpRanges (v6.2 PSCustomObject fix) =="
$mk = { param([string]$s,[string]$e) [PSCustomObject]@{ Start=[uint32](Convert-IpToUint32 $s); End=[uint32](Convert-IpToUint32 $e) } }
$in = [System.Collections.Generic.List[object]]::new()
$in.Add((& $mk '1.1.1.1' '1.1.1.5')); $in.Add((& $mk '1.1.1.6' '1.1.1.9'))
$m = Merge-IpRanges $in
Assert ($m.Count -eq 1) 'touching ranges merge'
AssertEqual '1.1.1.1-1.1.1.9' "$(Convert-Uint32ToIp $m[0].Start)-$(Convert-Uint32ToIp $m[0].End)" 'touching merged value'
$in = [System.Collections.Generic.List[object]]::new()
$in.Add((& $mk '10.0.0.0' '10.0.0.255')); $in.Add((& $mk '10.0.1.0' '10.0.1.255'))
$m = Merge-IpRanges $in
Assert ($m.Count -eq 1) 'adjacent /24s merge'
AssertEqual '10.0.0.0-10.0.1.255' "$(Convert-Uint32ToIp $m[0].Start)-$(Convert-Uint32ToIp $m[0].End)" 'adjacent merged value'
$in = [System.Collections.Generic.List[object]]::new()
$in.Add((& $mk '10.0.0.0' '10.0.0.255')); $in.Add((& $mk '10.0.0.128' '10.0.0.191'))
$m = Merge-IpRanges $in
Assert ($m.Count -eq 1) 'contained range merges'
$in = [System.Collections.Generic.List[object]]::new()
$in.Add((& $mk '10.9.0.0' '10.9.0.10')); $in.Add((& $mk '10.8.0.0' '10.8.0.10'))
$m = Merge-IpRanges $in
Assert ($m.Count -eq 2) 'disjoint stays 2'
AssertEqual '10.8.0.0' (Convert-Uint32ToIp $m[0].Start) 'sorted by start'
$m = @(Merge-IpRanges ([System.Collections.Generic.List[object]]::new()))
Assert ($m.Count -eq 0) 'empty input -> empty'

Write-Host "`n== Get-ComplementRanges =="
$c = @(Get-ComplementRanges @())
Assert ($c.Count -eq 1) 'no approved -> one full block range'
AssertEqual '0.0.0.0-255.255.255.255' "$(Convert-Uint32ToIp $c[0].Start)-$(Convert-Uint32ToIp $c[0].End)" 'full block value'
$merged = Merge-IpRanges ([System.Collections.Generic.List[object]]@(
    [PSCustomObject]@{ Start=[uint32](Convert-IpToUint32 '10.0.0.0'); End=[uint32](Convert-IpToUint32 '10.0.0.255') }
))
$c = Get-ComplementRanges $merged
Assert ($c.Count -eq 2) 'one /24 approved -> 2 complement ranges'
AssertEqual '0.0.0.0-9.255.255.255' "$(Convert-Uint32ToIp $c[0].Start)-$(Convert-Uint32ToIp $c[0].End)" 'complement pre'
AssertEqual '10.0.1.0-255.255.255.255' "$(Convert-Uint32ToIp $c[1].Start)-$(Convert-Uint32ToIp $c[1].End)" 'complement post'
$merged = Merge-IpRanges ([System.Collections.Generic.List[object]]@(
    [PSCustomObject]@{ Start=[uint32]0; End=[uint32]::MaxValue }
))
$c = @(Get-ComplementRanges $merged)
Assert ($c.Count -eq 0) 'approved /0 -> zero complement ranges'

Write-Host "`n== Large-scale: /24 minus one IP (regression: v6.2 '61 missing') =="
$addrLines = New-Object System.Collections.Generic.List[string]
for ($i = 0; $i -le 255; $i++) { if ($i -ne 50) { $addrLines.Add("10.1.0.$i") } }
$parsed = Parse-AddressListWithInvalid -Lines $addrLines
Assert ($parsed.Valid.Count -eq 255) '255 hosts parsed valid (0..255 minus one)'
Assert ($parsed.Invalid.Count -eq 0) 'no invalid entries'
$parsedRanges = Parse-ApprovedToRanges -Approved @($parsed.Valid)
Assert (-not $parsedRanges.HasAny) 'no Any'
$merged = @(Merge-IpRanges $parsedRanges.Ranges)
Assert ($merged.Count -eq 2) "255 hosts merge to 2 ranges (got $($merged.Count))"
AssertEqual '10.1.0.0-10.1.0.49' "$(Convert-Uint32ToIp $merged[0].Start)-$(Convert-Uint32ToIp $merged[0].End)" 'merged range 1'
AssertEqual '10.1.0.51-10.1.0.255' "$(Convert-Uint32ToIp $merged[1].Start)-$(Convert-Uint32ToIp $merged[1].End)" 'merged range 2'
$comp = @(Get-ComplementRanges $merged)
Assert ($comp.Count -eq 3) "complement has 3 ranges (got $($comp.Count))"
$len = & {
    $tot = [uint64]0
    foreach ($x in (@($merged) + @($comp))) { $tot += [uint64]([uint64]$x.End - [uint64]$x.Start) + 1 }
    $tot
}
Assert ($len -eq 4294967296) 'merged + complement covers the entire 32-bit space exactly (2^32)'

Write-Host "`n== Randomized invariant tests (20 rounds) =="
$rand = New-Object System.Random(20260821)
$pool = @()
for ($i = 0; $i -lt 300; $i++) {
    $base = "10.$($rand.Next(256)).$($rand.Next(256)).0"
    $kind = $rand.Next(4)
    switch ($kind) {
        0 { $pool += "$base/$(24 + $rand.Next(8))" }                       # /24..31
        1 { $pool += "$base/$($rand.Next(33))" }                           # /0..32
        2 { $a = "$base"; $pool += "${base}-10.$($rand.Next(256)).255.255" }
        3 { $pool += "172.16.$($rand.Next(256)).$($rand.Next(256))" }      # host
    }
}
$allInvariants = $true
for ($round = 0; $round -lt 20; $round++) {
    $n = $rand.Next(5, 120)
    $sel = New-Object System.Collections.Generic.List[string]
    for ($j = 0; $j -lt $n; $j++) { $sel.Add($pool[$rand.Next($pool.Count)]) }
    $pr = Parse-ApprovedToRanges -Approved $sel
    if ($pr.HasAny) { continue }
    $merged = @(Merge-IpRanges $pr.Ranges)
    $comp = @(Get-ComplementRanges $merged)
    # invariant 1: merged sorted & disjoint (gaps are allowed - they belong to the complement)
    $ok1 = $true
    for ($k = 1; $k -lt $merged.Count; $k++) {
        if ($merged[$k].Start -le $merged[$k - 1].End) { $ok1 = $false; break }
    }
    # invariant 2: complement sorted & disjoint
    $ok2 = $true
    for ($k = 1; $k -lt $comp.Count; $k++) {
        if ($comp[$k].Start -le $comp[$k - 1].End) { $ok2 = $false; break }
    }
    # invariant 3: exact partition of [0, 2^32)
    $tot = [uint64]0
    foreach ($x in (@($merged) + @($comp))) { $tot += [uint64]([uint64]$x.End - [uint64]$x.Start) + 1 }
    $ok3 = ($tot -eq 4294967296)
    if (-not ($ok1 -and $ok2 -and $ok3)) {
        $allInvariants = $false
        Write-Host "        round $round violated: merged=$ok1 comp=$ok2 partition=$ok3" -ForegroundColor Yellow
    }
}
Assert $allInvariants 'all 20 randomized rounds: disjoint + exact partition'

Write-Host "`n== wfw conversions & GPO names =="
AssertEqual '10.0.0.0/255.255.255.0' (ConvertTo-WfwRemoteAddress '10.0.0.0/24') 'CIDR -> dotted mask'
AssertEqual 'Any' (ConvertTo-WfwRemoteAddress 'Any') 'keyword passthrough'
AssertEqual '10.0.0.1' (ConvertTo-WfwRemoteAddress '10.0.0.1') 'single passthrough'
AssertEqual '10.0.0.1-10.0.0.9' (ConvertTo-WfwRemoteAddress '10.0.0.1-10.0.0.9') 'range passthrough'
AssertEqual '10.0.0.1' (ConvertTo-BareIp '10.0.0.1/24') 'bare ip from CIDR'
AssertEqual '10.0.0.1' (ConvertTo-BareIp '10.0.0.1-10.0.0.9') 'bare ip from range'
AssertEqual 'Servers-Access-3389-TCP-ADD' (Get-GpoName -OuDn 'OU=Servers,DC=corp,DC=local' -PortToken '3389' -Proto 'TCP' -Action 'ADD') 'GPO name ADD'
AssertEqual 'Servers-Access-3389-TCP-ANY' (Get-GpoName -OuDn 'OU=Servers,DC=corp,DC=local' -PortToken '3389' -Proto 'TCP' -Action 'ANY') 'GPO name action replace'
AssertEqual 'Servers-Access-Any-Any-ADD' (Get-GpoName -OuDn 'OU=Servers,DC=corp,DC=local' -PortToken 'Any' -Proto 'Any' -Action 'ADD') 'GPO name any/any (FIX F5)'
AssertEqual 'Servers' (Get-OUShortName 'OU=Servers,DC=corp,DC=local') 'OU short name'
$ips = @('0.0.0.0','1.2.3.4','10.0.0.1','192.168.1.1','255.255.255.255','172.16.5.9')
$roundOk = $true
foreach ($ip in $ips) { if ((Convert-Uint32ToIp (Convert-IpToUint32 $ip)) -ne $ip) { $roundOk = $false } }
Assert $roundOk 'ip <-> uint32 round trip'
Assert (Test-PortAny 'Any') 'PortAny Any'
Assert (Test-PortAny '*') 'PortAny *'
Assert (-not (Test-PortAny '80')) 'PortAny 80 false'

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $script:Pass, $script:Fail)
if ($script:Fail -gt 0) { exit 1 }
exit 0
