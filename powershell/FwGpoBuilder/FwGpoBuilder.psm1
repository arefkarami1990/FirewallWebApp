#requires -Version 5.1
<#
.SYNOPSIS
    FwGpoBuilder.psm1 - Headless, pure-logic core of "Firewall GPO Builder v6.2".

.DESCRIPTION
    This module contains ALL deterministic logic: IP/CIDR parsing, range
    merging, complement (block-everything-else) computation, wfw rule-string
    conversion and GPO naming. It performs NO AD / network access, so it is
    fully unit-testable on any PowerShell implementation (Windows PowerShell
    and pwsh on Linux/macOS).

    The AD/Group-Policy operations live in FwGpoBuilder.ad.psm1 and the
    JSON CLI entry point in Invoke-FwGpoOp.ps1.

.NOTES
    Behaviour is a faithful port of v6.2 (including the v6.2 merge fix that
    switched hashtable ranges to PSCustomObject so Sort-Object works).

    Documented fixes vs the v6.2 GUI:
      F1. "10.0.0.0/255.255.255.0" (dotted netmask) is now correctly parsed
          as CIDR /24. v6.2 silently collapsed it to the single IP 10.0.0.0.
      F2. "Any Port" no longer emits LPort=0 (invalid WFP port). The LPort
          field is omitted, which in wfw rule-string syntax means all ports.
      F3. Old-rule cleanup is name-scoped (Allow-FW-* / Block-FW-*) so we
          never delete firewall rules that were not created by this tool.
      F4. "Any" / "LocalSubnet" modes honor the selected protocol (TCP / UDP
          / Any) instead of hard-coding TCP only.
      F5. Port token "Any" is used consistently in GPO names (v6.2 used 0,
          which made name-based search for Any-Port policies unreliable).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$GpoNamePattern  = '{0}-Access-{1}-{2}'
$FirewallRuleVer = 'v2.30'

$script:FwKeywords = @('Any','LocalSubnet','DNS','DHCP','WINS','DefaultGateway','Internet','PlayToDevice')

# ---------------------------------------------------------------------------
# Basic validation
# ---------------------------------------------------------------------------

function Test-PortAny {
    param([string]$Port)
    if ([string]::IsNullOrWhiteSpace($Port)) { return $false }
    return ($Port.Trim() -match '^(Any|\*)$')
}

function Test-ValidIp {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return $false }
    $Ip = $Ip.Trim() -replace '[^\d\.]'
    if ($Ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }
    foreach ($p in $Ip.Split('.')) {
        $n = 0
        if (-not [int]::TryParse($p, [ref]$n)) { return $false }
        if ($n -lt 0 -or $n -gt 255) { return $false }
    }
    return $true
}

function Convert-SubnetMaskToPrefixLength {
    <#
    .SYNOPSIS  255.255.255.0 -> 24. Returns $null when the mask is not a
               contiguous valid netmask. 0.0.0.0 -> 0 (/0 = Any).
    #>
    param([string]$Mask)
    if ([string]::IsNullOrWhiteSpace($Mask)) { return $null }
    if (-not (Test-ValidIp $Mask)) { return $null }
    $ip = [uint32](Convert-IpToUint32 $Mask)
    if ($ip -eq [uint32]0) { return 0 }
    if ($ip -eq [uint32]::MaxValue) { return 32 }
    # 32-bit complement in uint32 space (avoids PowerShell signed/unsigned
    # promotion pitfalls with hex literals), then widened to uint64.
    $inv = [uint64]([uint32]::MaxValue - [uint32]$ip)
    if (($inv -band ($inv + 1)) -ne 0) { return $null }   # non-contiguous
    $count = 0
    for ($i = 31; $i -ge 0; $i--) {
        if (($ip -shr $i) -band 1) { $count++ } else { break }
    }
    return $count
}

function Test-IpOrCidr {
    param([string]$S)
    if ([string]::IsNullOrWhiteSpace($S)) { return $false }
    $S = $S.Trim() -replace '[^\d\./\-]'
    $kw = $script:FwKeywords
    if ($kw -contains $S) { return $true }
    if ($S -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        if (-not (Test-ValidIp $Matches[1])) { return $false }
        $p = [int]$Matches[2]
        return ($p -ge 0 -and $p -le 32)
    }
    if ($S -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        # F1: dotted netmask
        if (-not (Test-ValidIp $Matches[1])) { return $false }
        return ($null -ne (Convert-SubnetMaskToPrefixLength $Matches[2]))
    }
    if ($S -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') {
        return ((Test-ValidIp $Matches[1]) -and (Test-ValidIp $Matches[2]))
    }
    return (Test-ValidIp $S)
}

# ---------------------------------------------------------------------------
# Address list parsing
# ---------------------------------------------------------------------------

function Parse-AddressListWithInvalid {
    <#
    .SYNOPSIS  Splits a multi-line/semi/comm/space separated list into Valid / Invalid.
               Accepted forms: 10.0.0.1 | 10.0.0.0/24 | 10.0.0.0/255.255.255.0 | 10.0.0.1-10.0.0.9
    #>
    param([string[]]$Lines)
    $valid = New-Object System.Collections.Generic.List[string]
    $invalid = New-Object System.Collections.Generic.List[string]
    foreach ($raw in $Lines) {
        if ($null -eq $raw) { continue }
        $line = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        foreach ($seg in ($line -split '[,\s;]+')) {
            $seg = $seg.Trim() -replace '[^\d\./\-A-Za-z]'
            if (-not $seg) { continue }
            if (Test-IpOrCidr $seg) { $valid.Add($seg) } else { $invalid.Add($seg) }
        }
    }
    return @{ Valid = $valid; Invalid = $invalid }
}

function Test-AddressListStrict {
    <#
    .SYNOPSIS  Like Parse-AddressListWithInvalid but rejects empty input and
               requires at least one entry. Returns $null on success.
               Throws with the full invalid list on failure.
    #>
    param([string[]]$Lines)
    $parsed = Parse-AddressListWithInvalid -Lines $Lines
    if ($parsed.Valid.Count -eq 0) {
        throw "No valid IP/CIDR/range entries found."
    }
    if ($parsed.Invalid.Count -gt 0) {
        throw "Invalid entries: $($parsed.Invalid -join ', ')"
    }
    return $null
}

# ---------------------------------------------------------------------------
# wfw (Windows Firewall rule string) conversions
# ---------------------------------------------------------------------------

function Convert-CidrToSubnetMask {
    param([int]$PrefixLength)
    if ($PrefixLength -lt 0 -or $PrefixLength -gt 32) { throw "prefix $PrefixLength out of range 0-32" }
    if ($PrefixLength -eq 0) { return '0.0.0.0' }
    $maskInt = [uint32]([uint32]::MaxValue -shl (32 - $PrefixLength))
    $bytes = [System.BitConverter]::GetBytes($maskInt)
    [Array]::Reverse($bytes)
    return (($bytes | ForEach-Object { [string]$_ }) -join '.')
}

function ConvertTo-WfwRemoteAddress {
    <#
    .SYNOPSIS  Converts one address to the wfw RA4 value:
               10.0.0.0/24  -> 10.0.0.0/255.255.255.0
               10.0.0.1     -> 10.0.0.1
               10.0.0.1-10.0.0.9 -> kept as range
               keywords     -> kept as-is
    #>
    param([string]$Address)
    $kw = $script:FwKeywords
    if ($kw -contains $Address) { return $Address }
    if ($Address -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $mask = Convert-CidrToSubnetMask ([int]$Matches[2])
        return "$($Matches[1])/$mask"
    }
    if ($Address -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$') {
        return $Address   # already dotted-mask form
    }
    return $Address
}

function ConvertTo-BareIp {
    param([string]$Address)
    if ([string]::IsNullOrWhiteSpace($Address)) { return '' }
    $Address = $Address.Trim()
    $kw = $script:FwKeywords
    if ($kw -contains $Address) { return $Address }
    if ($Address -match '^(\d{1,3}(?:\.\d{1,3}){3})/([\d.]+)$') { return $Matches[1] }
    if ($Address -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') { return $Matches[1] }
    return $Address
}

# ---------------------------------------------------------------------------
# IP <-> uint32
# ---------------------------------------------------------------------------

function Convert-IpToUint32 {
    param([string]$Ip)
    $clean = $Ip.Trim() -replace '[^\d\.]'
    if (-not (Test-ValidIp $clean)) { throw "Not a valid IPv4 address: '$Ip'" }
    $ipObj = [System.Net.IPAddress]::Parse($clean)
    $bytes = $ipObj.GetAddressBytes()
    [uint64]$val = ([uint64]$bytes[0] * 16777216) + ([uint64]$bytes[1] * 65536) + ([uint64]$bytes[2] * 256) + [uint64]$bytes[3]
    return [uint32]$val
}

function Convert-Uint32ToIp {
    param([uint64]$Int)
    $b0 = [int][math]::Floor($Int / 16777216) % 256
    $b1 = [int][math]::Floor($Int / 65536) % 256
    $b2 = [int][math]::Floor($Int / 256) % 256
    $b3 = [int]($Int % 256)
    return "$b0.$b1.$b2.$b3"
}

# ---------------------------------------------------------------------------
# Range parsing / merging / complement
# ---------------------------------------------------------------------------

function Get-RangeFromCidr {
    param([string]$Cidr)
    if ([string]::IsNullOrWhiteSpace($Cidr)) { return $null }
    $Cidr = $Cidr.Trim()
    if ($Cidr -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,3}(?:\.\d{1,3})*)$') {
        $ip = $Matches[1]
        $maskPart = $Matches[2]
        if (-not (Test-ValidIp $ip)) { return $null }
        if ($maskPart -match '\.') {
            $pref = Convert-SubnetMaskToPrefixLength $maskPart
            if ($null -eq $pref) { return $null }
        } else {
            $pref = [int]$maskPart
            if ($pref -lt 0 -or $pref -gt 32) { return $null }
        }
        $ipInt = [uint32](Convert-IpToUint32 $ip)
        if ($pref -eq 0) { return [PSCustomObject]@{ Start = [uint32]0; End = [uint32]::MaxValue } }
        $mask = [uint32]([uint32]::MaxValue -shl (32 - $pref))
        $network = $ipInt -band $mask
        $broadcast = $network -bor (-bnot $mask -band [uint32]::MaxValue)
        return [PSCustomObject]@{ Start = $network; End = $broadcast }
    }
    return $null
}

function Get-RangeFromIpOrHyphen {
    param([string]$S)
    if ([string]::IsNullOrWhiteSpace($S)) { return $null }
    $S = $S.Trim() -replace '[^\d\.\-]'
    if ($S -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') {
        $a = $Matches[1]; $b = $Matches[2]
        try {
            $start = [uint32](Convert-IpToUint32 $a)
            $end = [uint32](Convert-IpToUint32 $b)
            if ($start -gt $end) { $tmp = $start; $start = $end; $end = $tmp }   # normalize reversed ranges
            return [PSCustomObject]@{ Start = $start; End = $end }
        } catch { return $null }
    }
    if (Test-ValidIp $S) {
        $i = [uint32](Convert-IpToUint32 $S)
        return [PSCustomObject]@{ Start = $i; End = $i }
    }
    return $null
}

function Parse-ApprovedToRanges {
    <#
    .SYNOPSIS  Parses an approved address list into numeric ranges.
               'Any'/'Internet' sets HasAny=true (everything allowed, no blocks).
    #>
    param([string[]]$Approved)
    $ranges = New-Object System.Collections.Generic.List[object]
    $hasAny = $false
    foreach ($a in $Approved) {
        if ([string]::IsNullOrWhiteSpace($a)) { continue }
        $a = $a.Trim() -replace '[^\d\./\-]'
        if ($a -in @('Any','Internet')) { $hasAny = $true; break }
        $r = $null
        if ($a -match '/') {
            $r = Get-RangeFromCidr $a
        } elseif ($a -match '-') {
            $r = Get-RangeFromIpOrHyphen $a
        } else {
            $r = Get-RangeFromIpOrHyphen $a
        }
        if ($r) { $ranges.Add($r) }
    }
    return @{ Ranges = $ranges; HasAny = $hasAny }
}

function Merge-IpRanges {
    <#
    .SYNOPSIS  Merges overlapping/touching ranges.
               (v6.2: PSCustomObject is used for sorting so that Sort-Object
               resolves the Start/End properties - hashtables sort to $null.)
    #>
    param([System.Collections.Generic.List[object]]$Ranges)
    if ($Ranges.Count -eq 0) { return @() }
    $sorted = $Ranges | Sort-Object -Property Start, End
    $merged = New-Object System.Collections.Generic.List[object]
    [uint32]$curStart = [uint32]$sorted[0].Start
    [uint32]$curEnd   = [uint32]$sorted[0].End
    for ($i = 1; $i -lt $sorted.Count; $i++) {
        $r = $sorted[$i]
        [uint32]$rS = [uint32]$r.Start
        [uint32]$rE = [uint32]$r.End
        if ($rS -le ([uint64]$curEnd + 1)) {
            if ($rE -gt $curEnd) { $curEnd = $rE }
        } else {
            $merged.Add([PSCustomObject]@{ Start = $curStart; End = $curEnd })
            $curStart = $rS
            $curEnd = $rE
        }
    }
    $merged.Add([PSCustomObject]@{ Start = $curStart; End = $curEnd })
    return $merged
}

function Get-ComplementRanges {
    <#
    .SYNOPSIS  Given merged approved ranges, returns the ranges that must be
               BLOCKED so that approved + blocked == 0.0.0.0 - 255.255.255.255
               exactly (no overlap, no gap).
    #>
    param($MergedRanges)
    $complement = New-Object System.Collections.Generic.List[object]
    [uint32]$current = 0
    [uint32]$max = [uint32]::MaxValue
    if ($null -eq $MergedRanges -or @($MergedRanges).Count -eq 0) {
        $complement.Add([PSCustomObject]@{ Start = [uint32]0; End = $max })
        return $complement
    }
    foreach ($r in $MergedRanges) {
        [uint32]$rStart = [uint32]$r.Start
        [uint32]$rEnd = [uint32]$r.End
        if ($rStart -gt $current) {
            $endMinusOne = [uint32]([uint64]$rStart - 1)
            $complement.Add([PSCustomObject]@{ Start = $current; End = $endMinusOne })
        }
        if ($rEnd -eq $max) { $current = $max; break }
        [uint64]$next = [uint64]$rEnd + 1
        if ($next -le [uint64]$max) { $current = [uint32]$next } else { $current = $max; break }
    }
    # Append the tail block only when we have NOT already reached the top of
    # the address space. (v6.2 used `current -le max -and current -ne 0`,
    # which emitted a spurious single-IP block range 255.255.255.255-...
    # whenever the approved set ended exactly at 255.255.255.255.)
    if ($current -lt $max) {
        $complement.Add([PSCustomObject]@{ Start = $current; End = $max })
    }
    return $complement
}

function Test-RangeOverlap {
    param($A, $B)
    return -not ($A.End -lt $B.Start -or $A.Start -gt $B.End)
}

function Convert-RangeToWfwString {
    param($Range)
    $sIp = Convert-Uint32ToIp $Range.Start
    $eIp = Convert-Uint32ToIp $Range.End
    if ($Range.Start -eq $Range.End) { return $sIp } else { return "$sIp-$eIp" }
}

function Convert-RangeToCidrString {
    <#
    .SYNOPSIS  Reports a range as a CIDR when it is exactly one aligned network,
               otherwise $null (for human-readable audit output only).
    #>
    param($Range)
    [uint64]$len = [uint64]([uint64]$Range.End - [uint64]$Range.Start) + 1
    if ($len -eq 0 -or $len -gt [uint64][uint32]::MaxValue) { return $null }
    if (($len -band ($len - 1)) -ne 0) { return $null }
    $pref = 32
    if ($len -gt 1) { $pref = 32 - [int][math]::Log($len, 2) }
    if ($pref -eq 32) {
        return "$($(Convert-Uint32ToIp $Range.Start))/32"
    }
    $mask = [uint32]([uint32]::MaxValue -shl $pref)
    if (([uint32]$Range.Start -band $mask) -ne 0) { return $null }
    return "$($(Convert-Uint32ToIp $Range.Start))/$pref"
}

# ---------------------------------------------------------------------------
# GPO naming (v6.2 semantics)
# ---------------------------------------------------------------------------

function Get-GpoNameBase {
    param([string]$OuDn, [string]$PortToken, [string]$Proto)
    $short = 'OU'
    try { $short = Get-OUShortName $OuDn } catch { $short = 'OU' }
    if ([string]::IsNullOrWhiteSpace($short)) { $short = 'OU' }
    $protoShort = switch ($Proto) { 'TCP' { 'TCP' } 'UDP' { 'UDP' } default { 'Any' } }
    return ($GpoNamePattern -f $short, $PortToken, $protoShort)
}

function Get-GpoName {
    param([string]$OuDn, [string]$PortToken, [string]$Proto, [string]$Action = 'ADD')
    try {
        $base = Get-GpoNameBase -OuDn $OuDn -PortToken $PortToken -Proto $Proto
        # Case-SENSITIVE matching: the action tokens are ALL-CAPS (ADD/ANY/
        # BLOCK-LOCALSUBNET) while the protocol token for TCP+UDP is 'Any'
        # (title case). v6.2 used case-insensitive -match, which corrupted
        # Any-Port GPO names (e.g. 'Servers-Access-0-Any' -> '...-0-ADD').
        if ($base -cnotmatch '-ADD$|-ANY$|-BLOCK-LOCALSUBNET$') { $base = "$base-$Action" }
        else { $base = $base -creplace '-(ADD|ANY|BLOCK-LOCALSUBNET)$', "-$Action" }
        return $base
    } catch {
        return "FW-Access-$PortToken-$Proto-$Action"
    }
}

function Get-OUShortName {
    param([string]$DN)
    if ([string]::IsNullOrWhiteSpace($DN)) { return 'OU' }
    if ($DN -match '^(?:OU|CN|DC)=([^,]+)') { return $Matches[1].Trim() }
    return ($DN -replace '[\\/:*?"<>|]', '_')
}

Export-ModuleMember -Function `
    Test-PortAny, Test-ValidIp, Convert-SubnetMaskToPrefixLength, Test-IpOrCidr, `
    Parse-AddressListWithInvalid, Test-AddressListStrict, `
    Convert-CidrToSubnetMask, ConvertTo-WfwRemoteAddress, ConvertTo-BareIp, `
    Convert-IpToUint32, Convert-Uint32ToIp, `
    Get-RangeFromCidr, Get-RangeFromIpOrHyphen, Parse-ApprovedToRanges, `
    Merge-IpRanges, Get-ComplementRanges, Test-RangeOverlap, `
    Convert-RangeToWfwString, Convert-RangeToCidrString, `
    Get-GpoNameBase, Get-GpoName, Get-OUShortName
