#requires -Version 5.1
<#
.SYNOPSIS
    FwGpoBuilder.ad.psm1 - Active Directory / Group Policy operations.

.DESCRIPTION
    Windows-only module. Every function here talks to the domain controller
    via the ActiveDirectory / GroupPolicy modules. The process identity used
    is the identity of the calling process - i.e. the IIS app pool / Windows
    service account, which must be either:
      * a GMSA (Group Managed Service Account), or
      * a domain user with sufficient privileges (e.g. Domain Admins).
    No credentials are ever passed on the command line or in environment
    variables; the module simply uses the ambient identity.

    All public functions return plain PSCustomObjects that ConvertTo-Json
    can serialize safely (no DirectoryEntry / GPO objects in responses).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:FwRuleVer = 'v2.30'
$script:FwFwKey = 'HKLM\Software\Policies\Microsoft\WindowsFirewall\FirewallRules'
$script:FwManagedPrefixes = @('Allow-FW-', 'Block-FW-')

Import-Module (Join-Path $PSScriptRoot 'FwGpoBuilder.psm1') -DisableNameChecking

function Import-FwAdModules {
    $missing = @()
    foreach ($mod in 'GroupPolicy', 'ActiveDirectory') {
        try {
            if (-not (Get-Module -Name $mod)) {
                if (Get-Module -ListAvailable -Name $mod) {
                    Import-Module $mod -DisableNameChecking -ErrorAction Stop
                } else { $missing += $mod }
            }
        } catch { $missing += "$mod ($($_.Exception.Message))" }
    }
    if ($missing.Count -gt 0) {
        throw "Required PowerShell module(s) not available on this machine: $($missing -join ', '). On a member server install RSAT: Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management~~~~0.0.1.0, Rsat.AdPowerShell~~~~0.0.1.0"
    }
}

# ---------------------------------------------------------------------------
# Domain / identity info
# ---------------------------------------------------------------------------

function Get-FwDomainInfo {
    Import-FwAdModules
    $domain = Get-ADDomain -ErrorAction Stop
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return [PSCustomObject]@{
        Domain      = $domain.DNSRoot
        Pdc         = $domain.PDCEmulator
        ServiceUser = $id.Name
        IsDomain    = $id.IsAuthenticated
    }
}

function Test-FwIsDomainAdmin {
    param([string]$Identity)
    try {
        Import-FwAdModules
        $principal = if ([string]::IsNullOrWhiteSpace($Identity)) { $null } else { New-Object System.Security.Principal.WindowsPrincipal((New-Object System.Security.Principal.WindowsIdentity($Identity)) ) }
        if (-not $principal) { return $false }
        $id = $principal.Identity
        if ($id.IsAuthenticated -and $id.Name -match '\\(Administrator|.*-DC\..*)$') { return $true }
        $identityValue = $principal.Translate([System.Security.Principal.SecurityIdentifier]).Value
        $da = (Get-ADGroup 'Domain Admins' -Server (Get-ADDomain).PDCEmulator -ErrorAction SilentlyContinue)
        if ($da) {
            $members = Get-ADGroupMember -Identity $da.SamAccountName -Server $da.Server -ErrorAction SilentlyContinue
            foreach ($m in $members) {
                try {
                    $sid = New-Object System.Security.Principal.SecurityIdentifier($m.Sid.Value)
                    if ($sid.Value -eq $identityValue) { return $true }
                } catch {}
            }
        }
        return $false
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# User / group resolution (web authz)
# ---------------------------------------------------------------------------

function Get-FwResolveUser {
    <#
    .SYNOPSIS  Resolves a user (UPN or DOMAIN\user) and checks membership of
               the given (flat) admin groups. Fails closed: any AD error
               results in IsAdmin=false.
    #>
    param([string]$Upn, [string[]]$AdminGroups)
    Import-FwAdModules
    if ([string]::IsNullOrWhiteSpace($Upn)) { throw 'upn is required.' }
    $user = $null
    try {
        $user = Get-ADUser -Identity $Upn -Properties DistinguishedName, DisplayName, SamAccountName -ErrorAction Stop
    } catch {
        $user = $null
    }
    if ($null -eq $user) {
        return [PSCustomObject]@{ Found = $false; DisplayName = $null; IsAdmin = $false }
    }
    $dn = $user.DistinguishedName
    $isAdmin = $false
    foreach ($g in $AdminGroups) {
        if ([string]::IsNullOrWhiteSpace($g)) { continue }
        try {
            $group = Get-ADGroup -Identity $g -ErrorAction Stop
            $members = Get-ADGroupMember -Identity $group.DistinguishedName -ErrorAction Stop
            foreach ($m in $members) {
                if ($m.DistinguishedName -ceq $dn) { $isAdmin = $true; break }
            }
        } catch {}
        if ($isAdmin) { break }
    }
    return [PSCustomObject]@{
        Found       = $true
        DisplayName = $user.DisplayName
        IsAdmin     = $isAdmin
    }
}

# ---------------------------------------------------------------------------
# OU / GPO discovery
# ---------------------------------------------------------------------------

function Get-FwAllOus {
    param([int]$Limit = 5000)
    Import-FwAdModules
    $pdc = (Get-ADDomain).PDCEmulator
    $all = Get-ADOrganizationalUnit -Filter * -Server $pdc -Properties Name, DistinguishedName -ErrorAction Stop
    $out = foreach ($o in ($all | Sort-Object DistinguishedName)) {
        [PSCustomObject]@{ Name = $o.Name; Dn = $o.DistinguishedName }
    }
    if ($out -is [array] -and $out.Count -gt $Limit) { $out = $out[0..($Limit - 1)] }
    return $out
}

function Test-FwOuExists {
    param([string]$Dn)
    if ([string]::IsNullOrWhiteSpace($Dn)) { return $false }
    try {
        $obj = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Dn")
        return ($obj.distinguishedName -ne $null)
    } catch { return $false }
}

function Get-FwAllGpos {
    param([int]$Limit = 1000)
    Import-FwAdModules
    $names = (Get-GPO -All -ErrorAction SilentlyContinue).DisplayName | Where-Object { $_ } | Sort-Object
    if ($names.Count -gt $Limit) { $names = $names[0..($Limit - 1)] }
    return $names
}

function Find-FwExistingGpoForPort {
    param([string]$OuDn, [string]$PortToken, [string]$Proto)
    Import-FwAdModules
    $base = Get-GpoNameBase -OuDn $OuDn -PortToken $PortToken -Proto $Proto
    try {
        $all = Get-GPO -All -ErrorAction SilentlyContinue
        foreach ($g in $all) {
            if ($g.DisplayName -like "*$PortToken*" -and $g.DisplayName -like "*$base*") { return $g }
        }
        $short = Get-OUShortName -DN $OuDn
        foreach ($g in $all) {
            if ($g.DisplayName -like "*$short*" -and $g.DisplayName -like "*$PortToken*") { return $g }
        }
    } catch {}
    return $null
}

# ---------------------------------------------------------------------------
# Reading existing managed rules
# ---------------------------------------------------------------------------

function Get-FwLportMatchFilter {
    <#
    .SYNOPSIS  Returns a predicate description for "this rule belongs to the
               given port". For Any port it matches rules WITHOUT LPort or
               with LPort=0 / LPort=Any (legacy).
    #>
    param([int]$Port, [bool]$PortIsAny)
    return [PSCustomObject]@{ Port = $Port; PortIsAny = $PortIsAny }
}

function Test-FwRuleMatchesPort {
    param([string]$RuleString, [int]$Port, [bool]$PortIsAny)
    if ($PortIsAny) {
        if ($RuleString -match 'LPort=(\d+)\|') { return ($Matches[1] -eq '0') }
        if ($RuleString -match 'LPort=Any\|') { return $true }
        return ($RuleString -notmatch 'LPort=')   # no LPort field => all ports
    }
    return ($RuleString -match "LPort=$Port\|")
}

function Test-FwRuleIsManaged {
    param([string]$ValueName)
    foreach ($p in $script:FwManagedPrefixes) { if ($ValueName -like "$p*") { return $true } }
    return $false
}

function Read-FwExistingAllowed {
    param([string]$GpoName, [int]$Port, [bool]$PortIsAny, [string]$Protocol)
    $existing = New-Object System.Collections.Generic.List[string]
    try {
        $vals = Get-GPRegistryValue -Name $GpoName -Key $script:FwFwKey -ErrorAction SilentlyContinue
        foreach ($v in $vals) {
            $d = $v.Value
            if (-not (Test-FwRuleIsManaged -ValueName $v.ValueName)) { continue }
            if ($d -notmatch 'Action=Allow') { continue }
            if ($d -notmatch 'Active=TRUE') { continue }
            if ($d -notmatch 'EmbedCtxt=.*Block') { continue }
            if (-not (Test-FwRuleMatchesPort -RuleString $d -Port $Port -PortIsAny $PortIsAny)) { continue }
            $ok = $false
            if ($Protocol -eq 'TCP' -and $d -match 'Protocol=6\|') { $ok = $true }
            if ($Protocol -eq 'UDP' -and $d -match 'Protocol=17\|') { $ok = $true }
            if ($Protocol -eq 'Any' -and ($d -match 'Protocol=6\|' -or $d -match 'Protocol=17\|')) { $ok = $true }
            if (-not $ok) { continue }
            if ($d -notmatch '\|RA4=([^|]+)\|') { continue }
            foreach ($ra in ($Matches[1] -split ',')) {
                $bare = ConvertTo-BareIp $ra
                if ($bare -and $bare -notin $existing) { $existing.Add($bare) }
            }
        }
    } catch {}
    return $existing
}

function Get-FwGpoRules {
    <#
    .SYNOPSIS  Reads back managed Allow/Block rules for a port (audit view).
    #>
    param([string]$GpoName, [int]$Port, [bool]$PortIsAny)
    $allows = @(); $blocks = @()
    try {
        $vals = Get-GPRegistryValue -Name $GpoName -Key $script:FwFwKey -ErrorAction SilentlyContinue
        foreach ($v in $vals) {
            $d = $v.Value
            if (-not (Test-FwRuleIsManaged -ValueName $v.ValueName)) { continue }
            if ($d -notmatch 'Active=TRUE') { continue }
            if (-not (Test-FwRuleMatchesPort -RuleString $d -Port $Port -PortIsAny $PortIsAny)) { continue }
            $addr = if ($d -match '\|RA4=([^|]+)\|') { $Matches[1] } else { '' }
            if ($d -match 'Action=Allow') {
                $allows += [PSCustomObject]@{ Name = $v.ValueName; Action = 'Allow'; Address = $addr }
            } else {
                $blocks += [PSCustomObject]@{ Name = $v.ValueName; Action = 'Block'; Address = $addr }
            }
        }
    } catch {}
    return [PSCustomObject]@{ Allows = $allows; Blocks = $blocks }
}

# ---------------------------------------------------------------------------
# GPO profile baseline (v6.2 Update-GpoProfile)
# ---------------------------------------------------------------------------

function Update-FwGpoProfile {
    param([string]$GpoName)
    $keys = @(
        'HKLM\Software\Policies\Microsoft\WindowsFirewall\DomainProfile',
        'HKLM\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile',
        'HKLM\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
    )
    foreach ($k in $keys) {
        try {
            Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'EnableFirewall' -Type DWord -Value 1 | Out-Null
            Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'DefaultInboundAction' -Type DWord -Value 1 | Out-Null
            Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'DefaultOutboundAction' -Type DWord -Value 0 | Out-Null
            Set-GPRegistryValue -Name $GpoName -Key $k -ValueName 'AllowLocalPolicyMerge' -Type DWord -Value 1 | Out-Null
        } catch {}
    }
}

# ---------------------------------------------------------------------------
# Rule writing (v6.2 Add-AllowAndBlockRules-StrictNoOverlap + fixes)
# ---------------------------------------------------------------------------

function Get-FwLportSegment {
    param([int]$Port, [bool]$PortIsAny)
    if ($PortIsAny) { return '' }     # F2: omit LPort => all ports
    return "LPort=$Port|"
}

function Remove-FwManagedRules {
    <#
    .SYNOPSIS  Deletes managed rules (Allow-FW-*/Block-FW-*) for a port.
               F3: name-scoped so foreign rules are never touched.
    #>
    param([string]$GpoName, [int]$Port, [bool]$PortIsAny)
    $deleted = 0
    try {
        $vals = Get-GPRegistryValue -Name $GpoName -Key $script:FwFwKey -ErrorAction SilentlyContinue
        foreach ($v in $vals) {
            if (-not (Test-FwRuleIsManaged -ValueName $v.ValueName)) { continue }
            if (Test-FwRuleMatchesPort -RuleString $v.Value -Port $Port -PortIsAny $PortIsAny) {
                Remove-GPRegistryValue -Name $GpoName -Key $script:FwFwKey -ValueName $v.ValueName -ErrorAction SilentlyContinue
                $deleted++
            }
        }
    } catch {}
    return $deleted
}

function Add-FwAllowAndBlockRules {
    <#
    .SYNOPSIS  Writes Allow rules for the approved list and Block rules for
               the complement (everything else), with a hard no-overlap
               verification that THROWS on any overlap (v6.2 behaviour).
               F4: honors Protocol TCP / UDP / Any in every mode.
    #>
    param(
        [string]$GpoName,
        [int]$Port,
        [bool]$PortIsAny,
        [string]$Protocol,
        [string[]]$FinalAllowed
    )
    $log = New-Object System.Collections.Generic.List[string]
    $lport = Get-FwLportSegment -Port $Port -PortIsAny $PortIsAny
    $portToken = if ($PortIsAny) { 'Any' } else { "$Port" }

    $protos = @()
    if ($Protocol -in @('TCP','Any')) { $protos += 'TCP' }
    if ($Protocol -in @('UDP','Any')) { $protos += 'UDP' }

    foreach ($proto in $protos) {
        $num = if ($proto -eq 'TCP') { 6 } else { 17 }
        $idx = 0
        foreach ($addr in $FinalAllowed) {
            $wfw = ConvertTo-WfwRemoteAddress $addr
            $name = "Allow-FW-$proto-$portToken-Approved-$idx"
            $str = "${script:FwRuleVer}|Action=Allow|Active=TRUE|Dir=In|Protocol=$num|$lport RA4=$wfw|Name=Allow $proto $portToken from $addr|Desc=ADD Allow NO OVERLAP|EmbedCtxt=FW-ADD|"
            Set-GPRegistryValue -Name $GpoName -Key $script:FwFwKey -ValueName $name -Type String -Value $str | Out-Null
            $log.Add("Allow $proto $portToken from $addr (RA4=$wfw)")
            $idx++
        }
    }

    $parsed = Parse-ApprovedToRanges -Approved $FinalAllowed
    if ($parsed.HasAny) { $log.Add('HasAny: block rules skipped'); return @{ Log = $log; AllowCount = $FinalAllowed.Count * $protos.Count; BlockCount = 0 } }

    $merged = @(Merge-IpRanges -Ranges $parsed.Ranges)
    $complement = @(Get-ComplementRanges -MergedRanges $merged)

    foreach ($cr in $complement) {
        foreach ($ar in $merged) {
            if (Test-RangeOverlap -A $cr -B $ar) {
                $msg = "FATAL OVERLAP: Block $(Convert-Uint32ToIp $cr.Start)-$(Convert-Uint32ToIp $cr.End) overlaps Allow $(Convert-Uint32ToIp $ar.Start)-$(Convert-Uint32ToIp $ar.End)"
                throw $msg
            }
        }
    }
    $log.Add("Verified NO OVERLAP - $($complement.Count) block range(s)")

    $bIdx = 0
    foreach ($cr in $complement) {
        $wfwBlock = Convert-RangeToWfwString $cr
        foreach ($proto in $protos) {
            $num = if ($proto -eq 'TCP') { 6 } else { 17 }
            $bName = "Block-FW-$proto-$portToken-Except-$bIdx"
            $bStr = "${script:FwRuleVer}|Action=Block|Active=TRUE|Dir=In|Protocol=$num|$lport RA4=$wfwBlock|Name=Block $proto $portToken from $wfwBlock|Desc=Block all except allowed NO OVERLAP|EmbedCtxt=FW-ADD-Block|"
            Set-GPRegistryValue -Name $GpoName -Key $script:FwFwKey -ValueName $bName -Type String -Value $bStr | Out-Null
        }
        $log.Add("Block $portToken from $wfwBlock$(Convert-RangeToCidrString $cr)")
        $bIdx++
        if ($bIdx -gt 200) { $log.Add('BLOCK LIMIT REACHED (200 ranges)'); break }
    }

    return @{ Log = $log; AllowCount = $FinalAllowed.Count * $protos.Count; BlockCount = $complement.Count * $protos.Count }
}

# ---------------------------------------------------------------------------
# Orchestrator (v6.2 Apply flow, headless)
# ---------------------------------------------------------------------------

function Invoke-FwApplyGpo {
    <#
    .SYNOPSIS  Creates or updates the firewall GPO for an OU/port and (re)builds
               the managed rules. Returns a JSON-serializable result object.
    #>
    param(
        [string]$OuDn,
        [int]$Port,
        [bool]$PortIsAny,
        [string]$Protocol,      # TCP | UDP | Any
        [string]$Mode,          # specific | any | localsubnet
        [string[]]$Addresses,
        [bool]$BlockOthers,
        [bool]$SearchExisting = $true
    )
    Import-FwAdModules

    $log = New-Object System.Collections.Generic.List[string]
    $portToken = if ($PortIsAny) { 'Any' } else { "$Port" }

    # --- strict validation (second layer; the web backend validates too) ---
    if ([string]::IsNullOrWhiteSpace($OuDn)) { throw 'OU DN is empty.' }
    if (-not (Test-FwOuExists -Dn $OuDn)) { throw "OU not found: $OuDn" }
    if ($Protocol -notin @('TCP','UDP','Any')) { throw "Invalid protocol '$Protocol'." }
    if ($Mode -notin @('specific','any','localsubnet')) { throw "Invalid mode '$Mode'." }
    if (-not $PortIsAny -and ($Port -lt 1 -or $Port -gt 65535)) { throw "Port out of range 1-65535." }
    if ($Mode -eq 'specific') {
        if (-not $Addresses -or @($Addresses).Count -eq 0) { throw 'No addresses supplied for mode=specific.' }
        Test-AddressListStrict -Lines (@($Addresses)) | Out-Null
        $log.Add("Strict address validation OK ($($Addresses.Count) entries)")
    }

    $domainDns = (Get-ADDomain).DNSRoot

    # --- find or create GPO ---
    $existingGpo = $null
    if ($SearchExisting) {
        $existingGpo = Find-FwExistingGpoForPort -OuDn $OuDn -PortToken $portToken -Proto $Protocol
    }
    $gpoNameToUse = ''
    if ($existingGpo) {
        $gpoNameToUse = $existingGpo.DisplayName
        $log.Add("Reusing existing GPO: $gpoNameToUse")
    } else {
        $action = switch ($Mode) { 'any' { 'ANY' } 'localsubnet' { 'BLOCK-LOCALSUBNET' } default { 'ADD' } }
        $gpoNameToUse = Get-GpoName -OuDn $OuDn -PortToken $portToken -Proto $Protocol -Action $action
        $gpoNameToUse = $gpoNameToUse -replace '[\\/:*?"<>|]', '_'
        $log.Add("Creating new GPO: $gpoNameToUse")
    }

    $created = $false
    $gpoExists = Get-GPO -Name $gpoNameToUse -ErrorAction SilentlyContinue
    if (-not $gpoExists) {
        New-GPO -Name $gpoNameToUse -Domain $domainDns -ErrorAction Stop | Out-Null
        Update-FwGpoProfile -GpoName $gpoNameToUse
        try {
            New-GPLink -Name $gpoNameToUse -Target $OuDn -Domain $domainDns -LinkEnabled Yes -Enforced No -ErrorAction Stop | Out-Null
            $log.Add("GPO linked to $OuDn")
        } catch { $log.Add("GPLink warning: $($_.Exception.Message)") }
        $created = $true
    }

    # --- delete old managed rules for this port, rebuild ---
    $deletedOld = Remove-FwManagedRules -GpoName $gpoNameToUse -Port $Port -PortIsAny $PortIsAny
    $log.Add("Deleted $deletedOld old managed rule(s) for port $portToken and rebuilding")

    $allowCount = 0; $blockCount = 0
    if ($Mode -eq 'any') {
        $lport = Get-FwLportSegment -Port $Port -PortIsAny $PortIsAny
        $protos = @()
        if ($Protocol -in @('TCP','Any')) { $protos += [PSCustomObject]@{ Name = 'TCP'; Num = 6 } }
        if ($Protocol -in @('UDP','Any')) { $protos += [PSCustomObject]@{ Name = 'UDP'; Num = 17 } }
        foreach ($p in $protos) {
            $name = "Allow-FW-$($p.Name)-$portToken-Any"
            $str = "${script:FwRuleVer}|Action=Allow|Active=TRUE|Dir=In|Protocol=$($p.Num)|$lport RA4=Any|Name=Allow $($p.Name) $portToken Any|Desc=Any|EmbedCtxt=FW-ANY|"
            Set-GPRegistryValue -Name $gpoNameToUse -Key $script:FwFwKey -ValueName $name -Type String -Value $str | Out-Null
            $allowCount++
            $log.Add("Allow $($p.Name) $portToken from Any")
        }
    }
    elseif ($Mode -eq 'localsubnet') {
        $lport = Get-FwLportSegment -Port $Port -PortIsAny $PortIsAny
        $protos = @()
        if ($Protocol -in @('TCP','Any')) { $protos += [PSCustomObject]@{ Name = 'TCP'; Num = 6 } }
        if ($Protocol -in @('UDP','Any')) { $protos += [PSCustomObject]@{ Name = 'UDP'; Num = 17 } }
        foreach ($p in $protos) {
            $name = "Block-FW-$($p.Name)-$portToken-LocalSubnet"
            $str = "${script:FwRuleVer}|Action=Block|Active=TRUE|Dir=In|Protocol=$($p.Num)|$lport RA4=LocalSubnet|Name=Block $($p.Name) $portToken LocalSubnet|Desc=Block LocalSubnet|EmbedCtxt=FW-BLOCK-LOCAL|"
            Set-GPRegistryValue -Name $gpoNameToUse -Key $script:FwFwKey -ValueName $name -Type String -Value $str | Out-Null
            $blockCount++
            $log.Add("Block $($p.Name) $portToken from LocalSubnet")
        }
    }
    else {
        $list = @($Addresses)
        $res = Add-FwAllowAndBlockRules -GpoName $gpoNameToUse -Port $Port -PortIsAny $PortIsAny -Protocol $Protocol -FinalAllowed $list
        $allowCount = $res.AllowCount; $blockCount = $res.BlockCount
        foreach ($l in $res.Log) { $log.Add($l) }
    }

    # --- verification pass: read back what we wrote ---
    $readBack = Get-FwGpoRules -GpoName $gpoNameToUse -Port $Port -PortIsAny $PortIsAny
    $log.Add("Verification: $($readBack.Allows.Count) allow + $($readBack.Blocks.Count) block rule(s) present in GPO")

    return [PSCustomObject]@{
        GpoName   = $gpoNameToUse
        Created   = $created
        AllowCount = $allowCount
        BlockCount = $blockCount
        DeletedOld = $deletedOld
        ReadBackAllows = $readBack.Allows.Count
        ReadBackBlocks = $readBack.Blocks.Count
        Log      = $log
    }
}

Export-ModuleMember -Function `
    Get-FwDomainInfo, Test-FwIsDomainAdmin, `
    Get-FwAllOus, Test-FwOuExists, Get-FwAllGpos, Find-FwExistingGpoForPort, `
    Read-FwExistingAllowed, Get-FwGpoRules, Update-FwGpoProfile, `
    Remove-FwManagedRules, Add-FwAllowAndBlockRules, Invoke-FwApplyGpo
