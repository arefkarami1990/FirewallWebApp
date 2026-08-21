#requires -Version 5.1
<#
.SYNOPSIS
    Invoke-FwGpoOp.ps1 - JSON CLI entry point for FwGpoBuilder.

.DESCRIPTION
    Called by the FwGpoWeb backend as:
        powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File Invoke-FwGpoOp.ps1 -RequestFile <req.json> -ResponseFile <resp.json>

    Request JSON:  { "op": "<name>", "params": { ... } }
    Response JSON: { "ok": true,  "data": <object> }
                    { "ok": false, "error": "<message>" }

    SECURITY: user-controlled values are passed only through the request
    JSON file (never on the command line). No Invoke-Expression is used.
    The process identity is the service identity (GMSA or domain user).
#>

param(
    [Parameter(Mandatory)][string]$RequestFile,
    [Parameter(Mandatory)][string]$ResponseFile
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Write-FwResponse {
    param([bool]$Ok, $Data, [string]$Error)
    $obj = [ordered]@{ ok = $Ok }
    if ($Ok) { $obj.data = $Data } else { $obj.error = $Error }
    $json = $obj | ConvertTo-Json -Depth 12 -Compress
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ResponseFile, $json, $utf8NoBom)
}

function Get-JsonParam {
    param($Obj, [string]$Name, $Default = $null)
    if ($null -eq $Obj) { return $Default }
    $psobj = [psobject]$Obj
    if ($psobj.Properties -and ($psobj.Properties.Name -contains $Name)) { return $Obj.$Name }
    return $Default
}

function To-StringArray {
    param($Value)
    if ($null -eq $Value) { return @() }
    if ($Value -is [string]) { return @($Value) }
    return @($Value)
}

try {
    if (-not (Test-Path -LiteralPath $RequestFile -PathType Leaf)) {
        throw "Request file not found."
    }
    $raw = Get-Content -LiteralPath $RequestFile -Raw -Encoding UTF8
    $req = $raw | ConvertFrom-Json
    $op = ((Get-JsonParam $req 'op' '') -as [string]).Trim().ToLowerInvariant()
    $p = $req.params

    Import-Module (Join-Path $PSScriptRoot 'FwGpoBuilder.psm1') -DisableNameChecking

    function Import-FwAd {
        try {
            Import-Module (Join-Path $PSScriptRoot 'FwGpoBuilder.ad.psm1') -DisableNameChecking -ErrorAction Stop
        } catch {
            throw "AD/GPO operations are unavailable on this host: $($_.Exception.Message)"
        }
    }

    $data = $null
    switch ($op) {
        'ping-dc' {
            Import-FwAd
            $data = Get-FwDomainInfo
        }
        'whoami' {
            Import-FwAd
            $id = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $data = [PSCustomObject]@{ Identity = $id; IsDomainAdmin = (Test-FwIsDomainAdmin -Identity $id) }
        }
        'resolve-user' {
            Import-FwAd
            $upn = (Get-JsonParam $p 'upn' '') -as [string]
            $groups = To-StringArray (Get-JsonParam $p 'groups' @())
            $data = Get-FwResolveUser -Upn $upn -AdminGroups $groups
        }
        'list-ous' {
            Import-FwAd
            $limit = [int](Get-JsonParam $p 'limit' 5000)
            $data = [PSCustomObject]@{ Ous = @(Get-FwAllOus -Limit $limit) }
        }
        'test-ou' {
            Import-FwAd
            $dn = (Get-JsonParam $p 'dn' '') -as [string]
            $data = [PSCustomObject]@{ Exists = (Test-FwOuExists -Dn $dn) }
        }
        'list-gpos' {
            Import-FwAd
            $data = [PSCustomObject]@{ Gpos = @(Get-FwAllGpos) }
        }
        'search-gpo' {
            Import-FwAd
            $ouDn = (Get-JsonParam $p 'ouDn' '') -as [string]
            $port = [int](Get-JsonParam $p 'port' 0)
            $portIsAny = [bool](Get-JsonParam $p 'portIsAny' $false)
            $proto = (Get-JsonParam $p 'protocol' 'TCP') -as [string]
            if ([string]::IsNullOrWhiteSpace($ouDn)) { throw 'ouDn is required.' }
            if (-not (Test-FwOuExists -Dn $ouDn)) { throw "OU not found: $ouDn" }
            if ($proto -notin @('TCP','UDP','Any')) { throw "Invalid protocol '$proto'." }
            if (-not $portIsAny -and ($port -lt 1 -or $port -gt 65535)) { throw 'Port out of range 1-65535.' }
            $portToken = if ($portIsAny) { 'Any' } else { "$port" }
            $found = Find-FwExistingGpoForPort -OuDn $ouDn -PortToken $portToken -Proto $proto
            if ($found) {
                $existing = Read-FwExistingAllowed -GpoName $found.DisplayName -Port $port -PortIsAny $portIsAny -Protocol $proto
                $data = [PSCustomObject]@{ Found = $true; GpoName = $found.DisplayName; Existing = @($existing) }
            } else {
                $data = [PSCustomObject]@{ Found = $false; GpoName = $null; Existing = @() }
            }
        }
        'gpo-rules' {
            Import-FwAd
            $gpoName = (Get-JsonParam $p 'gpoName' '') -as [string]
            $port = [int](Get-JsonParam $p 'port' 0)
            $portIsAny = [bool](Get-JsonParam $p 'portIsAny' $false)
            if ([string]::IsNullOrWhiteSpace($gpoName)) { throw 'gpoName is required.' }
            $data = Get-FwGpoRules -GpoName $gpoName -Port $port -PortIsAny $portIsAny
        }
        'apply' {
            Import-FwAd
            $ouDn = (Get-JsonParam $p 'ouDn' '') -as [string]
            $port = [int](Get-JsonParam $p 'port' 0)
            $portIsAny = [bool](Get-JsonParam $p 'portIsAny' $false)
            $proto = (Get-JsonParam $p 'protocol' 'TCP') -as [string]
            $mode = (Get-JsonParam $p 'mode' 'specific') -as [string]
            $addresses = To-StringArray (Get-JsonParam $p 'addresses' @())
            $blockOthers = [bool](Get-JsonParam $p 'blockOthers' $true)
            $searchExisting = [bool](Get-JsonParam $p 'searchExisting' $true)
            $data = Invoke-FwApplyGpo -OuDn $ouDn -Port $port -PortIsAny $portIsAny -Protocol $proto -Mode $mode -Addresses $addresses -BlockOthers $blockOthers -SearchExisting $searchExisting
        }
        default {
            throw "Unknown op '$op'."
        }
    }
    Write-FwResponse $true $data ''
}
catch {
    # Never leak stack traces / internal paths to the web client.
    Write-FwResponse $false $null $_.Exception.Message
}
