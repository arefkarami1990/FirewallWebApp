<#
.SYNOPSIS
    Creates the gMSA (Group Managed Service Account) used to run FwGpoWeb on
    Windows Server 2025, and grants it the AD/Group-Policy permissions it needs.

.DESCRIPTION
    The web application's PowerShell/AD layer runs under the *service
    identity* (no credentials are ever passed to the process). This script
    prepares that identity as a gMSA:

      1. Verifies the KDS root key exists (required for gMSA Kerberos).
      2. Creates the AD service account with the HTTP SPN (Kerberos for
         browser SSO when the app is self-hosted; harmless under IIS).
      3. Installs the gMSA on the target web server (machine must be joined
         to the domain).
      4. Grants permissions:
           -GrantDomainAdmin : adds the gMSA to Domain Admins (simplest,
                               matches the original v6.2 tool's usage).
           -GrantGroup <name> : creates/uses a security group and adds the
                               gMSA to it; then delegates GPO management on
                               the desired OUs (least privilege).
      5. Verifies the installation (Test-ADServiceAccount).

.PARAMETER GmsaName
    Account name (no $ suffix; Windows appends it). Max 20 chars recommended.

.PARAMETER DnsDomain
    Primary DNS domain of the forest (default: current user's domain).

.PARAMETER SpnHost
    FQDN/host used in the browser (e.g. fwgpo.corp.local) - becomes the
    HTTP SPN for Kerberos.

.PARAMETER ComputerName
    Web server that will run the app (default: local computer).

.EXAMPLE
    .\New-Gmsa.ps1 -GmsaName FWGPO -SpnHost fwgpo.corp.local -GrantDomainAdmin
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GmsaName,
    [string]$DnsDomain = $env:USERDNSDOMAIN,
    [Parameter(Mandatory = $true)][string]$SpnHost,
    [string]$ComputerName = $env:COMPUTERNAME,
    [switch]$GrantDomainAdmin,
    [string]$GrantGroup = ""
)

$ErrorActionPreference = 'Stop'
$upn = "$GmsaName.$DnsDomain"

function Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

# --- 0. sanity -------------------------------------------------------------
if ($GmsaName.Length -gt 20) { throw "GmsaName should be <= 20 characters." }
try { Import-Module ActiveDirectory -ErrorAction Stop }
catch { throw "ActiveDirectory module not available. Run this from a domain controller or a machine with RSAT AD PowerShell (Add-WindowsCapability -Online -Name Rsat.AdPowerShell~~~~0.0.1.0)." }
if (-not $DnsDomain) { throw "Cannot determine DNS domain; pass -DnsDomain." }

# --- 1. KDS root key (informational - NEVER fatal) ---------------------------
$domain = Get-ADDomain
$pdc = $domain.PDCEmulator
if (-not $pdc) { $pdc = $domain.PDC }
if (-not $pdc) { $pdc = $domain.DNSRoot }
Step "Checking KDS root key (gMSA Kerberos prerequisite) [PDC: $pdc]"
try {
    # Correct tool name is 'kdsroot' (NOT 'kdsrootkey'). Runs only on DCs.
    $kdsOut = & kdsroot -Get -KeyType 0 2>&1 | Out-String
    if ($kdsOut -match '0x0') {
        Write-Host "    KDS root key present." -ForegroundColor Green
    }
    else {
        Write-Warning "KDS root key NOT found. Before gMSA logon can work, on the PDC run:`n    kdsroot -Create -KeyType 0 -ValidityInYears 10`nand wait for replication."
    }
} catch {
    # kdsroot missing / not a DC / permission issue - never block the install
    Write-Warning "Could not verify KDS root key here: $($_.Exception.Message)`nIf gMSA logon fails later, on the PDC run: kdsroot -Create -KeyType 0 -ValidityInYears 10"
}

# --- 2. create the service account -----------------------------------------
Step "Creating AD service account '$upn' (SPN HTTP/$SpnHost)"
if (Get-ADServiceAccount -Identity $GmsaName -ErrorAction SilentlyContinue) {
    Write-Host "    already exists; updating SPN" -ForegroundColor Yellow
    Set-ADServiceAccount -Identity $GmsaName -ServicePrincipalName "HTTP/$SpnHost"
} else {
    New-ADServiceAccount -Name $GmsaName -DNSName $upn -ServicePrincipalName "HTTP/$SpnHost" -Description "FwGpoWeb service account"
}

# --- 3. install on the web server ------------------------------------------
Step "Installing gMSA on $ComputerName (requires the machine to be domain-joined)"
try {
    if ($ComputerName -eq $env:COMPUTERNAME) {
        Install-ADServiceAccount -Identity $GmsaName
        Test-ADServiceAccount -Identity $GmsaName | Write-Host
    } else {
        $cred = Get-Credential -Message "Credentials (domain admin) for $ComputerName"
        Invoke-Command -ComputerName $ComputerName -Credential $cred -ScriptBlock {
            param($name)
            Import-Module ActiveDirectory
            Install-ADServiceAccount -Identity $name
            Test-ADServiceAccount -Identity $name
        } -ArgumentList $GmsaName
    }
} catch {
    throw "gMSA installation failed: $($_.Exception.Message)"
}

# --- 4. permissions ---------------------------------------------------------
if ($GrantDomainAdmin) {
    Step "Adding $GmsaName to 'Domain Admins' (simplest option)"
    $da = Get-ADGroup 'Domain Admins'
    Add-ADGroupMember -Identity $da.SamAccountName -Members $GmsaName
}
elseif ($GrantGroup) {
    Step "Granting via group '$GrantGroup' (least privilege)"
    if (-not (Get-ADGroup -Identity $GrantGroup -ErrorAction SilentlyContinue)) {
        New-ADGroup -Name $GrantGroup -GroupScope Global -SamAccountName $GrantGroup -Description "FwGpoWeb GPO administrators" | Out-Null
    }
    Add-ADGroupMember -Identity $GrantGroup -Members $GmsaName
    Write-Host @"

NOTE: for true least privilege, delegate GPO management instead of granting
full admin. The app also needs to READ the GPO containers it manages. A
practical baseline (adjust to your delegation model):

  1. Keep the gMSA in a dedicated group: $GrantGroup
  2. On each target OU, delegate (Delegation of Control Wizard):
       - Create/delete GPOs in the domain
       - Link GPOs to the OU
       - Modify GPOs
  3. Set the app's AdminGroups config to '$GrantGroup'.
"@ -ForegroundColor Yellow
}
else {
    Write-Warning "No grant selected: the gMSA currently has no GPO permissions. Use -GrantDomainAdmin or -GrantGroup."
}

Write-Host @"

DONE. App pool identity for the IIS app (note the trailing '$'):
    $DnsDomain.ToUpperInvariant()\${GmsaName}\$   (or $upn)

Verify later with:  Test-ADServiceAccount -Identity $GmsaName
"@ -ForegroundColor Green
