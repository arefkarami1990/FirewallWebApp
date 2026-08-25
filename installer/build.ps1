# Builds FwGpoWeb-Setup-1.0.2.exe (NSIS installer) on Windows.
# Requires: .NET 8 SDK + NSIS 3.x (makensis on PATH).
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

$null = Get-Command dotnet -ErrorAction Stop
$null = Get-Command makensis -ErrorAction Stop

$ver = '1.0.2'

Write-Host "==> Cleaning staging/dist" -ForegroundColor Cyan
Remove-Item -Recurse -Force staging, dist -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force staging, dist | Out-Null

Write-Host "==> Publishing self-contained win-x64 app" -ForegroundColor Cyan
dotnet publish (Join-Path $PSScriptRoot '..\backend\FwGpoWeb\FwGpoWeb.csproj') -c Release -r win-x64 --self-contained true -o (Join-Path $PSScriptRoot 'staging\app')
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Write-Host "==> Staging PowerShell module + gMSA script" -ForegroundColor Cyan
New-Item -ItemType Directory -Force (Join-Path $PSScriptRoot 'staging\deploy') | Out-Null
Copy-Item (Join-Path $PSScriptRoot '..\deploy\New-Gmsa.ps1') (Join-Path $PSScriptRoot 'staging\deploy\New-Gmsa.ps1')
New-Item -ItemType Directory -Force (Join-Path $PSScriptRoot 'staging\powershell') | Out-Null
Copy-Item -Recurse (Join-Path $PSScriptRoot '..\powershell\FwGpoBuilder') (Join-Path $PSScriptRoot 'staging\powershell\FwGpoBuilder')

Write-Host "==> Building NSIS installer" -ForegroundColor Cyan
makensis -V2 (Join-Path $PSScriptRoot 'FwGpoWeb-Setup.nsi')
if ($LASTEXITCODE -ne 0) { throw "makensis failed" }

$out = Join-Path $PSScriptRoot "dist\FwGpoWeb-Setup-$ver.exe"
Write-Host ""
Write-Host "OK: $out" -ForegroundColor Green
Get-Item $out | Format-List Name, Length, LastWriteTime
