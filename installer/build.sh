#!/usr/bin/env bash
# Builds FwGpoWeb-Setup-1.0.1.exe (NSIS installer) — works on Linux (cross-build)
# or Windows (makensis + dotnet on PATH).
set -euo pipefail
cd "$(dirname "$0")"

command -v dotnet >/dev/null 2>&1 || { echo "ERROR: dotnet (SDK 8) not on PATH"; exit 1; }
command -v makensis >/dev/null 2>&1 || { echo "ERROR: makensis (NSIS 3.x) not on PATH"; exit 1; }

VER="1.0.1"
echo "==> Cleaning staging/dist"
rm -rf staging dist
mkdir -p staging dist

echo "==> Publishing self-contained win-x64 app (this takes a while)"
dotnet publish ../backend/FwGpoWeb/FwGpoWeb.csproj -c Release -r win-x64 --self-contained true -o staging/app

echo "==> Staging PowerShell module + gMSA script"
mkdir -p staging/deploy
cp ../deploy/New-Gmsa.ps1 staging/deploy/New-Gmsa.ps1
mkdir -p staging/powershell
cp -r ../powershell/FwGpoBuilder staging/powershell/FwGpoBuilder

echo "==> Building NSIS installer"
makensis -V2 FwGpoWeb-Setup.nsi

echo ""
echo "OK: dist/FwGpoWeb-Setup-${VER}.exe"
ls -lh "dist/FwGpoWeb-Setup-${VER}.exe"
