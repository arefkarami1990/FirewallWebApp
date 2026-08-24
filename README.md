# FwGpoWeb — Firewall GPO Web Console

Web-based successor of **Firewall GPO Builder v6.2** for **Windows Server 2025**:
builds Windows-Firewall GPOs (allow lists + block-everything-else complement,
strict no-overlap) against your domain controller, with enterprise-grade auth:

- **Windows SSO** (Kerberos / NTLM) — no passwords in the browser
- **MFA mandatory**: TOTP (QR) **and** FIDO2/WebAuthn (**fingerprint** via Windows Hello, security keys, Face)
- **Admin group** gate (default `Domain Admins`)
- Runs the DC/Group-Policy layer as a **gMSA** or a **domain admin user** (the service identity — no credentials are ever transmitted)
- Defense-in-depth input validation (C# **and** PowerShell), file-based PowerShell bridge (no command-line injection surface), DataProtection-encrypted user secrets, append-only audit log + Event Log, hardened CSP/headers, rate limiting, MFA lockout

Persian docs: [`docs/fa/DEPLOYMENT.md`](docs/fa/DEPLOYMENT.md) · [`docs/fa/SECURITY.md`](docs/fa/SECURITY.md) · [Pentest report](docs/PENTEST-REPORT.md)

## Layout

```
backend/FwGpoWeb          ASP.NET Core 8 web app (API + SPA frontend in wwwroot/)
backend/FwGpoWeb.Tests    xUnit unit tests (TOTP RFC vectors, validation, lockout, GPO service)
powershell/FwGpoBuilder   FwGpoBuilder.psm1 (pure IP/range/GPO-name logic, v6.2 semantics)
                          FwGpoBuilder.ad.psm1 (AD/GPO operations) + Invoke-FwGpoOp.ps1 (JSON CLI)
powershell/Tests          80-test PowerShell suite (runs on any PowerShell, incl. Linux)
deploy/                   New-Gmsa.ps1 · Install-FwGpoWeb.ps1 · Verify-Deployment.ps1 · Uninstall-FwGpoWeb.ps1
tests/pentest/pentest.py  52-test E2E + penetration suite (incl. a software FIDO2 authenticator)
docs/                     deployment (fa), security model (fa), pentest report
```

## Quick start (dev / mock, no AD needed)

```bash
# Linux/macOS/Windows with .NET 8 SDK
cd backend/FwGpoWeb
ASPNETCORE_ENVIRONMENT=Mock dotnet run     # or: dotnet run --launch-profile http
# open http://localhost:5000
```

Mock mode simulates SSO (as `admin@corp.local`) and a small AD (4 OUs, 1 seeded GPO)
so the whole stack — including the real WebAuthn ceremony — is exercisable offline.

## Run the test suites

```bash
# C# unit tests (64)
cd backend && dotnet test

# PowerShell core-logic tests (80) — any pwsh 7+ / Windows PowerShell 5.1
pwsh powershell/Tests/Run-Tests.ps1

# E2E + pentest (52) — server must be running in Mock mode
ASPNETCORE_ENVIRONMENT=Mock dotnet run   # then in another shell:
python3 tests/pentest/pentest.py

# Deploy-script scenarios (46) — simulated Windows server, any OS
pwsh tests/deploy/Run-DeployScriptTests.ps1
```

**Total: 295 automated tests (71 C# unit + 80 PowerShell core + 88 deploy/installer
scenarios + 56 E2E/pentest, incl. a real Kestrel HTTPS/PFX test). All green as of
2026-08-24 — see [docs/PENTEST-REPORT.md](docs/PENTEST-REPORT.md).**

## Installation — one-click installer (recommended)

**`installer/`** builds a single self-contained EXE — `FwGpoWeb-Setup-1.0.1.exe` — that runs the whole installation:

```
FwGpoWeb-Setup-1.0.1.exe                       ; wizard (service identity, App URL, cert, gMSA)
FwGpoWeb-Setup-1.0.1.exe /S /ServiceIdentity=CORP\FWGPO$ /AppUrl=https://fwgpo.corp.local
```

What it does in one pass:
1. (optional) creates the **gMSA** with the correct SPN + Domain Admins grant
2. installs the **self-contained .NET 8 app** (no runtime download — works air-gapped;
   RSAT is installed from a mounted ISO via the *Capability Source* field when missing)
3. provisions the **HTTPS certificate** as PFX inside the ACL-restricted data dir
   (your PFX, a store cert by thumbprint, or a generated self-signed for dev)
4. registers + starts the **Windows service** under your identity (gMSA$ or domain user)
5. runs the **full verification** (10 checks) and shows a PASS/FAIL report

Architecture of the standalone mode: **Kestrel self-hosted + Windows Service + native
Kerberos SSO (Negotiate handler)** — no IIS, no ASP.NET Core Module. The IIS path
(`deploy/Install-FwGpoWeb.ps1`) remains available for IIS-based deployments.

Rebuild the installer (Linux or Windows, needs .NET 8 SDK + NSIS 3):
```bash
cd installer && ./build.sh        # or: .\build.ps1  on Windows
```

Full guides:
- Online: [docs/fa/DEPLOYMENT.md](docs/fa/DEPLOYMENT.md)
- **Offline / air-gapped (server without internet):** [docs/fa/INSTALL-OFFLINE.md](docs/fa/INSTALL-OFFLINE.md)

## Deploy to Windows Server 2025

```powershell
# 1) on the DC (or RSAT machine): create the gMSA
deploy\New-Gmsa.ps1 -GmsaName FWGPO -SpnHost fwgpo.corp.local -GrantDomainAdmin

# 2) on the web server (elevated):
deploy\Install-FwGpoWeb.ps1 -ServiceIdentity "CORP\FWGPO$" -AppUrl "https://fwgpo.corp.local" -CertThumbprint <thumb>

# 3) verify
deploy\Verify-Deployment.ps1 -ServiceIdentity "CORP\FWGPO$" -AppUrl "https://fwgpo.corp.local"
```

To run under a **domain admin user** instead of a gMSA: skip step 1 and pass
`-ServiceIdentity "CORP\jdoe"`. Full guide: [docs/fa/DEPLOYMENT.md](docs/fa/DEPLOYMENT.md).

## API (all under /api, JSON)

| Method & path | Gate | Purpose |
|---|---|---|
| `GET  /api/health` | open | liveness |
| `GET  /api/health/diag` | admin | DC ping + service identity |
| `GET  /api/auth/status` | open | SSO/MFA/admin state |
| `GET  /api/auth/sso` | open | SSO handshake (401 challenge) |
| `GET  /api/auth/csrf` | auth | antiforgery token |
| `GET  /api/auth/totp/setup` | auth | TOTP secret + QR |
| `POST /api/auth/totp/confirm` | auth | verify + enroll TOTP |
| `GET  /api/auth/fido/register/begin` | auth | WebAuthn registration options |
| `POST /api/auth/fido/register/complete` | auth | store credential |
| `GET  /api/auth/fido/list` · `DELETE /api/auth/fido/{id}` | auth | manage credentials |
| `GET  /api/auth/fido/mfa/begin` | auth | WebAuthn assertion options |
| `POST /api/auth/mfa/complete` | auth | **complete MFA (totp or webauthn)** |
| `GET  /api/auth/logout` | open | end session |
| `GET  /api/ad/ous` · `GET /api/ad/ou/check?dn=` | admin | OU discovery |
| `GET  /api/gpo/list` | admin | list GPOs |
| `POST /api/gpo/search` | admin | find existing GPO for OU/port + load IPs |
| `POST /api/gpo/apply` | admin | **create/update GPO + rebuild rules** |
| `GET  /api/gpo/rules` | admin | read back allow/block rules |
| `GET  /api/audit?limit=` | admin | recent audit entries |
