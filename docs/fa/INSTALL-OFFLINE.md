# 📋 راهنمای گام‌به‌گام نصب — سرور بدون اینترنت (Air-Gapped)

> ### 🚀 ساده‌ترین راه آفلاین: نصب‌کننده EXE
> فایل **`FwGpoWeb-Setup-1.0.0.exe`** (از `installer/dist` یا با `installer/build.sh`
> ساخته‌شده) خودش اپ self-contained + اسکریپت‌ها را حمل می‌کند — یعنی **فقط یک فایل
> روی USB** کافی است (نیاز به publish جدا، ران‌تایم جدا و ISO برای .NET نیست):
>
> ```
> D:\FwGpoOffline\FwGpoWeb-Setup-1.0.0.exe
> ```
> ویزارد از شما فقط می‌پرسد: هویت سرویس، آدرس HTTPS سایت، گواهی (PFX یا self-signed)
> و در صورت نبودن RSAT روی سرور، درایو ISO مانت‌شده (Capability Source).
> در پایان ۱۰ راستی‌آزمایی را اجرا و گزارش PASS/FAIL نشان می‌دهد.
>
> ادامه این سند، راه دستی مرحله‌به‌مرحله است.

سناریو: سرور Windows Server 2025 **به اینترنت دسترسی ندارد**. همه فایل‌ها را از GitHub دانلود کرده‌ای و با USB می‌بری.

```
┌─────────────────────────┐      USB        ┌──────────────────────────┐
│  PC با اینترنت          │  ─────────────► │  سرور 2025 آفلاین         │
│  1) کد از GitHub        │                  │  + DC در دامنه داخلی      │
│  2) dotnet publish      │                  │  (DC به اینترنت نیاز     │
│  3) ران‌تایم + ISO       │                  │   ندارد — همه در دامنه)   │
└─────────────────────────┘                  └──────────────────────────┘
```

> 💡 نکته مهم: **DC و سرور وب هر دو داخل دامنه‌اند** — برای کار برنامه فقط DNS/Kerberos داخلی لازم است، اینترنت نه.

---

## فاز ۱ — روی PC با اینترنت (حدود ۲۰ دقیقه)

### ۱.۱ کد را از GitHub بگیر
```
https://github.com/arefkarami1990/FirewallWebApp  →  Code → Download ZIP
```
(تو همین کار را کرده‌ای ✅)

### ۱.۲ .NET 8 SDK را روی PC نصب کن
- از [dotnet.microsoft.com/download/dotnet/8.0](https://dotnet.microsoft.com/download/dotnet/8.0)
- **SDK** (نه Runtime) — نسخه 8.0.x Windows x64
- بعد از نصب در PowerShell: `dotnet --list-sdks`

### ۱.۳ ساخت نسخه publish (یک‌بار، روی PC)
PowerShell، داخل پوشه اکسترکت‌شده:
```bat
cd C:\path\to\FirewallWebApp
dotnet publish backend\FwGpoWeb\FwGpoWeb.csproj -c Release -o .\publish
```
✅ بررسی: فایل `publish\FwGpoWeb.dll` باید وجود داشته باشد

### ۱.۴ دانلود ران‌تایم برای سرور (آفلاین)
- از همان صفحه: **ASP.NET Core Runtime 8.0.x → Windows x64 → Installer (.exe)**
- فایل `aspnetcore-runtime-8.0.x-win-x64.exe` (حدود 35MB)

### ۱.۵ (فقط اگر سرور IIS/RSAT ندارد) ISO ویندوز
- ISO **Windows Server 2025** را دانلود کن (برای منبع آفلاین featureها)

### ۱.۶ (اختیاری) گواهی TLS
- اگر PKI داخلی داری: گواهی با SAN = FQDN سایت را صادر و PFX را بردار
- اگر نه: در فاز ۳ روی سرور خودت self-signed می‌سازی

### ۱.۷ همه‌چیز را روی USB بزن
```
FwGpoOffline\
├── FirewallWebApp\          (کل رپو)
├── publish\                 (خروجی مرحله ۱.۳ — داخل رپو هم هست)
├── aspnetcore-runtime-8.0.x-win-x64.exe
└── windows-server-2025.iso  (اختیاری)
```

---

## فاز ۲ — روی DC (حدود ۱۰ دقیقه — DC در دامنه است، اینترنت نمی‌خواهد)

### ۲.۱ پوشه deploy را روی DC بیاور
فقط پوشه `FirewallWebApp\deploy` را کپی کن.

### ۲.۲ ساخت gMSA
PowerShell **Admin** روی DC:
```powershell
cd C:\path\to\deploy
.\New-Gmsa.ps1 -GmsaName FWGPO -SpnHost fwgpo.yourdomain.local -GrantDomainAdmin
```
- `-SpnHost`: FQDN سایت (همینی که کاربر در مرورگر می‌بینه)
- خروجی باید شامل این باشد:
  ```
  ==> KDS root key present.
  ==> Creating AD service account 'FWGPO.yourdomain.local'
  ==> Installing gMSA on ...
  ==> Adding FWGPO to 'Domain Admins'
  DONE.
  ```

### ۲.۳ صبر برای replication (یا اجباری)
```powershell
repadmin /syncall /APD
```

> 🔄 **اگر به‌جای gMSA، کاربر دامین ادمین می‌خواهی:** فاز ۲ را رد کن و در مرحله ۳.۴ به‌جای `CORP\FWGPO$` اسم کاربر (مثل `CORP\jdoe`) را بده. (برای کاربر دامین، «Log on as a batch job» لازم است که معمولاً برای Authenticated Users فعال است.)

---

## فاز ۳ — روی سرور وب آفلاین (حدود ۲۰ دقیقه)

### ۳.۱ پیش‌نیازها (روی سرور)
| مورد | وضعیت مورد نیاز |
|---|---|
| دامین‌جویند | ✅ باید باشد |
| DNS | رکورد A برای FQDN سایت (مثل `fwgpo.yourdomain.local`) |
| گواهی TLS | اگر PFX داری: `Import-PfxCertificate -FilePath D:\cert.pfx -CertStoreLocation Cert:\LocalMachine\My` و Thumbprint را یادداشت کن |

### ۳.۲ نصب ران‌تایم .NET 8 (از USB)
```powershell
D:\FwGpoOffline\aspnetcore-runtime-8.0.x-win-x64.exe /quiet /norestart
dotnet --list-runtimes   # → Microsoft.AspNetCore.App 8.0.x باید بیاید
```

### ۳.۳ (فقط اگر IIS/RSAT نیست) نصب آفلاین از ISO
ISO را mount کن (فرض کن درایو `E:`):
```powershell
# IIS + Windows Authentication
Install-WindowsFeature Web-Server, Web-Common-Http, Web-Static-Content, Web-Default-Doc, Web-Http-Errors, Web-Log-Libraries, Web-Request-Filters, Web-Stat-Logging, Web-Mgmt-Console, Web-Mgmt-Service, Web-Http-Compression, IIS-WindowsAuth -Source E:\sources\sxs -LimitAccess

# RSAT: Group Policy + AD PowerShell (نیاز لایه DC)
Add-WindowsCapability -Online -Name Rsat.GroupPolicy.Management~~~~0.0.1.0 -Source E:\ -LimitAccess
Add-WindowsCapability -Online -Name Rsat.AdPowerShell~~~~0.0.1.0 -Source E:\ -LimitAccess
```
اگر IIS/RSAT از قبل نصب است، اسکرپت نصب خودکار این مرحله را رد می‌کند.

### ۳.۴ اجرای نصب
PowerShell **Admin**، روی سرور:
```powershell
cd D:\FwGpoOffline\FirewallWebApp\deploy

.\Install-FwGpoWeb.ps1 `
  -ServiceIdentity "CORP\FWGPO$" `
  -AppUrl "https://fwgpo.yourdomain.local" `
  -CertThumbprint <THUMBPRINT_مرحله_3.1> `
  -PublishDir "D:\FwGpoOffline\FirewallWebApp\publish"
```
(اگر IIS/RSAT را دستی از ISO نصب **نموده‌ای** و نبودند، این دو پارامتر را هم بده:
`-FeatureSource "E:\sources\sxs" -CapabilitySource "E:\"`)

خروجی مورد انتظار (آخر اسکریپت):
```
==> Smoke test: GET /api/health
    200: {"status":"ok","version":"1.0.0"}
DONE.
```

### ۳.۵ راستی‌آزمایی
```powershell
.\Verify-Deployment.ps1 -ServiceIdentity "CORP\FWGPO$" -AppUrl "https://fwgpo.yourdomain.local"
```
🎯 هدف: **همه PASS** (ران‌تایم، ماژول‌ها، gMSA، App Pool، سایت، Windows Auth، ACL، health، ping DC)

---

## فاز ۴ — اولین ورود (روی PC کاربر، در دامنه)

### ۴.۱ مرورگر
- Edge/Chrome روی ویندوز **دامین‌جویند**
- سایت باید در زون **Intranet** باشد (وگرنه SSO خودکار نمی‌شود):
  - Edge: `edge://settings/cookies` → *Manage and delete cookies and site data* → یا از IE Classic: Internet Options → Security → Intranet → Sites → Advanced → افزودن `https://fwgpo.yourdomain.local`
- باز کن: `https://fwgpo.yourdomain.local`

### ۴.۲ SSO خودکار
- بدون پرامپت اسم/گذرواژه باید وارد شد (Kerberos)
- صفحه «Two-factor verification» ظاهر می‌شود

### ۴.۳ ثبت MFA (یک‌بار)
دکمه **MFA Setup**:
- **📱 TOTP:** QR را با Google Authenticator / Authy / 1Password اسکن کن → کد ۶ رقمی را بزن → ثبت شد
- **🔑 FIDO2/فینگرپرینت:** **Register credential** → کلید امنیتی را لمس کن یا **اثر انگشت Windows Hello** را ثبت کن

### ۴.۴ ورود روزمره
`https://fwgpo.yourdomain.local` → SSO خودکار → **اثر انگشت / TOTP** → کنسول GPO Builder

### ۴.۵ ساخت اولین پالیسی
1. **OU** را انتخاب کن (Browse AD)
2. پورت/پروتکل (یا Preset مثل RDP 3389)
3. **Search & load IPs** (الزامی — IPهای قبلی لواد می‌شوند)
4. IPهای مجاز را ویرایش/افزود
5. **Validate** → **Apply** (پس از تأیید)
6. در `gpmc.msc` (Group Policy Management) GPO را ببین و قوانین Allow + Block مکمل را چک کن

---

## عیب‌یابی رایج

| مشکل | علت / راه‌حل |
|---|---|
| مرورگر پرامپت می‌دهد به‌جای SSO خودکار | سایت در زون Intranet نیست یا HTTPS نیست |
| `401 SSO_REQUIRED` مدام تکرار می‌شود | SPN تکراری: روی DC بزن `setspn -X`؛ یا `SpnHost` با FQDN سایت یکی نیست |
| `gMSA logon failed` / برنامه بالا نمی‌آید | روی سرور: `Test-ADServiceAccount -Identity FWGPO` — replication صبر کن یا `repadmin /syncall /APD` |
| `GroupPolicy module not available` | RSAT GroupPolicy نصب نشده (مرحله ۳.۳) |
| `Access is denied` هنگام Apply | هویت سرویس دسترسی ندارد — gMSA/کاربر باید در گروه مجاز باشد (مرحله ۲.۲) |
| FIDO2/فینگرپرینت کار نمی‌کند | **فقط HTTPS** — و `AppUrl` باید کاراکتر به کاراکتر با نوار مرورگر یکی باشد |
| `Verify` روی App Pool FAIL | `IIS:\AppPools\FwGpoWebPool` → Identity را دستی `CORP\FWGPO$` کن |

## پشتیبان‌بندی (مهم)

هر هفته `C:\ProgramData\FwGpoWeb` را backup بگیر:
- `secrets\users.json.enc` — secret TOTP + اعتبارال‌های FIDO2 (با DPAPI رمزنگاری شده — **فقط روی همان سرور/دامنه باز می‌شود**)
- `audit\*.jsonl` — لاگ‌های امنیتی
- `dataprotection-keys\` — کلیدهای نشست/کوکی (بدون این، همه نشست‌ها باطل می‌شوند)

## حذف کامل

```powershell
.\Uninstall-FwGpoWeb.ps1 -RemoveGmsa FWGPO -RemoveData
```
