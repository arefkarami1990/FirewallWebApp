# راهنمای استقرار FwGpoWeb روی Windows Server 2025

این برنامه کنسول وب برای ساخت/ویرایش **پالیسی‌های فایروال ویندوز به صورت GPO** است (محوصله‌سازی وبی‌س ابزار «Firewall GPO Builder v6.2»).
ارتباط با DC از طریق ماژول PowerShell (ActiveDirectory + GroupPolicy) و با **هویت سرویس** (gMSA یا کاربر دامین ادمین) برقرار می‌شود.

---

## ۱. معماری

```
مرورگر (ویندوز دامین‌جویند، زون Intranet)
   │  Kerberos SSO  +  MFA (TOTP / FIDO2)
   ▼
IIS (Windows Authentication)  ──►  ASP.NET Core 8 (FwGpoWeb)
                                       │
            ┌──────────────────────────┼────────────────────────────┐
            ▼                          ▼                            ▼
      Session + کوکی         PowerShell Bridge (فرآیند جدا)      DataProtection
      (DataProtection)       powershell.exe -File Invoke-…ps1     (کلیدهای رمزنگاری)
            │                          │
            │                          ▼  (با هویت App Pool: gMSA$ یا دامین‌یوزر)
            │                 DC: GroupPolicy / ActiveDirectory
            ▼
      C:\ProgramData\FwGpoWeb  (کلیدهای کاربر، FIDO2، لاگ‌های audit — ACL محدود)
```

نکته‌های کلیدی:
- **هیچ گذرواژه‌ای در هیچ‌جا عبور نمی‌کند.** هویت DC = هویت فرآیند سرویس.
- ورودی‌های کاربر **دو لایه** اعتبارسنجی می‌شوند: (۱) C# در بک‌اند، (۲) PowerShell روی سرور. هیچ‌وقت از طریق command-line به PowerShell نمی‌رسند (فقط فایل JSON).
- **SSO** با Kerberos (handler Negotiate / Windows Auth در IIS).
- **MFA** اجباری است: TOTP (QR + اپلیکیشن احراز) و یا **FIDO2/WebAuthn** (کلید امنیتی، **اثر انگشت** Windows Hello، Face).
- دسترسی نهایی: عضویت در گروه ادمین (پیش‌فرض `Domain Admins`، قابل تنظیم در `AdminGroups`).

---

## ۲. پیش‌نیازها

| مورد | توضیح |
|---|---|
| سرور | Windows Server 2022 یا 2025، دامین‌جویند، دسترسی ادمین |
| DC | دسترسی از سرور وب به DC (LDAP 389 / Kerberos) |
| مرورگر کاربر | ویندوز دامین‌جویند، سایت در زون **Intranet** باشد (برای SSO بدون پرامپت) |
| TLS | گواهی با SAN = دامنه سایت (برای SSO و WebAuthn، HTTPS الزامی است؛ در WebAuthn فقط HTTPS معتبر است) |
| گواهی | Self-signed برای تست قابل است، ولی برای تولید حتماً گواهی معتبر |

> مرورگر فقط از **HTTPS** به WebAuthn دسترسی دارد؛ بنابراین SSO + FIDO2 در عمل الزامی به HTTPS دارند.

## ۳. گام‌به‌گام

> ### ⚡ راه پیشنهادی: نصب‌کننده یک‌کلیک (EXE)
> فایل `FwGpoWeb-Setup-1.0.2.exe` (در `installer/dist` یا ساخته‌شده با `installer/build.sh`)
> **تمام مراحل ۱ تا ۴ را در یک اجرا** انجام می‌دهد:
>
> ```
> FwGpoWeb-Setup-1.0.2.exe        (ویزارد: هویت سرویس، آدرس سایت، گواهی، ساخت gMSA)
> ```
> یا ساکنت (بدون رابط گرافیکی):
> ```
> FwGpoWeb-Setup-1.0.2.exe /S /ServiceIdentity=CORP\FWGPO$ /AppUrl=https://fwgpo.corp.local [/CreateGmsa=true /CertPfx=C:\cert.pfx /CertPfxPassword=... /CapabilitySource=E:\]
> ```
>
> **مزیت اصلی حالت standalone (که EXE استفاده می‌کند):** بدون IIS و بدون دانلود
> runtime — اپ self-contained است و به‌صورت **سرویس ویندوز + Kestrel** با **SSO کربروس
> بومی** (handler Negotiate) اجرا می‌شود. برای سرور آفلاین فقط در صورت نبودن RSAT،
> ISO مانت‌شده لازم است (فیلد *Capability Source*).
>
> خروجی نهایی: صفحه‌ی PASS/FAIL برای ۱۰ راستی‌آزمایی (فایل‌ها، ماژول، سرویس، هویت،
> gMSA، کانفیگ، گواهی، ACL، HTTPS، اتصال به DC).
>
> ادامه این بخش، راه **دستی** (IIS) است — اگر از EXE استفاده کردید نیازی به آن‌ها نیست.

### گام ۱ — ساخت gMSA (روی DC یا ماشینی با RSAT AD)

```powershell
.\New-Gmsa.ps1 -GmsaName FWGPO -SpnHost fwgpo.corp.local -GrantDomainAdmin
```

- `-GrantDomainAdmin`: ساده‌ترین حالت (gMSA به Domain Admins اضافه می‌شود) — همان مدل ابزار v6.2 شما.
- برای least privilege: `-GrantGroup FWGPO-Admins` و سپس دیلیگاسیون GPO روی OUها (راهنما در خروجی اسکریپت).
- اگر ترجیح می‌دهید **کاربر دامین ادمین** به‌جای gMSA باشد: گام ۱ را رد کنید و نام کاربری را در گام ۲ بدهید.

### گام ۲ — نصب برنامه (روی سرور وب، با PowerShell ادمین)

```powershell
.\Install-FwGpoWeb.ps1 -ServiceIdentity "CORP\FWGPO$" -AppUrl "https://fwgpo.corp.local" -CertThumbprint <THUMBPRINT>
```

(برای کاربر دامین: `-ServiceIdentity "CORP\jdoe"`)

اسکریپت این کارها را انجام می‌دهد:
1. نصب **.NET 8 ASP.NET Runtime** (در صورت نبودن)
2. نصب **IIS + Windows Authentication**
3. نصب **RSAT**: Group Policy Management + AD PowerShell
4. `dotnet publish` برنامه به `C:\Program Files\FwGpoWeb`
5. نوشتن `appsettings.Production.json` (RpId/Origin برای WebAuthn، مسیر ماژول PS)
6. ساخت `C:\ProgramData\FwGpoWeb` با **ACL فقط برای هویت سرویس + Administrators**
7. ساخت **App Pool** با `IdentityType=SpecificUser` (هویت = gMSA$/کاربر)
8. سایت HTTPS روی پورت ۴۴۳ + فعال‌سازی Windows Auth
9. تست smoke (`/api/health`)

### گام ۳ — راستی‌آزمایی

```powershell
.\Verify-Deployment.ps1 -ServiceIdentity "CORP\FWGPO$" -AppUrl "https://fwgpo.corp.local"
```

خروجی: PASS/FAIL برای ران‌تایم، ماژول‌ها، هویت سرویس، gMSA، IIS، ACL و API.

### گام ۴ — ورود کاربران و MFA

1. کاربر از مرورگر ویندوز (زون Intranet) آدرس سایت را باز کند → **SSO خودکار** (بدون پرامپت)
2. صفحه «Two-factor verification» → یکی از:
   - **MFA Setup** → اسکن QR با Google Authenticator/Authy/1Password → ثبت secret
   - **FIDO2 / Fingerprint** → ثبت کلید امنیتی یا **اثر انگشت** (Windows Hello)
3. بعد از MFA موفق، اگر در گروه ادمین باشد → بخش GPO Builder باز می‌شود

## ۴. پیکربندی (appsettings.Production.json)

| کلید | پیش‌فرض | توضیح |
|---|---|---|
| `App:AuthMode` | `Windows` | `Windows` = SSO؛ `Mock` فقط برای توسعه |
| `App:Hosting` | `Iis` | `Kestrel` = self-hosted (روشن‌سازی: سرویس ویندوز با `sc`، گام ۶) |
| `App:AdminGroups` | `["Domain Admins"]` | گروه(های) مجاز برای ورود به بخش GPO |
| `App:SessionIdleMinutes` | `30` | timeout نشست |
| `App:SessionAbsoluteHours` | `8` | مدت مطلق کوکی verified |
| `WebAuthn:RpId` | host سایت | باید با hostname کاملاً یکی باشد |
| `WebAuthn:Origins` | `[AppUrl]` | origin دقیق HTTPS (با port اگر غیر 443) |
| `Pwsh:Exe` | `powershell.exe` | PowerShell 5.1 سرور |
| `Pwsh:ModuleDir` | `C:\Program Files\FwGpoWeb\powershell\FwGpoBuilder` | |
| `Pwsh:TimeoutSeconds` | `300` | مهلت هر عملیات DC |
| `Security:MfaMaxAttempts` | `5` | بعد از N شکست MFA → قفل ۱۵ دقیقه |
| `Security:MfaLockoutMinutes` | `15` | |

## ۵. خودکارسازی Kestrel (حالت self-hosted، اختیاری)

```powershell
sc.exe create FwGpoWeb binPath= '"C:\Program Files\FwGpoWeb\FwGpoWeb.exe"' `
  objectName= "CORP\FWGPO$" start= auto
sc.exe set FwGpoWeb -S 20  # restart on fail (اختیاری)
```
و در `appsettings.Production.json`: `"Hosting":"Kestrel"`, `"KestrelUrl":"https://0.0.0.0:8443"` (با گواهی در `Kestrel` binding). IIS در این حالت لازم نیست.

## ۶. پشتیبان‌بندی و بازیابی

- **`C:\ProgramData\FwGpoWeb`** را منظم backup کنید:
  - `secrets\users.json.enc` — secret TOTP + اعتبارال‌های FIDO2 کاربران (رمزنگاری‌شده با DPAPI Machine scope)
  - `audit\*.jsonl` — لاگ‌های امنیتی
  - `dataprotection-keys\` — کلیدهای DataProtection (بدون این، همه نشست‌ها/کوکی‌های verified باطل می‌شوند)
- بازگردانی: کافیه فایل‌ها را در سرور جدید (با همان DPAPI context — یعنی همان دامنه/سرور) کپی کنید.
- در سرور **جدید** باید کلیدهای DataProtection را هم منتقل کنید (وگرنه کاربران باید MFA را از نو کنند).

## ۷. ناگتی (Troubleshooting)

| مشکل | علت/راه‌حل |
|---|---|
| مرورگر پرامپت کربروس نمی‌دهد | سایت در زون Intranet نیست؛ یا HTTPS نیست؛ یا مرورگر Edge/Chrome در «Intranet zone» تنظیم نشده |
| `401 SSO_REQUIRED` تکرار می‌شود | SPN تکراری در AD؟ `setspn -X` را بزنید؛ نام کامپیون/SPN با `SpnHost` یکی باشد |
| خطای `GPO module not available` | RSAT GroupPolicy نصب نشده — گام ۲ اسکرپت |
| `Access is denied` هنگام New-GPO | هویت سرویس دسترسی ندارد — gMSA/کاربر را به گروه مناسب اضافه کنید |
| WebAuthn خطای origin می‌دهد | `WebAuthn:Origins` دقیقاً باید با آدرس نوار مرورگر (شامل port) یکی باشد؛ فقط HTTPS |
| برنامه بعد از ریبوت کار نمی‌کند | وضعیت سرویس/App Pool را چک کنید؛ `gMSA` باید روی همان سرور installed باشد (`Test-ADServiceAccount`) |

## ۸. حذف

```powershell
.\Uninstall-FwGpoWeb.ps1 -RemoveGmsa FWGPO -RemoveData
```
