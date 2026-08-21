# مدل امنیت FwGpoWeb

## ۱. مدل تهدید

| تهدید | خنثی‌سازی |
|---|---|
| دسترسی غیرمجاز به UI | SSO (Kerberos) + **MFA اجباری** + گروه ادمین |
| حمله CSRF | کوکی‌های `SameSite=Lax` + **Anti-Forgery Token** برای همه POST/DELETE |
| Session fixation | کوکی `FwGpo.Verified` با **DataProtection** (رمزنگاری + integrity) که فقط **لحظه MFA موفق** صادر می‌شود و به هویت SSO گره خورده؛ نشست قبلی پاک می‌شود |
| حدس رمز MFA (brute force) | **قفل ۱۵ دقیقه بعد از ۵ شکست** + rate limit ۶۰/دقیقه بر IP |
| تزریق PowerShell / command-line injection | ورودی‌ها **فقط** از طریق فایل JSON می‌روند (هرگز روی command line)؛ `ArgumentList` ثابت؛ اعتبارسنجی **دو لایه** (C# + PS)؛ `Invoke-Expression` وجود ندارد |
| تزریق DN / مسیر (path traversal) | اعتبارسنجی ساختار DN + رد کردن متا-کاراکترهای shell |
| بازپخش/Tamper در FIDO2 | چالش یک‌بارمصرف سروری، بررسی origin در clientDataJSON، بررسی امضا و signCount، **replay رد می‌شود** (تست B13) |
| نشت اطلاعات در خطاها | خطاها فقط پیام تمیز (بدون stack trace)؛ لاگ‌های کامل فقط سمت سرور |
| دسترسی فیزیکی/فایل | کلیدهای کاربر با **DPAPI (Machine scope)** + ACL محدود بر روی `C:\ProgramData\FwGpoWeb` |
| دسترسی بیش از حد هویت سرویس | انتخاب: gMSA با دیلیگاسیون (least privilege) یا Domain Admin (مدل ساده) |

## ۲. جریان احراز هویت (AuthN/AuthZ)

```
1. SSO      : مرورگر ← Kerberos/NTLM (IIS Windows Auth یا Negotiate/Kestrel)
2. Session  : کوکی FwGpo.Sid (HttpOnly, SameSite=Lax, Secure on HTTPS)
3. MFA      : TOTP (RFC 6238، SHA-1، ±۱ پنجره ۳۰ ثانیه) یا FIDO2/WebAuthn
4. Verified : کوکی FwGpo.Verified = DataProtection({upn, method, iat})
               - فقط بعد از MFA موفق
               - چسبیده به upn (تغییر هویت SSO = باطل)
               - مهلت مطلق ۸ ساعت (مستقل از idle)
5. AuthZ    : عضویت در App:AdminGroups (بررسی LDAP/AD، کش ۵ دقیقه)
```

## ۳. ذخیره‌سازی کلیدهای کاربر

- فایل: `%ProgramData%\FwGpoWeb\secrets\users.json.enc`
- کل محتوا با **DPAPI Machine scope** رمزنگاری می‌شود (بر Linux در حالت توسعه: AES-256-GCM)
- ACL: فقط هویت سرویس + Administrators
- هر FIDO2 credential: (credentialId, COSE public key, signCount, transports) — برای بازیابی در سرور جدید باید backup شود

## ۴. آدرس‌دهی ورودی‌ها (defense in depth)

| ورودی | لایه ۱ (C#) | لایه ۲ (PowerShell) |
|---|---|---|
| IP list | `InputValidator.ParseAddressList` (token‌بندی + regex سخت) | `Test-AddressListStrict` (همان قواعد) |
| Port | ۱–۶۵۵ یا `Any` | تکرار همان |
| Protocol | فقط TCP/UDP/Any | تکرار همان |
| Mode | فقط specific/any/localsubnet | تکرار همان |
| OU DN | ساختار DN + ممنوعیت `| & \` $ ; * ? " '` + حداکثر ۱۰۰ کاراکتر | `Test-FwOuExists` (LDAP) |
| GPO name | `SanitizeGpoName` + whitelist کاراکترها | sanitize تکراری |

هر مقدار نامعتبر **قبل** از رسیدن به PowerShell رد می‌شود (تست B3–B6 اثبات می‌کند هیچ apply‌ای رخ نداده).

## ۵. لایه فایروال (منطق v6.2)

- قوانین Allow برای آدرس‌های مجاز + قوانین Block برای **مکمل** (همه آدرس‌های دیگر) — الگوریتم merge/complement همان نسخه ۶.۲ شما با **برگشت‌خوردگی تستی کامل** (۸۰ تست + اینواریانت‌های تصادفی: بدون overlap، پوشش دقیق فضای ۳۲ بیتی).
- **Verify no-overlap**: اگر حتی یک overlap بین Allow/Block پیدا شود، apply **نشان می‌دهد** (throw) و اعمال نمی‌شود.
- بعد از apply، یک **read-back** انجام می‌شود و شمارش قوانین موجود در GPO گزارش می‌شود.
- پاک‌سازی قوانین قبلی **name-scoped** است (فقط `Allow-FW-*` / `Block-FW-*`) — قوانین دیگران دست نمی‌خورد.

## ۶. لاگ و ممیزی

- `audit\audit-YYYYMMDD.jsonl` — JSON-lines: actor، عمل، جزئیات، موفقیت، IP، زمان (UTC)
- روی ویندوز همزمان در **Event Log** (Application / Source: FwGpoWeb)
- رویدادها: SSO، MFA_OK/FAIL، قفل، ثبت FIDO2، apply GPO (با جزئیات OU/Port/IPها)، read-back، logout
- لاگ‌ها append-only هستند (فقط اضافه می‌شوند)

## ۷. سرتیبل‌های امنیتی HTTP

| هدر | مقدار |
|---|---|
| `Content-Security-Policy` | `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Permissions-Policy` | `camera=(), microphone=(), geolocation=()` |
| `Cache-Control` (API) | `no-store` |
| `Strict-Transport-Security` | فعال روی HTTPS (یک سال) |

## ۸. محدودیت‌های شناخته‌شده / فرض‌ها

1. **هویت سرویس** به AD دسترسی GPO دارد — دامنه شما فرض می‌کند گره‌های دامین‌جویند قابل اعتمادند (فرض کلی Windows).
2. بررسی گروه ادمین **یک سطح** است (بدون تکرار گروه‌های تو در هم) — گروه‌های مجاز را flat نگه دارید.
3. در حالت Mock (فقط توسعه) هیچ‌یک از کنترل‌های واقعی AD در کار نیست.
4. WebAuthn در **HTTPS** اعتبار دارد؛ برای تست HTTP در توسعه، origin باید در لیست باشد.
