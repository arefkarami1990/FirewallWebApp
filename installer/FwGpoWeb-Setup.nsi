; =============================================================================
; FwGpoWeb Setup — standalone installer (NSIS)
;
; One-click installation of FwGpoWeb in STANDALONE mode:
;   self-contained .NET 8 app + Kestrel + Windows Service.
;   No IIS, no .NET runtime download, works air-gapped (RSAT from ISO if missing).
;
; Interactive:  FwGpoWeb-Setup-1.0.2.exe
; Silent:       FwGpoWeb-Setup-1.0.2.exe /S /ServiceIdentity=CORP\FWGPO$ /AppUrl=https://fwgpo.corp.local [/CreateGmsa=true /GmsaName=FWGPO /Port=443 /CertPfx=C:\cert.pfx /CertPfxPassword=pw /ServicePassword=pw /CapabilitySource=E:\ /InstallPath=... /DataPath=...]
;   (silent values must not contain spaces)
;
; Build: makensis FwGpoWeb-Setup.nsi   (staging/ is created by build.sh / build.ps1)
; =============================================================================

!define APP_NAME   "FwGpoWeb"
!define APP_VER    "1.0.2"
!define STAGE      "$TEMP\FwGpoWebSetup"
!define ARGSFILE   "$TEMP\FwGpoWebSetup\installer-args.txt"
!define RESULTFILE "$TEMP\FwGpoWebSetup\setup-result.txt"

Unicode true
RequestExecutionLevel admin
Name "${APP_NAME} Setup ${APP_VER}"
OutFile "dist\FwGpoWeb-Setup-${APP_VER}.exe"
SetCompressor /SOLID lzma

!include "MUI2.nsh"
!include "nsDialogs.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"
!include "WinMessages.nsh"

; ---------------------------------------------------------------- UI language
!define MUI_WELCOMEPAGE_TITLE  "${APP_NAME} ${APP_VER} — Firewall GPO Web Console"
!define MUI_WELCOMEPAGE_TEXT \
  "Installs ${APP_NAME} in standalone mode: self-contained .NET 8 application + Kestrel + Windows Service.$\r$\n$\r$\n• No IIS and no .NET runtime download are required — online or fully air-gapped servers both work (RSAT is taken from a mounted ISO when missing).$\r$\n• Windows SSO (Kerberos) + mandatory MFA (TOTP / FIDO2 fingerprint) are included.$\r$\n• The app connects to your domain controller using the service identity you provide (gMSA or domain user).$\r$\n$\r$\nRun this as Administrator on the web server."

; ---------------------------------------------------------------- pages
!insertmacro MUI_PAGE_WELCOME
Page custom InputShow InputLeave
Page instfiles
Page custom ResultShow ResultLeave
!insertmacro MUI_LANGUAGE "English"

; ---------------------------------------------------------------- variables
Var ServiceIdentity
Var AppUrl
Var Port
Var GmsaName
Var CreateGmsa
Var ServicePassword
Var CertPfx
Var CertPfxPassword
Var CapabilitySource
Var InstallPath
Var DataPath
Var Silent
Var ResultOk
Var ResultText

; ---------------------------------------------------------------- .onInit
Function .onInit
  StrCpy $Silent "0"
  StrCpy $Port "443"
  StrCpy $GmsaName "FWGPO"
  StrCpy $CreateGmsa "true"
  StrCpy $InstallPath "C:\Program Files\FwGpoWeb"
  StrCpy $DataPath "C:\ProgramData\FwGpoWeb"
  StrCpy $ResultText ""
  StrCpy $ResultOk "0"
  IfSilent silentinit
  Goto initdone
  silentinit:
  StrCpy $Silent "1"
  StrCpy $CreateGmsa "false"
  Call ParseArgServiceIdentity
  Call ParseArgAppUrl
  Call ParseArgPort
  Call ParseArgGmsaName
  Call ParseArgCreateGmsa
  Call ParseArgServicePassword
  Call ParseArgCertPfx
  Call ParseArgCertPfxPassword
  Call ParseArgCapabilitySource
  Call ParseArgInstallPath
  Call ParseArgDataPath
  initdone:
FunctionEnd

; ---- tiny arg parser: value of /Key= in $CmdLine -> $R3 (values: no spaces)
; Extracts the current token up to a space and string-compares it with "/Key=".
Function ParseArg
  Exch $R5
  Push $R4
  Push $R6
  Push $R7
  Push $R8
  StrCpy $R4 "/$R5="
  StrCpy $R3 ""
  StrCpy $R7 $CmdLine
  token:
  StrCmp $R7 "" notfound
  StrCpy $R6 $R7 1
  ${If} $R6 == " "
    StrCpy $R7 $R7 -1
    Goto token
  ${EndIf}
  ; collect the current token into $R8
  StrCpy $R8 ""
  ${Do}
    StrCpy $R6 $R7 1
    ${If} $R6 == ""
      ${ExitDo}
    ${EndIf}
    ${If} $R6 == " "
      ${ExitDo}
    ${EndIf}
    StrCpy $R8 "$R8$R6"
    StrCpy $R7 $R7 -1
  ${Loop}
  ${If} $R8 == $R4
    ; value = the rest of the line after the token (skip one space)
    StrCpy $R6 $R7 1
    ${If} $R6 == " "
      StrCpy $R7 $R7 -1
    ${EndIf}
    StrCpy $R3 "$R7"
    Goto notfound
  ${EndIf}
  Goto token
  notfound:
  Pop $R8
  Pop $R7
  Pop $R6
  Pop $R4
  Exch $R3
FunctionEnd

Function ParseArgServiceIdentity
  Push "ServiceIdentity"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $ServiceIdentity "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgAppUrl
  Push "AppUrl"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $AppUrl "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgPort
  Push "Port"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $Port "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgGmsaName
  Push "GmsaName"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $GmsaName "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgCreateGmsa
  Push "CreateGmsa"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $CreateGmsa "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgServicePassword
  Push "ServicePassword"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $ServicePassword "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgCertPfx
  Push "CertPfx"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $CertPfx "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgCertPfxPassword
  Push "CertPfxPassword"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $CertPfxPassword "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgCapabilitySource
  Push "CapabilitySource"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $CapabilitySource "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgInstallPath
  Push "InstallPath"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $InstallPath "$R3"
  ${EndIf}
FunctionEnd
Function ParseArgDataPath
  Push "DataPath"
  Call ParseArg
  Pop $R3
  ${If} $R3 != ""
    StrCpy $DataPath "$R3"
  ${EndIf}
FunctionEnd

; ---------------------------------------------------------------- input page
Var hDlg
Var editSI
Var editAppUrl
Var editPort
Var editGmsaName
Var chkGmsa
Var editSvcPwd
Var editCertPfx
Var editCertPwd
Var editCapSrc

; control constants (Debian's nsDialogs.nsh ships without the NSD_Create* macros)
!define EDIT_CLS    EDIT
!define EDIT_STY    ${DEFAULT_STYLES}|${WS_TABSTOP}|${ES_AUTOHSCROLL}
!define EDIT_EXSTY  ${WS_EX_WINDOWEDGE}|${WS_EX_CLIENTEDGE}
!define LBL_CLS     STATIC
!define LBL_STY     ${DEFAULT_STYLES}|${SS_NOTIFY}
!define LBL_EXSTY   ${WS_EX_TRANSPARENT}
!define GB_CLS      BUTTON
!define GB_STY      ${DEFAULT_STYLES}|${BS_GROUPBOX}
!define CHK_CLS     BUTTON
!define CHK_STY     ${DEFAULT_STYLES}|${WS_TABSTOP}|${BS_TEXT}|${BS_VCENTER}|${BS_AUTOCHECKBOX}|${BS_MULTILINE}
!define RES_CLS     EDIT
!define RES_STY     ${DEFAULT_STYLES}|${ES_MULTILINE}|${ES_READONLY}|${WS_VSCROLL}

Function InputShow
  nsDialogs::Create 1018
  Pop $hDlg
  ${If} $hDlg == error
    Abort
  ${EndIf}

  nsDialogs::CreateControl ${GB_CLS} ${GB_STY} ${WS_EX_TRANSPARENT} 0 0 100% 152u "Installation parameters"
  Pop $0

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 12u 30% 12u "Service Identity  *"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 12u 62% 12u ""
  Pop $editSI
  ${NSD_Edit_SetCueBannerText} $editSI 0 "DOMAIN\GMSA$$  or  DOMAIN\user"
  ${NSD_SetText} $editSI $ServiceIdentity

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 26u 30% 12u "App URL (HTTPS)  *"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 26u 62% 12u ""
  Pop $editAppUrl
  ${NSD_Edit_SetCueBannerText} $editAppUrl 0 "https://fwgpo.yourdomain.local  (exact origin the browser will show)"
  ${NSD_SetText} $editAppUrl $AppUrl

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 40u 30% 12u "HTTPS Port"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 40u 62% 12u $Port
  Pop $editPort

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 54u 30% 12u "GMSA Name"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 54u 62% 12u $GmsaName
  Pop $editGmsaName

  nsDialogs::CreateControl ${CHK_CLS} ${CHK_STY} 0 4u 68u 94% 12u "Create the gMSA now  (this machine must be the DC, or have RSAT AD + KDS)"
  Pop $chkGmsa
  ; interactive mode default is always "create gMSA" (silent mode never shows this page)
  SendMessage $chkGmsa ${BM_SETCHECK} ${BST_CHECKED} 0

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 84u 30% 12u "Service password"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 84u 62% 12u ""
  Pop $editSvcPwd
  ${NSD_Edit_SetCueBannerText} $editSvcPwd 0 "only if NOT a gMSA"
  ${NSD_SetText} $editSvcPwd $ServicePassword

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 98u 30% 12u "Certificate PFX"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 98u 62% 12u ""
  Pop $editCertPfx
  ${NSD_Edit_SetCueBannerText} $editCertPfx 0 "path to your PFX  (leave blank = self-signed, dev only)"
  ${NSD_SetText} $editCertPfx $CertPfx

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 112u 30% 12u "PFX password"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 112u 62% 12u ""
  Pop $editCertPwd
  ${NSD_Edit_SetCueBannerText} $editCertPwd 0 "only if a PFX is provided"
  ${NSD_SetText} $editCertPwd $CertPfxPassword

  nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 4u 126u 30% 12u "ISO source (offline)"
  Pop $0
  nsDialogs::CreateControl ${EDIT_CLS} ${EDIT_STY} ${EDIT_EXSTY} 36% 126u 62% 12u ""
  Pop $editCapSrc
  ${NSD_Edit_SetCueBannerText} $editCapSrc 0 "root of mounted Windows ISO, e.g. E:\  (only if RSAT is missing)"
  ${NSD_SetText} $editCapSrc $CapabilitySource

  nsDialogs::Show
FunctionEnd

Function InputLeave
  System::Call user32::GetWindowText(p$editSI,t.s,i${NSIS_MAX_STRLEN})
  Pop $ServiceIdentity
  System::Call user32::GetWindowText(p$editAppUrl,t.s,i${NSIS_MAX_STRLEN})
  Pop $AppUrl
  System::Call user32::GetWindowText(p$editPort,t.s,i${NSIS_MAX_STRLEN})
  Pop $Port
  System::Call user32::GetWindowText(p$editGmsaName,t.s,i${NSIS_MAX_STRLEN})
  Pop $GmsaName
  System::Call user32::GetWindowText(p$editSvcPwd,t.s,i${NSIS_MAX_STRLEN})
  Pop $ServicePassword
  System::Call user32::GetWindowText(p$editCertPfx,t.s,i${NSIS_MAX_STRLEN})
  Pop $CertPfx
  System::Call user32::GetWindowText(p$editCertPwd,t.s,i${NSIS_MAX_STRLEN})
  Pop $CertPfxPassword
  System::Call user32::GetWindowText(p$editCapSrc,t.s,i${NSIS_MAX_STRLEN})
  Pop $CapabilitySource
  ; InstallPath/DataPath keep their defaults (or the silent-mode values)
  SendMessage $chkGmsa ${BM_GETCHECK} 0 0 $0
  ${If} $0 == ${BST_CHECKED}
    StrCpy $CreateGmsa "true"
  ${Else}
    StrCpy $CreateGmsa "false"
  ${EndIf}

  ${If} $ServiceIdentity == ""
    MessageBox MB_ICONSTOP "Service Identity is required (e.g. CORP\FWGPO$$ or CORP\jdoe)."
    Abort
  ${EndIf}
  ${If} $AppUrl == ""
    MessageBox MB_ICONSTOP "App URL is required (e.g. https://fwgpo.yourdomain.local)."
    Abort
  ${EndIf}
  StrCpy $0 $AppUrl 8
  ${If} $0 != "https://"
    MessageBox MB_ICONSTOP "App URL must be HTTPS — Windows SSO and FIDO2/WebAuthn require a secure context."
    Abort
  ${EndIf}
  ${If} $Port == ""
    StrCpy $Port "443"
  ${EndIf}
  Push $Port
  Call ValidatePort
  Pop $0
  ${If} $0 == "0"
    MessageBox MB_ICONSTOP "HTTPS Port must be a number between 1 and 65535 (got: $Port)."
    Abort
  ${EndIf}
  ${If} $GmsaName == ""
    StrCpy $GmsaName "FWGPO"
  ${EndIf}
  Call WriteArgsFile
FunctionEnd

; ValidatePort -> $0 = 1 ok (1-5 digit number), 0 bad
Function ValidatePort
  Exch $R2
  Push $R1
  Push $R3
  Push $R4
  StrCpy $R4 $R2
  StrCpy $R1 0
  StrCpy $R0 1
  vploop:
  StrCpy $R3 $R4 1
  StrCmp $R3 "" vpdone
  ${If} $R3 < "0"
    StrCpy $R0 0
    Goto vpdone
  ${EndIf}
  ${If} $R3 > "9"
    StrCpy $R0 0
    Goto vpdone
  ${EndIf}
  IntOp $R1 $R1 + 1
  ${If} $R1 > 5
    StrCpy $R0 0
    Goto vpdone
  ${EndIf}
  StrCpy $R4 $R4 -1
  Goto vploop
  vpdone:
  ${If} $R1 == 0
    StrCpy $R0 0
  ${EndIf}
  Pop $R4
  Pop $R3
  Pop $R1
  Exch $R0
FunctionEnd

; ---------------------------------------------------------------- write args
Function WriteArgsFile
  Exch $R0
  FileOpen $R0 "${ARGSFILE}" w
  ${If} $R0 == -1
    Pop $R0
    MessageBox MB_ICONSTOP "Could not write ${ARGSFILE}"
    Abort
  ${EndIf}
  FileWrite $R0 "ServiceIdentity=$ServiceIdentity$\r$\n"
  FileWrite $R0 "AppUrl=$AppUrl$\r$\n"
  FileWrite $R0 "Port=$Port$\r$\n"
  FileWrite $R0 "GmsaName=$GmsaName$\r$\n"
  FileWrite $R0 "CreateGmsa=$CreateGmsa$\r$\n"
  FileWrite $R0 "ServicePassword=$ServicePassword$\r$\n"
  FileWrite $R0 "CertPfx=$CertPfx$\r$\n"
  FileWrite $R0 "CertPfxPassword=$CertPfxPassword$\r$\n"
  FileWrite $R0 "CapabilitySource=$CapabilitySource$\r$\n"
  FileWrite $R0 "InstallPath=$InstallPath$\r$\n"
  FileWrite $R0 "DataPath=$DataPath$\r$\n"
  FileClose $R0
  Pop $R0
FunctionEnd

; ---------------------------------------------------------------- read result
Var ResultLine
Var PSExe
Function ReadResult
  StrCpy $ResultText ""
  StrCpy $ResultOk "0"
  IfFileExists "${RESULTFILE}" haveresult
  StrCpy $ResultText "The installation did not produce a result file. The staging folder was kept (path above); its install.log shows what happened. Also check the Windows Application event log."
  Goto readdone
  haveresult:
  FileOpen $R0 "${RESULTFILE}" r
  ${If} $R0 == -1
    StrCpy $ResultText "Could not read the result file."
    Goto readdone
  ${EndIf}
  ${Do}
    FileRead $R0 $ResultLine
    StrCmp $ResultLine "" readloopdone
    ${If} $ResultLine == "STATUS=OK"
      StrCpy $ResultOk "1"
      StrCpy $ResultLine "STATUS: SUCCESS — FwGpoWeb is installed and verified."
    ${ElseIf} $ResultLine == "STATUS=FAIL"
      StrCpy $ResultOk "0"
      StrCpy $ResultLine "STATUS: FAILED"
    ${EndIf}
    ${If} $ResultLine != ""
      StrCpy $ResultText "$ResultText$ResultLine$\r$\n"
    ${EndIf}
  ${Loop}
  readloopdone:
  FileClose $R0
  readdone:
FunctionEnd

Function ResultShow
  nsDialogs::Create 1018
  Pop $hDlg
  ${If} $hDlg == error
    Abort
  ${EndIf}
  ${If} $ResultOk == "1"
    nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 0 0 100% 18u "Installation completed successfully."
    Pop $0
  ${Else}
    nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 0 0 100% 18u "Installation FAILED - see details below."
    Pop $0
  ${EndIf}
  nsDialogs::CreateControl ${RES_CLS} ${RES_STY} ${EDIT_EXSTY} 0 22u 100% 110u ""
  Pop $0
  SendMessage $0 ${WM_SETTEXT} 0 STR:$ResultText
  ${If} $ResultOk == "0"
    nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 0 138u 100% 24u "The staging folder was kept: ${STAGE}   (full log: see LOG line above)"
    Pop $0
  ${Else}
    nsDialogs::CreateControl ${LBL_CLS} ${LBL_STY} ${LBL_EXSTY} 0 138u 100% 24u "Next: open the App URL from a domain-joined browser (intranet zone) and complete MFA (TOTP / FIDO2 fingerprint)."
    Pop $0
  ${EndIf}
  nsDialogs::Show
FunctionEnd
Function ResultLeave
FunctionEnd

; ---------------------------------------------------------------- install
Section "Install ${APP_NAME}"
  RMDir /r "${STAGE}"
  CreateDirectory "${STAGE}"
  CreateDirectory "${STAGE}\app"
  SetOutPath "${STAGE}\app"
  File /r "staging\app\*."

  CreateDirectory "${STAGE}\deploy"
  SetOutPath "${STAGE}\deploy"
  File "staging\deploy\New-Gmsa.ps1"

  CreateDirectory "${STAGE}\installer"
  SetOutPath "${STAGE}\installer"
  File "Install-FwGpoWeb-Service.ps1"
  File "Verify-FwGpoWeb-Service.ps1"
  File "Install-FromInstaller.ps1"

  CreateDirectory "${STAGE}\powershell\FwGpoBuilder"
  SetOutPath "${STAGE}\powershell\FwGpoBuilder"
  File /r "staging\powershell\FwGpoBuilder\*."

  ${If} $Silent == "1"
    Call WriteArgsFile
  ${EndIf}

  ; ---- resolve the PowerShell executable ----
  ; The NSIS stub is 32-bit; on 64-bit Windows, system32 is redirected to
  ; SysWOW64. The literal "sysnative" path maps to the REAL 64-bit System32,
  ; then we fall back to the normal system dir, then pwsh 7.
  StrCpy $PSExe ""
  IfFileExists "$WINDIR\System32\sysnative\WindowsPowerShell\v1.0\powershell.exe" psFound64
  IfFileExists "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" psFoundSys
  IfFileExists "$PROGRAMFILES64\PowerShell\7\pwsh.exe" psFoundPwsh
  IfFileExists "$PROGRAMFILES\PowerShell\7\pwsh.exe" psFoundPwsh32
  StrCpy $ResultOk "0"
  StrCpy $ResultText "Windows PowerShell was not found (checked $WINDIR\System32\sysnative, system dir, and Program Files PowerShell 7). Every Windows Server ships Windows PowerShell 5.1 - fix the system, then re-run."
  Goto installdone
  psFound64:
  StrCpy $PSExe "$WINDIR\System32\sysnative\WindowsPowerShell\v1.0\powershell.exe"
  Goto psResolved
  psFoundSys:
  StrCpy $PSExe "$SYSDIR\WindowsPowerShell\v1.0\powershell.exe"
  Goto psResolved
  psFoundPwsh:
  StrCpy $PSExe "$PROGRAMFILES64\PowerShell\7\pwsh.exe"
  Goto psResolved
  psFoundPwsh32:
  StrCpy $PSExe "$PROGRAMFILES\PowerShell\7\pwsh.exe"
  psResolved:
  DetailPrint "Using PowerShell: $PSExe"
  DetailPrint "Running the FwGpoWeb installation (gMSA, app, service, verify) — this can take a few minutes..."
  ExecWait '"$PSExe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${STAGE}\installer\Install-FromInstaller.ps1" -StageDir "${STAGE}" -ArgsFile "${ARGSFILE}"'
  installdone:
  Call ReadResult

  ${If} $ResultOk == "1"
    RMDir /r "${STAGE}"
  ${EndIf}
SectionEnd
