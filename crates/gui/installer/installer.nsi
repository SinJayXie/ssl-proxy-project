; SSL Proxy Client (GPUI) installer script.
;
; Upgrade-in-place with the old Tauri client: same install directory, same exe
; name (ssl-proxy-client.exe) and same uninstall registry key
; (HKCU\...\Uninstall\SSLProxyClient). Old shortcuts and the Control Panel entry
; are taken over by the new build, no manual uninstall needed.
;
; Keep this file ASCII-only: makensis reads UTF-8 scripts only when they carry a
; BOM, and the MUI language files already provide localized UI text.

Unicode true
SetCompressor /SOLID lzma
SetCompressorDictSize 32
RequestExecutionLevel user
XPStyle on

; Resolve relative paths from this script's directory.
!cd "${__FILEDIR__}"

!define PRODUCT_NAME "SSLProxyClient"
!define PRODUCT_PUBLISHER "ssl-proxy"
!define PRODUCT_EXE "ssl-proxy-client.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

!ifndef PRODUCT_VERSION
  !define PRODUCT_VERSION "0.0.0"
!endif
; The build script stages the exe under payload\ (UPX-compressed when available)
; and passes /DUSE_PAYLOAD; compiling this script by hand uses the raw release exe.
!ifndef PAYLOAD_EXE
  !ifdef USE_PAYLOAD
    !define PAYLOAD_EXE "..\..\..\target\installer\payload\ssl-proxy-gui.exe"
  !else
    !define PAYLOAD_EXE "..\..\..\target\release\ssl-proxy-gui.exe"
  !endif
!endif
!ifndef SOURCE_GEO
  !define SOURCE_GEO "..\assets\GeoDB.dat"
!endif
; Icons come from the Tauri client's icon set.
!ifndef ICON_FILE
  !define ICON_FILE "..\..\..\..\ssl-proxy-client-tauri\src-tauri\icons\icon.ico"
!endif
; OutFile can be overridden by the unified build script with /DOUT_FILE=<abs path>.
!ifndef OUT_FILE
  !define OUT_FILE "..\..\..\target\installer\${PRODUCT_NAME}_${PRODUCT_VERSION}_x64-setup.exe"
!endif

Name "SSL Proxy Client ${PRODUCT_VERSION}"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\${PRODUCT_NAME}"
BrandingText "SSL Proxy Client v${PRODUCT_VERSION}"

VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "SSL Proxy Client Setup"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "LegalCopyright" "(c) ssl-proxy"

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "FileFunc.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON "${ICON_FILE}"
!define MUI_UNICON "${ICON_FILE}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\${PRODUCT_EXE}"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  SetRegView 64

  ; Reuse the previous install directory (in-place upgrade). Values written by
  ; the old installer are quoted, strip them.
  ReadRegStr $0 HKCU "${UNINST_KEY}" "InstallLocation"
  ${If} $0 != ""
    StrCpy $1 $0 1
    ${If} $1 == "$\""
      StrCpy $0 $0 -1 1
    ${EndIf}
    StrCpy $1 $0 1 -1
    ${If} $1 == "$\""
      StrCpy $0 $0 -1
    ${EndIf}

    ; An explicit /D= on the command line wins over the registry value.
    ${If} $INSTDIR == "$LOCALAPPDATA\${PRODUCT_NAME}"
      StrCpy $INSTDIR $0
    ${EndIf}
  ${EndIf}
FunctionEnd

Section "Install" SEC_MAIN
  SetOutPath "$INSTDIR"

  ; Stop the running instance (it may be sitting in the tray), otherwise the
  ; exe file is locked and cannot be overwritten.
  nsExec::Exec 'taskkill /F /IM ${PRODUCT_EXE}'
  Pop $0

  File "/oname=${PRODUCT_EXE}" "${PAYLOAD_EXE}"
  File "/oname=GeoDB.dat" "${SOURCE_GEO}"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Start-menu + desktop shortcuts are always (re)created, so upgrades keep a
  ; working icon even when the old version had none.
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_EXE}"
  CreateShortCut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\${PRODUCT_EXE}"

  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$\"$INSTDIR\${PRODUCT_EXE}$\""
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$\"$INSTDIR$\""
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" "$0"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  nsExec::Exec 'taskkill /F /IM ${PRODUCT_EXE}'
  Pop $0

  Delete "$INSTDIR\${PRODUCT_EXE}"
  Delete "$INSTDIR\GeoDB.dat"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}.lnk"
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  DeleteRegKey HKCU "${UNINST_KEY}"

  ; Remove the directory only when empty, keeping consent.dat / app.log.
  RMDir "$INSTDIR"
SectionEnd
