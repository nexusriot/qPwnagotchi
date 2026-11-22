; qPwnagotchi NSIS installer. Defines passed by scripts/build-windows.sh:
;   VERSION NUMVERSION SRCDIR ICON OUTFILE
Unicode true
!include "MUI2.nsh"

Name "qPwnagotchi ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMFILES64\qPwnagotchi"
InstallDirRegKey HKLM "Software\qPwnagotchi" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

VIProductVersion "${NUMVERSION}"
VIAddVersionKey "ProductName" "qPwnagotchi"
VIAddVersionKey "FileDescription" "qPwnagotchi installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\qpwnagotchi.exe"
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
  SetOutPath "$INSTDIR"
  File /r "${SRCDIR}\*.*"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  CreateDirectory "$SMPROGRAMS\qPwnagotchi"
  CreateShortcut "$SMPROGRAMS\qPwnagotchi\qPwnagotchi.lnk" "$INSTDIR\qpwnagotchi.exe"
  CreateShortcut "$SMPROGRAMS\qPwnagotchi\Uninstall.lnk" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\qPwnagotchi" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\qPwnagotchi" "DisplayName" "qPwnagotchi"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\qPwnagotchi" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\qPwnagotchi" "DisplayIcon" "$INSTDIR\qpwnagotchi.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\qPwnagotchi" "UninstallString" "$\"$INSTDIR\Uninstall.exe$\""
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\qPwnagotchi" "NoModify" 1
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\qPwnagotchi\*.lnk"
  RMDir "$SMPROGRAMS\qPwnagotchi"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\qPwnagotchi"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\qPwnagotchi"
SectionEnd
