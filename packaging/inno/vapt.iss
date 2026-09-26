; Inno Setup 6 script — builds Deduplex-Setup.exe
; Compile from repo root:
;   iscc packaging\inno\vapt.iss
; Or: & "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\inno\vapt.iss
;
; Prerequisites:
;   - Inno Setup 6.x
;   - Built one-folder tree: dist\Deduplex\
;
; Data note: %LOCALAPPDATA%\Deduplex\ (DB + evidence) is NOT
; deleted on default uninstall. Optional wipe:
;   - Wipe-DeduplexData.bat + Start Menu "Remove Deduplex app data (optional)"
;   - Uninstall MsgBox (Yes/No, default No) → DelTree only if Yes (interactive only)
;   - /SILENT and /VERYSILENT uninstall: ALWAYS keep LocalAppData (no MsgBox, no DelTree)
; Wipe / DelTree target Deduplex ONLY — never auto-delete legacy
; %LOCALAPPDATA%\VAPTEffortReduction\.
; See InfoAfterFile / UNINSTALL_NOTE.txt / packaging/README.md.

#define MyAppName "Deduplex"
#define MyAppVersion "0.1.0-spike"
#define MyAppPublisher "Wattlecorp"
#define MyAppExeName "Deduplex.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Deduplex
DefaultGroupName=Deduplex
DisableProgramGroupPage=yes
OutputDir=..\..\dist\installer
OutputBaseFilename=Deduplex-Setup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
; Lab spike defaults — installer must not open bind or enable AUTH.
PrivilegesRequired=lowest
; After install: remind user LocalAppData data may remain after uninstall.
InfoAfterFile=AFTER_INSTALL.txt

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; One-folder PyInstaller output (entire directory tree)
Source: "..\..\dist\Deduplex\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; Uninstall / leftover-data note installed beside the app
Source: "UNINSTALL_NOTE.txt"; DestDir: "{app}"; Flags: ignoreversion
; Optional LocalAppData wipe helper (does not run on uninstall by itself)
Source: "Wipe-DeduplexData.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Remove Deduplex app data (optional)"; Filename: "{app}\Wipe-DeduplexData.bat"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

; Do NOT use unconditional [UninstallDelete] on %LOCALAPPDATA%\Deduplex\
; — default uninstall preserves DB + evidence; wipe only via bat or Yes on MsgBox.
; NEVER DelTree the legacy %LOCALAPPDATA%\VAPTEffortReduction\ folder.

[Code]
{ Silent /VERYSILENT uninstall must KEEP LocalAppData — never DelTree when silent.
  Interactive only: Yes/No MsgBox (No default) may wipe %LOCALAPPDATA%\Deduplex\.
  No /WIPE flag in v1. Legacy VAPTEffortReduction is never touched. }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { QuietUninstallString uses /SILENT — must skip wipe entirely }
    if UninstallSilent then
      Exit;

    DataDir := ExpandConstant('{localappdata}\Deduplex');
    if DirExists(DataDir) then
    begin
      { MB_YESNO or MB_DEFBUTTON2 → No is the default (safe) }
      if MsgBox(
           'Also delete application data under LocalAppData\Deduplex? (DB + evidence)' + #13#10 + #13#10 +
           DataDir + #13#10 + #13#10 +
           'Choose No to keep your database and evidence (recommended default).' + #13#10 +
           'Note: legacy LocalAppData\VAPTEffortReduction is never deleted by this installer.',
           mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        if not DelTree(DataDir, True, True, True) then
          MsgBox('Could not fully delete:' + #13#10 + DataDir + #13#10 + #13#10 +
                 'Close any open handles and delete the folder manually if needed.',
                 mbError, MB_OK);
      end;
    end;
  end;
end;
