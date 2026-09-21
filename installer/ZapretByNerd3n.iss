; Build with build-installer.ps1. The application EXE is built separately.
#ifndef AppSource
  #error AppSource must name the staged application directory
#endif
#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef SetupOutput
  #define SetupOutput SourcePath + "dist"
#endif

[Setup]
AppId={{62CBFF39-615C-492D-A84E-B4779F533D9F}
AppName=zapret by nerd3n
AppVersion={#AppVersion}
AppPublisher=nerd3n
AppComments=Локальный интерфейс и проверка стратегий Flowseal zapret
DefaultDirName={localappdata}\ZapretByNerd3n
DefaultGroupName=zapret by nerd3n
DisableProgramGroupPage=yes
DisableDirPage=no
UsePreviousAppDir=yes
PrivilegesRequired=lowest
; WinDivert64.sys requires native x64 Windows, not ARM64 x64 emulation.
ArchitecturesAllowed=x64os
MinVersion=10.0
OutputDir={#SetupOutput}
OutputBaseFilename=Zapret-by-nerd3n-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayName=zapret by nerd3n
UninstallDisplayIcon={app}\ZapretByNerd3n.exe
Uninstallable=yes
CreateUninstallRegKey=yes
CloseApplications=yes
CloseApplicationsFilter=ZapretByNerd3n.exe
RestartApplications=no
ChangesAssociations=no
DisableWelcomePage=no
SetupMutex=ZapretByNerd3n.Setup.62CBFF39
VersionInfoVersion={#AppVersion}
VersionInfoDescription=Установка zapret by nerd3n
VersionInfoProductName=zapret by nerd3n

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Messages]
WelcomeLabel2=Программа установит zapret by nerd3n в папку вашего пользователя.%n%nВ комплект входят движок zapret, стратегии и профиль подключения. После установки приложение запросит права администратора, проверит стратегии на текущем подключении и сохранит результат первого подбора.%n%nДля начала нажмите «Далее».
FinishedLabel=zapret by nerd3n установлен.%n%nПри первом запуске потребуется разрешение Windows на запуск от имени администратора. Подбор выполняется в приложении на текущем подключении.

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Ярлыки:"; Flags: unchecked

[Files]
Source: "{#AppSource}\ZapretByNerd3n.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\THIRD_PARTY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\PYTHON-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\GSAP-LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\VERIFICATION.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs
Source: "{#AppSource}\profiles\infolink-shchelkovo.json"; DestDir: "{app}\profiles"; Flags: ignoreversion
Source: "{#AppSource}\bundle\*"; DestDir: "{app}\bundle"; Excludes: "*-user.txt,ACTIVE_DISCORD_UDP.bin,ACTIVE_GAME_UDP.bin,\utils\test results\*,*.log,*.test-backup.txt,\utils\game_filter.enabled"; Flags: ignoreversion recursesubdirs createallsubdirs
; Existing custom payload selections survive reinstall and uninstall.
Source: "{#AppSource}\bundle\bin\ACTIVE_DISCORD_UDP.bin"; DestDir: "{app}\bundle\bin"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#AppSource}\bundle\bin\ACTIVE_GAME_UDP.bin"; DestDir: "{app}\bundle\bin"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{autoprograms}\zapret by nerd3n\zapret by nerd3n"; Filename: "{app}\ZapretByNerd3n.exe"; Parameters: "--auto --elevate"; WorkingDir: "{app}"; Comment: "Открыть zapret by nerd3n"; AppUserModelID: "Nerd3n.Zapret"
Name: "{autoprograms}\zapret by nerd3n\Удалить zapret by nerd3n"; Filename: "{uninstallexe}"
Name: "{autodesktop}\zapret by nerd3n"; Filename: "{app}\ZapretByNerd3n.exe"; Parameters: "--auto --elevate"; WorkingDir: "{app}"; Tasks: desktopicon; AppUserModelID: "Nerd3n.Zapret"

[Code]
var
  LaunchAfterInstall: TNewCheckBox;

procedure InitializeWizard;
begin
  LaunchAfterInstall := TNewCheckBox.Create(WizardForm);
  LaunchAfterInstall.Parent := WizardForm.FinishedPage;
  LaunchAfterInstall.Left := WizardForm.FinishedLabel.Left;
  LaunchAfterInstall.Top := WizardForm.RunList.Top;
  LaunchAfterInstall.Width := WizardForm.FinishedLabel.Width;
  LaunchAfterInstall.Height := ScaleY(24);
  LaunchAfterInstall.Caption := 'Запустить zapret by nerd3n';
  LaunchAfterInstall.Checked := True;
  LaunchAfterInstall.Visible := False;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
    LaunchAfterInstall.Visible := not WizardSilent;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ErrorCode: Integer;
begin
  if (CurStep = ssDone) and (not WizardSilent) and LaunchAfterInstall.Checked then
  begin
    if not ShellExec('runas', ExpandConstant('{app}\ZapretByNerd3n.exe'), '--auto',
      ExpandConstant('{app}'), SW_SHOWNORMAL, ewNoWait, ErrorCode) then
    begin
      if ErrorCode = 1223 then
        MsgBox('Установка завершена. Запуск с правами администратора отменён.' + #13#10 +
          'Откройте zapret by nerd3n через ярлык в меню «Пуск», когда будете готовы.', mbInformation, MB_OK)
      else
        MsgBox('Установка завершена, но приложение не удалось запустить.' + #13#10 +
          SysErrorMessage(ErrorCode) + #13#10 +
          'Повторите запуск через ярлык в меню «Пуск».', mbError, MB_OK);
    end;
  end;
end;
