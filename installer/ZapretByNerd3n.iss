; Build with build-installer.ps1. The application EXE is built separately.
#ifndef AppSource
  #error AppSource must name the staged application directory
#endif
#ifndef AppVersion
  #define AppVersion "0.3.7"
#endif
#define DriverSHA256 GetSHA256OfFile(AppSource + "\bundle\bin\WinDivert64.sys")
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
SetupIconFile={#AppSource}\assets\app.ico
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
WelcomeLabel2=Программа установит zapret by nerd3n в папку вашего пользователя.%n%nВ комплект входят движок zapret и стратегии. После установки приложение откроется в отдельном окне, определит текущую сеть и выполнит первичный подбор. Провайдер заранее не назначается.%n%nУстановить выбранную стратегию с автозапуском Windows можно отдельной кнопкой в приложении.%n%nДля начала нажмите «Далее».
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
Source: "{#AppSource}\DESKTOP-LICENSES.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\VERIFICATION.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#AppSource}\docs\*"; DestDir: "{app}\docs"; Flags: ignoreversion recursesubdirs
Source: "{#AppSource}\profiles\infolink-shchelkovo.json"; DestDir: "{app}\profiles"; Flags: ignoreversion
Source: "{#AppSource}\bundle\*"; DestDir: "{app}\bundle"; Excludes: "*-user.txt,ACTIVE_DISCORD_UDP.bin,ACTIVE_GAME_UDP.bin,\bin\WinDivert64.sys,\utils\test results\*,*.log,*.test-backup.txt,\utils\game_filter.enabled"; Flags: ignoreversion recursesubdirs createallsubdirs
; A loaded kernel driver may remain locked after winws exits. Retain it only
; when its bytes exactly match this package; differing drivers still update.
Source: "{#AppSource}\bundle\bin\WinDivert64.sys"; DestDir: "{app}\bundle\bin"; Flags: ignoreversion; Check: DriverNeedsUpdate
; Existing custom payload selections survive reinstall and uninstall.
Source: "{#AppSource}\bundle\bin\ACTIVE_DISCORD_UDP.bin"; DestDir: "{app}\bundle\bin"; Flags: onlyifdoesntexist uninsneveruninstall
Source: "{#AppSource}\bundle\bin\ACTIVE_GAME_UDP.bin"; DestDir: "{app}\bundle\bin"; Flags: onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{autoprograms}\zapret by nerd3n\zapret by nerd3n"; Filename: "{app}\ZapretByNerd3n.exe"; Parameters: "--auto --elevate"; WorkingDir: "{app}"; Comment: "Открыть zapret by nerd3n"; IconFilename: "{app}\ZapretByNerd3n.exe"; IconIndex: 0; AppUserModelID: "Nerd3n.Zapret"
Name: "{autoprograms}\zapret by nerd3n\Удалить zapret by nerd3n"; Filename: "{uninstallexe}"; IconFilename: "{app}\ZapretByNerd3n.exe"; IconIndex: 0
Name: "{autodesktop}\zapret by nerd3n"; Filename: "{app}\ZapretByNerd3n.exe"; Parameters: "--auto --elevate"; WorkingDir: "{app}"; Tasks: desktopicon; IconFilename: "{app}\ZapretByNerd3n.exe"; IconIndex: 0; AppUserModelID: "Nerd3n.Zapret"

[Code]
var
  LaunchAfterInstall: TNewCheckBox;

function DriverNeedsUpdate: Boolean;
var
  DriverPath: String;
begin
  Result := True;
  DriverPath := ExpandConstant('{app}\bundle\bin\WinDivert64.sys');
  if FileExists(DriverPath) then
  begin
    try
      Result := CompareText(GetSHA256OfFile(DriverPath), '{#DriverSHA256}') <> 0;
      if not Result then
        Log('WinDivert64.sys matches package SHA-256; keeping existing driver file.');
    except
      Log('Cannot read installed driver hash; driver replacement remains required.');
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ExitCode: Integer;
begin
  Result := '';
  NeedsRestart := False;
  { Use the NEW executable from Setup's private temporary directory. The old
    elevated GUI cannot be closed by the unelevated Windows Restart Manager. }
  try
    ExtractTemporaryFile('ZapretByNerd3n.exe');
    if not Exec(ExpandConstant('{tmp}\ZapretByNerd3n.exe'),
      '--prepare-update "' + ExpandConstant('{app}') + '" --update-driver-sha256 {#DriverSHA256}', ExpandConstant('{tmp}'),
      SW_HIDE, ewWaitUntilTerminated, ExitCode) then
      Result := 'Не удалось подготовить обновление: ' + SysErrorMessage(ExitCode)
    else if ExitCode = 10 then
      Result := 'Не удалось освободить файлы установленной версии за 60 секунд.' + #13#10 +
        'Закройте zapret by nerd3n и программы, использующие движок из папки установки.' + #13#10 +
        'Если приложение не закрывается, перезагрузите Windows и повторите установку.' + #13#10 +
        'Также проверьте доступ на запись к папке: ' + ExpandConstant('{app}')
    else if ExitCode <> 0 then
      Result := 'Не удалось проверить готовность к обновлению (код ' + IntToStr(ExitCode) + ').' + #13#10 +
        'Закройте zapret by nerd3n и повторите установку. Если ошибка повторится, перезагрузите Windows.';
  except
    Result := 'Не удалось запустить подготовку обновления: ' + GetExceptionMessage;
  end;
  if Result <> '' then
    Result := Result + #13#10 + #13#10 + 'Файлы установленной версии не заменены.';
end;

function InitializeUninstall: Boolean;
var
  ErrorCode: Integer;
begin
  Result := True;
  if RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\ZapretByNerd3n') then
  begin
    if not ShellExec('runas', ExpandConstant('{app}\ZapretByNerd3n.exe'), '--remove-service',
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ErrorCode) then
    begin
      MsgBox('Удаление отменено: не удалось отключить автозапуск zapret.' + #13#10 +
        'Разрешите запрос Windows или удалите автозапуск в приложении и повторите удаление.', mbError, MB_OK);
      Result := False;
    end
    { ShellExec reports launch errors, not the child's exit code. Verify that
      the service actually disappeared after the elevated helper finished. }
    else if RegKeyExists(HKLM64, 'SYSTEM\CurrentControlSet\Services\ZapretByNerd3n') then
    begin
      MsgBox('Удаление отменено: служба zapret не была удалена.' + #13#10 +
        'Откройте приложение от имени администратора, удалите автозапуск и повторите.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

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
