# Как собрать и опубликовать релиз

Этот документ описывает выпуск **zapret by nerd3n 0.2.0** для Windows 10/11 x64:
сборку из конкретного коммита, проверку, подготовку архивов и ручную публикацию
на GitHub. Команды выполняются в PowerShell. Публикация начинается только на
последнем этапе; компиляция сама ничего не устанавливает и не запускает winws.

Репозиторий: [nerd-en/zapret-by-nerd3n](https://github.com/nerd-en/zapret-by-nerd3n).
Тег выпуска: `v0.2.0`. Для первого выпуска рекомендуется отметка **Pre-release**:
проверка приложения выполнена, но эффективность стратегий на реальной линии
**Инфолинк, Щёлково** ещё не подтверждена.

## Что потребуется

| Компонент | Версия и назначение |
| --- | --- |
| Windows | Windows 10/11 x64. ARM64 не поддерживается поставленным драйвером. |
| Python x64 | Исходный код требует Python 3.10+. Контрольная сборка выполнена на Python **3.13.5 x64**; для повторения используйте ту же версию. |
| PyInstaller | **6.22.3**, установленный в отдельное виртуальное окружение. |
| Inno Setup | **6.7.3**, нужен `ISCC.exe`. Установленный компилятор или официальный portable-режим. |
| Git | Для фиксации исходников и создания архива конкретного коммита. |
| GitHub Desktop | Необязательно; удобен для commit/push без терминала. |
| GitHub CLI | Необязательно; веб-интерфейса GitHub достаточно для публикации. |

Пользователю готового EXE Python, PyInstaller и Inno Setup не нужны. Системный
`curl.exe` нужен приложению для сетевых проверок. GSAP 3.15.0 уже находится в
`web/vendor`; npm для сборки этой версии не требуется.

Версии инструментов и зависимостей закреплены для повторения процедуры. Это
не обещание побайтово одинаковых EXE: на результат также влияют Python, Windows,
временные метки и среда сборки. Для каждого нового набора артефактов вычисляйте
собственные контрольные суммы.

## 1. Подготовить версию и исходники

Работайте из корня репозитория; замените путь на свою папку:

```powershell
Set-Location -LiteralPath 'C:\Projects\zapret-by-nerd3n'
git status --short
git branch --show-current
git remote -v
```

Ожидаемая ветка — `main`, origin —
`https://github.com/nerd-en/zapret-by-nerd3n.git`.

Проверьте согласованность номера версии:

| Файл | Что проверить |
| --- | --- |
| `zapret_ui/__init__.py` | `__version__ = "0.2.0"` |
| `app-version.txt` | `FileVersion` и `ProductVersion` — `0.2.0`, числовые поля — `(0, 2, 0, 0)` |
| `installer/ZapretByNerd3n.iss` | `AppVersion` по умолчанию — `0.2.0` |
| `installer/build-installer.ps1` | `$Version` по умолчанию — `0.2.0` |
| `README.md`, `VERIFICATION.md` | Возможности, результаты и ограничения соответствуют выпуску |

MIT-лицензия приложения соответствует типу лицензии Flowseal. Сохраняйте
авторство nerd3n, оригинальный `bundle/LICENSE.txt` и отдельные условия
сторонних компонентов: `THIRD_PARTY.md`, `GSAP-LICENSE.txt`, `PYTHON-LICENSE.txt`.
MIT оболочки не меняет лицензии WinDivert, Cygwin и GSAP.

Не добавляйте в Git:

- `data/`: настройки, отчёты, локальный ключ и сведения о проверенном подключении;
- `bundle/lists/*-user.txt`, результаты штатных тестов и локальные логи;
- `__pycache__/`, `*.pyc`, виртуальное окружение, `build/`, `dist/`;
- собранные `ZapretByNerd3n.exe`, установщик и релизные ZIP;
- `environment-check.json`, `.env`, ключи, токены и другие личные файлы.

Проверьте изменения внутри `bundle`: пользовательская замена `ACTIVE_*.bin`
или списков не должна случайно стать штатной конфигурацией выпуска. Движок,
списки и стратегии из выбранной ревизии upstream входят в исходный репозиторий
и поставку намеренно; их происхождение описано в `THIRD_PARTY.md`.

## 2. Проверить код и зафиксировать коммит

Для автоматических тестов сторонние Python-пакеты не требуются:

```powershell
py -3.13 -m unittest discover -s tests -v
```

Ожидаются успешные тесты; в среде без права создания символьных ссылок допустим
пропуск соответствующего теста. Актуальное число тестов смотрите в выводе,
а не используйте старое число как критерий успеха. Тест Windows Job Object
запускает и завершает только собственные безвредные Python-процессы. Тесты
сетевой логики используют подставные ответы; они не подтверждают обход DPI.

Чтобы проверить интерфейс без стартового определения сети и перебора стратегий:

```powershell
py -3.13 main.py --no-auto-setup --port 17842
```

Откроется локальная страница. Не нажимайте запуск стратегий или определение сети,
если выполняете только проверку UI. Для выхода используйте **Завершить приложение**.
Закрытие вкладки браузера не завершает сервер.

После проверок сделайте локальный commit. Через GitHub Desktop:

1. **File → Add local repository**: выберите папку проекта и добавьте её.
2. Убедитесь, что выбраны нужный репозиторий и ветка `main`.
3. В **Changes** просмотрите список файлов и diff; личные файлы и сборки туда попадать не должны.
4. Введите Summary, например `Prepare zapret by nerd3n 0.2.0`, и нажмите **Commit to main**.
5. Push можно выполнить после проверки получившихся артефактов, как описано ниже.

Добавление локального репозитория описано в
[документации GitHub Desktop](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-a-repository-from-your-local-computer-to-github-desktop).
Все следующие артефакты строятся из **этого зафиксированного коммита**, а не из
незакоммиченных файлов рабочей папки.

## 3. Создать чистый снимок и исходный ZIP

Следующий блок создаёт новую папку внутри игнорируемого `dist`. Старые сборки
и пользовательские данные не удаляются.

```powershell
$repo = (Get-Location).Path
$version = '0.2.0'
$commit = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0) { throw 'Не удалось получить коммит' }
if (git status --porcelain) { throw 'Сначала зафиксируйте или отдельно сохраните изменения' }

$forbidden = git ls-files | Where-Object {
    $_ -match '(^|/)(data|__pycache__|\.venv|\.build-env|build|dist|release-assets)(/|$)' -or
    $_ -match '\.py[co]$|(^|/)\.env($|\.)|(^|/)environment-check\.json$' -or
    $_ -match '^bundle/lists/.*-user\.txt$|^bundle/utils/(test results|logs)/' -or
    $_ -match '^bundle/.*\.(log|backup|test-backup\.txt)$|^bundle/utils/game_filter\.enabled$' -or
    $_ -match '(^|/)(ZapretByNerd3n|Zapret-by-nerd3n-Setup)\.exe$'
}
if ($forbidden) {
    $forbidden
    throw 'В Git уже отслеживаются файлы, не предназначенные для выпуска'
}

$releaseRoot = Join-Path $repo ('dist\release-' + $version + '-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Path $releaseRoot | Out-Null
$sourceZip = Join-Path $releaseRoot 'zapret-by-nerd3n-source.zip'
git archive --format=zip --prefix=zapret-by-nerd3n-source/ "--output=$sourceZip" $commit
if ($LASTEXITCODE -ne 0) { throw 'Не удалось собрать архив исходников' }
Expand-Archive -LiteralPath $sourceZip -DestinationPath (Join-Path $releaseRoot 'source')
$sourceRoot = Join-Path $releaseRoot 'source\zapret-by-nerd3n-source'
```

`git archive` включает отслеживаемые файлы выбранного коммита и не включает
локальные `data/`, кэши и окружение, если они не были добавлены в Git. ZIP
исходников содержит код оболочки, тесты, документацию, интерфейс, профиль и
комплект upstream. Он не содержит собранный EXE оболочки.

## 4. Собрать приложение

Продолжайте в том же PowerShell-окне, чтобы сохранить значения переменных:

```powershell
$venvRoot = Join-Path $releaseRoot 'build-env'
py -3.13 -m venv $venvRoot
if ($LASTEXITCODE -ne 0) { throw 'Не удалось создать окружение' }
$buildPython = Join-Path $venvRoot 'Scripts\python.exe'
& $buildPython -c 'import sys, struct; print(sys.version); print("bits:", struct.calcsize("P") * 8)'

& $buildPython -m pip install `
    'pyinstaller==6.22.3' `
    'pyinstaller-hooks-contrib==2026.7' `
    'altgraph==0.17.5' `
    'packaging==26.3' `
    'pefile==2024.8.26' `
    'pywin32-ctypes==0.2.3' `
    'setuptools==84.0.0'
if ($LASTEXITCODE -ne 0) { throw 'Не удалось установить инструменты сборки' }

Push-Location -LiteralPath $sourceRoot
try {
    & $buildPython -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw 'Тесты снимка исходников не прошли' }

    & $buildPython -m PyInstaller --noconfirm --clean --onefile --windowed --noupx `
        --name ZapretByNerd3n --add-data 'web:web' `
        --version-file app-version.txt main.py
    if ($LASTEXITCODE -ne 0) { throw 'Сборка EXE завершилась ошибкой' }
} finally {
    Pop-Location
}
```

Проверьте, что вывод Python сообщает 64 бита. Веб-интерфейс встраивается в EXE;
`bundle` и `profiles` устанавливаются **рядом** с EXE. Флаг `--uac-admin` не нужен:
повышением прав управляет аргумент приложения `--elevate`, который уже прописан
в установленном ярлыке. Параметры PyInstaller описаны в
[официальной документации](https://pyinstaller.org/en/stable/usage.html).

Флаг `--noupx` исключает влияние случайно установленного UPX. Ранее созданный
локальный `.spec` с абсолютными путями не требуется: он генерируется заново.

## 5. Подготовить переносную папку и установщик

Копируется только известный состав поставки из чистого снимка:

```powershell
$portableRoot = Join-Path $releaseRoot 'portable\zapret-by-nerd3n'
New-Item -ItemType Directory -Path $portableRoot | Out-Null
Copy-Item -LiteralPath (Join-Path $sourceRoot 'dist\ZapretByNerd3n.exe') -Destination $portableRoot

foreach ($folder in @('bundle', 'profiles', 'docs')) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $folder) -Destination $portableRoot -Recurse
}
foreach ($document in @('README.md', 'LICENSE', 'THIRD_PARTY.md', 'PYTHON-LICENSE.txt', 'GSAP-LICENSE.txt', 'VERIFICATION.md')) {
    Copy-Item -LiteralPath (Join-Path $sourceRoot $document) -Destination $portableRoot
}

$iscc = 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
& (Join-Path $sourceRoot 'installer\build-installer.ps1') `
    -AppDir $portableRoot -CompilerPath $iscc -OutputDir $releaseRoot -Version $version
```

Если Inno Setup расположен иначе, измените только `$iscc`. Используйте официальный
[Inno Setup 6.7.3](https://github.com/jrsoftware/issrc/releases/tag/is-6_7_3).
Скрипт проверяет обязательные файлы, компилирует установщик и пишет
`Zapret-by-nerd3n-Setup.exe.sha256`. Он не запускает установку.

Установщик содержит весь необходимый комплект и профиль
`profiles/infolink-shchelkovo.json`; пользователь не выбирает папку внешнего zapret.
Установка предназначена для текущего пользователя, путь по умолчанию —
`%LOCALAPPDATA%\ZapretByNerd3n`. Обычный ярлык вызывает `--auto --elevate`,
запуск после установки — `--auto` через UAC. Отмена UAC не отменяет установку.
Служба и автозапуск при входе в Windows не создаются.

Чтобы получить portable ZIP без потери файлов с именами, начинающимися с точки:

```powershell
$portableZip = Join-Path $releaseRoot 'zapret-by-nerd3n-portable.zip'
@'
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
import sys
root = Path(sys.argv[1]).resolve()
with ZipFile(sys.argv[2], "w", ZIP_DEFLATED, compresslevel=9) as archive:
    for path in sorted(root.rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(root.parent).as_posix())
'@ | & $buildPython - $portableRoot $portableZip
if ($LASTEXITCODE -ne 0) { throw 'Не удалось собрать переносной архив' }
```

Создавайте архив из этой подготовленной папки **до обычного запуска приложения**.
Даже запуск с `--no-auto-setup` создаёт `data/` и отсутствующие пользовательские
списки. Для проверки готового EXE распакуйте portable ZIP в отдельную тестовую
папку, запустите оттуда `ZapretByNerd3n.exe --no-auto-setup --port 17842` и
завершите через интерфейс. Не упаковывайте эту тестовую папку обратно в релиз.

## 6. Проверить состав, ограничения и SHA-256

Проверьте оба ZIP: отсутствуют `data`, пользовательские списки, кэши, локальные
логи, `.git` и виртуальные окружения. Исходный ZIP содержит исходники и тесты;
portable ZIP — EXE, bundle, профиль и документы. Не публикуйте `environment-check.json`.

Перед каждым выпуском проверьте интерфейс, отмену автоподбора и штатный выход.
Реальную установку/удаление желательно отдельно проверить на тестовом Windows-ПК.
Если этого не делали, прямо укажите это в описании выпуска. Сборка установщика
не равна проверке установки.

Сетевой прогон на линии Инфолинка проводится отдельно с разрешением владельца
подключения. Успешные HTTPS-проверки не доказывают воспроизведение видеопотока,
QUIC, WebSocket или голосовой UDP Discord. Не устанавливайте в профиле
`providerVerified`/`strategyVerified` в `true` без фактической проверки.

После окончательной сборки сформируйте контрольные суммы:

```powershell
$assetNames = @(
    'Zapret-by-nerd3n-Setup.exe',
    'zapret-by-nerd3n-portable.zip',
    'zapret-by-nerd3n-source.zip'
)
$checksumLines = foreach ($name in $assetNames) {
    $hash = (Get-FileHash -LiteralPath (Join-Path $releaseRoot $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $name"
}
[System.IO.File]::WriteAllLines((Join-Path $releaseRoot 'SHA256SUMS.txt'), $checksumLines, [System.Text.Encoding]::ASCII)

@("Version: $version", "Commit: $commit", 'Inno Setup: 6.7.3') |
    Set-Content -LiteralPath (Join-Path $releaseRoot 'BUILDINFO.txt') -Encoding UTF8
& $buildPython --version | Add-Content -LiteralPath (Join-Path $releaseRoot 'BUILDINFO.txt')
& $buildPython -m pip freeze | Add-Content -LiteralPath (Join-Path $releaseRoot 'BUILDINFO.txt')
```

После изменения хотя бы одного файла пересоберите соответствующий архив или
установщик и пересчитайте суммы. `SHA256SUMS.txt` помогает обнаружить повреждение
или замену файла; он не является цифровой подписью. Эта сборка EXE и установщика
не подписана сертификатом издателя.

## 7. Отправить main и создать GitHub Release вручную

В GitHub Desktop нажмите **Push origin** для ранее созданного коммита `main`.
Откройте репозиторий на GitHub и убедитесь, что последний коммит совпадает с
`$commit`. Если после сборки код изменился, соберите артефакты из нового коммита.
EXE и ZIP размещайте в **Release assets**, исходники — в дереве репозитория.

На [странице Releases](https://github.com/nerd-en/zapret-by-nerd3n/releases):

1. Нажмите **Draft a new release**.
2. В **Choose a tag** создайте `v0.2.0`; Target — `main` с проверенным коммитом.
3. Название: `zapret by nerd3n 0.2.0`.
4. Добавьте описание возможностей, требований и известных ограничений.
5. Прикрепите установщик, portable ZIP, source ZIP и `SHA256SUMS.txt`; при желании — `BUILDINFO.txt`.
6. Включите **This is a pre-release**. Сначала нажмите **Save draft**, проверьте состав, затем **Publish release**.

Порядок соответствует
[официальной инструкции GitHub](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository).
Автоматические GitHub-архивы `Source code (zip/tar.gz)` формируются по тегу;
отдельный source ZIP нужен для явно подготовленного именованного комплекта.

Готовый текст для копирования находится в [RELEASE_NOTES-v0.2.0.md](RELEASE_NOTES-v0.2.0.md). Краткий пример:

```markdown
## zapret by nerd3n 0.2.0 — предварительный выпуск

Приложение для Windows 10/11 x64 с комплектом Flowseal zapret,
22 штатными стратегиями, 6 дополнительными кандидатами и профилем
«Инфолинк · Щёлково». Есть автоматическое сравнение, отмена и JSON-отчёты.

Для установки скачайте Zapret-by-nerd3n-Setup.exe.
Для переносного запуска распакуйте весь zapret-by-nerd3n-portable.zip.
Python для готовой программы не требуется. Для запуска winws нужны права администратора.

Работоспособность стратегий на реальной линии Инфолинка ещё не подтверждена.
Автоматические измерения проверяют HTTPS; видео YouTube, QUIC,
WebSocket и голос Discord требуют отдельной ручной проверки.

Контрольные суммы: SHA256SUMS.txt. Исходники: zapret-by-nerd3n-source.zip.
Лицензия оболочки — MIT; лицензии зависимостей сохранены в поставке.
```

Не переиспользуйте опубликованный тег для исправленного бинарника. Для изменений
подготовьте следующую версию, например `v0.2.1`, с её исходниками и суммами.

## Необязательно: создать черновик через gh

Этот вариант заменяет создание черновика в браузере. Он не выполняется при сборке.
Сначала отправьте нужный коммит на GitHub и сохраните текст описания отдельным
файлом `release-notes.md` в `$releaseRoot`.

```powershell
$assets = @(
    (Join-Path $releaseRoot 'Zapret-by-nerd3n-Setup.exe'),
    (Join-Path $releaseRoot 'zapret-by-nerd3n-portable.zip'),
    (Join-Path $releaseRoot 'zapret-by-nerd3n-source.zip'),
    (Join-Path $releaseRoot 'SHA256SUMS.txt')
)
gh release create "v$version" @assets `
    --repo nerd-en/zapret-by-nerd3n --target $commit `
    --title "zapret by nerd3n $version" `
    --notes-file (Join-Path $releaseRoot 'release-notes.md') `
    --draft --prerelease
```

Откройте черновик в браузере, проверьте прикреплённые файлы и опубликуйте вручную.
Справка параметров: [gh release create](https://cli.github.com/manual/gh_release_create).
