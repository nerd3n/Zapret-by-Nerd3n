[CmdletBinding()]
param(
    [string]$BuildPython = '',
    [string]$OutputDir = ''
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $BuildPython) {
    $BuildPython = Join-Path $projectRoot '.build-env\Scripts\python.exe'
}
if (-not (Test-Path -LiteralPath $BuildPython -PathType Leaf)) {
    throw 'Build Python not found. Create .build-env and install requirements.txt and PyInstaller, or pass -BuildPython.'
}
$pythonPath = (Resolve-Path -LiteralPath $BuildPython).Path
if (-not $OutputDir) { $OutputDir = Join-Path $projectRoot 'dist' }
$destination = [System.IO.Path]::GetFullPath($OutputDir)
$buildDirectory = Join-Path $projectRoot 'build\desktop'
$payloadPath = Join-Path $buildDirectory 'payload.zip'
New-Item -ItemType Directory -Path $destination, $buildDirectory -Force | Out-Null

& $pythonPath (Join-Path $PSScriptRoot 'build_payload.py') --root $projectRoot --output $payloadPath
if ($LASTEXITCODE -ne 0) { throw "Embedded payload build failed with exit code $LASTEXITCODE" }

$buildArguments = @(
    '-m', 'PyInstaller', '--noconfirm', '--clean', '--onefile', '--windowed', '--noupx',
    '--name', 'ZapretByNerd3n',
    '--icon', (Join-Path $projectRoot 'assets\app.ico'),
    '--add-data', ((Join-Path $projectRoot 'web') + ';web'),
    '--add-data', ($payloadPath + ';.'),
    '--collect-data', 'webview',
    '--hidden-import', 'webview.platforms.winforms',
    '--hidden-import', 'webview.platforms.edgechromium',
    '--version-file', (Join-Path $projectRoot 'app-version.txt'),
    '--distpath', $destination,
    '--workpath', (Join-Path $buildDirectory 'pyinstaller'),
    '--specpath', $buildDirectory,
    (Join-Path $projectRoot 'main.py')
)
& $pythonPath @buildArguments
if ($LASTEXITCODE -ne 0) { throw "Desktop build failed with exit code $LASTEXITCODE" }
$executable = Join-Path $destination 'ZapretByNerd3n.exe'
if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
    throw 'PyInstaller reported success but ZapretByNerd3n.exe was not created.'
}
$installerSource = Join-Path $projectRoot 'ZapretByNerd3n.exe'
if ($executable -ne $installerSource) {
    Copy-Item -LiteralPath $executable -Destination $installerSource -Force
}
$digest = (Get-FileHash -LiteralPath $executable -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText(($executable + '.sha256'), "$digest  ZapretByNerd3n.exe`r`n", [System.Text.Encoding]::ASCII)
Write-Output "Created standalone executable: $executable"
Write-Output "SHA-256: $digest"
