[CmdletBinding()]
param(
    [string]$AppDir = (Split-Path -Parent $PSScriptRoot),
    [string]$CompilerPath = '',
    [string]$OutputDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'dist'),
    [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?$')]
    [string]$Version = '0.3.5'
)

$ErrorActionPreference = 'Stop'
$stageRoot = (Resolve-Path -LiteralPath $AppDir).Path
$requiredFiles = @(
    'ZapretByNerd3n.exe', 'assets\app.ico', 'README.md', 'LICENSE', 'THIRD_PARTY.md',
    'PYTHON-LICENSE.txt', 'GSAP-LICENSE.txt', 'DESKTOP-LICENSES.txt', 'VERIFICATION.md', 'docs\RELEASING.md',
    'profiles\infolink-shchelkovo.json',
    'bundle\general.bat', 'bundle\LICENSE.txt', 'bundle\bin\winws.exe',
    'bundle\bin\WinDivert.dll', 'bundle\bin\WinDivert64.sys',
    'bundle\bin\cygwin1.dll', 'bundle\bin\ACTIVE_DISCORD_UDP.bin',
    'bundle\bin\ACTIVE_GAME_UDP.bin'
)
foreach ($relativeFile in $requiredFiles) {
    $requiredPath = Join-Path $stageRoot $relativeFile
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Missing staged file: $requiredPath. Build the application before its installer."
    }
}

if (-not $CompilerPath) {
    $candidates = @()
    if ($env:ZAPRET_ISCC) { $candidates += $env:ZAPRET_ISCC }
    $pathCommand = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($pathCommand) { $candidates += $pathCommand.Source }
    $candidates += @(
        'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 6\ISCC.exe',
        'C:\Program Files\Inno Setup 7\ISCC.exe'
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $CompilerPath = $candidate
            break
        }
    }
}
if (-not $CompilerPath -or -not (Test-Path -LiteralPath $CompilerPath -PathType Leaf)) {
    throw 'Inno Setup compiler not found. Pass -CompilerPath with the full path to ISCC.exe.'
}
$compiler = (Resolve-Path -LiteralPath $CompilerPath).Path
$destination = [System.IO.Path]::GetFullPath($OutputDir)
New-Item -ItemType Directory -Path $destination -Force | Out-Null
$script = Join-Path $PSScriptRoot 'ZapretByNerd3n.iss'
# PowerShell passes an argument array; never compose a command or invoke a shell.
& $compiler ("/DAppSource=$stageRoot") ("/DSetupOutput=$destination") ("/DAppVersion=$Version") $script
if ($LASTEXITCODE -ne 0) {
    throw "Installer compilation failed with exit code $LASTEXITCODE"
}
$setupPath = Join-Path $destination 'Zapret-by-nerd3n-Setup.exe'
if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw 'Compiler reported success but Zapret-by-nerd3n-Setup.exe was not created.'
}
$digest = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
[System.IO.File]::WriteAllText((Join-Path $destination 'Zapret-by-nerd3n-Setup.exe.sha256'), "$digest  Zapret-by-nerd3n-Setup.exe`r`n", [System.Text.Encoding]::ASCII)
Write-Output "Created installer: $setupPath"
Write-Output "SHA-256: $digest"
