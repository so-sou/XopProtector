# Build a self-contained Windows desktop distribution:
#   dist/XopProtector/XopProtector.exe
#   dist/XopProtector/engine/{runtime,protector-packer.jar,shell-files}
# Optional Inno Setup installer:
#   dist/XopProtector-Setup-<ver>.exe
param(
    [switch]$SkipNativeShell,
    [switch]$SkipJlink,
    [switch]$SkipInstaller,
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Dist = Join-Path $Root "dist\XopProtector"
$Engine = Join-Path $Dist "engine"
$RuntimeDir = Join-Path $Engine "runtime"

Write-Host "==> :packer:jar"
& .\gradlew.bat :packer:jar
if ($LASTEXITCODE -ne 0) { throw "packer jar failed" }

$jar = Get-ChildItem (Join-Path $Root "packer\build\libs\protector-packer-*.jar") |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($null -eq $jar) { throw "protector-packer-*.jar not found" }
Write-Host "    $($jar.FullName)"

$shellSrc = Join-Path $Root "executable\shell-files"
if (-not $SkipNativeShell) {
    Write-Host "==> exportShellFiles"
    & .\gradlew.bat exportShellFiles
    if ($LASTEXITCODE -ne 0) { throw "exportShellFiles failed" }
}
if (!(Test-Path (Join-Path $shellSrc "dex\classes.dex"))) {
    throw "Missing shell-files at $shellSrc (run exportShellFiles or omit -SkipNativeShell)"
}

Write-Host "==> dotnet publish ($Configuration / $Runtime)"
$proj = Join-Path $Root "desktop\Protector.Desktop\Protector.Desktop.csproj"
$publishOut = Join-Path $Root "desktop\Protector.Desktop\bin\publish\$Runtime"
& dotnet publish $proj -c $Configuration -r $Runtime --self-contained true `
    -p:PublishSingleFile=false `
    -o $publishOut
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

Write-Host "==> assemble $Dist"
if (Test-Path $Dist) { Remove-Item $Dist -Recurse -Force }
New-Item -ItemType Directory -Path $Engine -Force | Out-Null
Copy-Item (Join-Path $publishOut "*") $Dist -Recurse -Force
Copy-Item $jar.FullName (Join-Path $Engine "protector-packer.jar") -Force
Copy-Item $shellSrc (Join-Path $Engine "shell-files") -Recurse -Force

if (-not $SkipJlink) {
    $javaHome = $env:JAVA_HOME
    if ([string]::IsNullOrWhiteSpace($javaHome)) {
        $javaCmd = Get-Command java -ErrorAction SilentlyContinue
        if ($null -eq $javaCmd) { throw "JAVA_HOME not set and java not on PATH" }
        $javaHome = Split-Path (Split-Path $javaCmd.Source -Parent) -Parent
    }
    $jlink = Join-Path $javaHome "bin\jlink.exe"
    if (!(Test-Path $jlink)) { throw "jlink not found: $jlink" }

    Write-Host "==> jlink runtime -> $RuntimeDir"
    if (Test-Path $RuntimeDir) { Remove-Item $RuntimeDir -Recurse -Force }
    # Modules used by the packer fat jar (dexlib2 / guava / zip / crypto / apksig).
    $modules = @(
        "java.base",
        "java.logging",
        "java.xml",
        "java.desktop",
        "java.management",
        "java.naming",
        "java.security.jgss",
        "java.sql",
        "jdk.crypto.ec",
        "jdk.unsupported",
        "jdk.zipfs"
    ) -join ","
    & $jlink `
        --add-modules $modules `
        --strip-debug `
        --no-header-files `
        --no-man-pages `
        --compress=2 `
        --output $RuntimeDir
    if ($LASTEXITCODE -ne 0) { throw "jlink failed" }
} else {
    Write-Host "==> SkipJlink: release will require JAVA_HOME / PATH java at runtime"
}

Write-Host ""
Write-Host "Done: $Dist"
Write-Host "  XopProtector.exe"
Write-Host "  engine\protector-packer.jar"
Write-Host "  engine\shell-files\"
if (-not $SkipJlink) { Write-Host "  engine\runtime\" }

if (-not $SkipInstaller) {
    Write-Host ""
    Write-Host "==> Inno Setup installer"
    & (Join-Path $PSScriptRoot "build-installer.ps1")
    if ($LASTEXITCODE -eq 2) {
        Write-Host "WARN: ISCC not installed — skipped Setup.exe (folder release is ready)."
    } elseif ($LASTEXITCODE -ne 0) {
        throw "build-installer.ps1 failed"
    }
}
