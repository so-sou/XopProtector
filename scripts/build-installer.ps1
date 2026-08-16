# Build Inno Setup installer for XopProtector.
# Prerequisite: dist\XopProtector\ already assembled (scripts\release-desktop.ps1).
# Optional: install Inno Setup 6 — https://jrsoftware.org/isinfo.php
param(
    [string]$IssFile = "",
    [switch]$SkipCheck
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($IssFile)) {
    $IssFile = Join-Path $Root "installer\XOP-Protector.iss"
}

$DistApp = Join-Path $Root "dist\XopProtector\XopProtector.exe"
if (-not (Test-Path $DistApp)) {
    throw "Missing $DistApp — run scripts\release-desktop.ps1 first."
}
$Engine = Join-Path $Root "dist\XopProtector\engine"
if (-not $SkipCheck) {
    if (-not (Test-Path (Join-Path $Engine "protector-packer.jar"))) {
        throw "Missing engine\protector-packer.jar"
    }
    if (-not (Test-Path (Join-Path $Engine "shell-files\dex\classes.dex"))) {
        throw "Missing engine\shell-files"
    }
}

function Find-ISCC {
    $candidates = @(
        "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
        "${env:ProgramFiles}\Inno Setup 6\ISCC.exe",
        "${env:LocalAppData}\Programs\Inno Setup 6\ISCC.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return $c }
    }
    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

$iscc = Find-ISCC
if ($null -eq $iscc) {
    Write-Host ""
    Write-Host "Inno Setup 6 (ISCC.exe) not found."
    Write-Host "1) Install from https://jrsoftware.org/isdl.php"
    Write-Host "2) Or open installer\XOP-Protector.iss in Inno Setup Compiler and Build."
    Write-Host ""
    Write-Host "Script ready: $IssFile"
    exit 2
}

Write-Host "==> ISCC: $iscc"
Write-Host "==> Compiling $IssFile"
& $iscc $IssFile
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit $LASTEXITCODE" }

$setup = Get-ChildItem (Join-Path $Root "dist") -Filter "XopProtector-Setup-*.exe" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($null -eq $setup) {
    $setup = Get-ChildItem (Join-Path $Root "dist") -Filter "XOP*-Setup-*.exe" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}
if ($null -eq $setup) { throw "Setup exe not found under dist\" }

Write-Host ""
Write-Host "Done: $($setup.FullName)"
Write-Host ("Size: {0:N1} MB" -f ($setup.Length / 1MB))
