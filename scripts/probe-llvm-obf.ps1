# Probe whether the active NDK clang accepts OLLVM/Hikari -mllvm passes.
# Usage:
#   .\scripts\probe-llvm-obf.ps1
#   .\scripts\probe-llvm-obf.ps1 -Clang "D:\toolchains\hikari\bin\clang++.exe"
param(
    [string]$Clang = "",
    [string]$Flags = "-mllvm -fla -mllvm -bcf -mllvm -sub"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

function Resolve-NdkClang {
    if (![string]::IsNullOrWhiteSpace($Clang) -and (Test-Path $Clang)) {
        return (Resolve-Path $Clang).Path
    }
    $sdk = $null
    foreach ($envName in @("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($envName)
        if (![string]::IsNullOrWhiteSpace($v) -and (Test-Path $v)) {
            $sdk = $v
            break
        }
    }
    if ($null -eq $sdk) {
        $localProps = Join-Path $Root "local.properties"
        if (Test-Path $localProps) {
            foreach ($line in Get-Content $localProps) {
                if ($line -match '^\s*ndk\.dir\s*=\s*(.+)\s*$') {
                    $sdk = $Matches[1].Trim() -replace '\\\\', '\'
                }
            }
        }
    }
    if ($null -eq $sdk -or !(Test-Path $sdk)) {
        throw "NDK clang not found. Pass -Clang or set ANDROID_NDK_HOME / ndk.dir"
    }
    $candidates = @(
        (Join-Path $sdk "toolchains\llvm\prebuilt\windows-x86_64\bin\clang++.exe"),
        (Join-Path $sdk "toolchains\llvm\prebuilt\linux-x86_64\bin\clang++")
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { return (Resolve-Path $c).Path }
    }
    throw "clang++ not found under NDK: $sdk"
}

$cxx = Resolve-NdkClang
Write-Host "clang++: $cxx"
Write-Host "flags:   $Flags"

$tmp = Join-Path $env:TEMP "protector-obf-probe.cpp"
$obj = Join-Path $env:TEMP "protector-obf-probe.o"
@"
int foo(int x) {
  if (x > 0) return x * 2;
  return x - 1;
}
"@ | Set-Content -Encoding ASCII $tmp

$flagArr = $Flags -split '\s+' | Where-Object { $_ -ne '' }
& $cxx -c $tmp -o $obj @flagArr 2>&1 | Tee-Object -Variable out
if ($LASTEXITCODE -ne 0) {
    Write-Host ""
    Write-Host "FAIL: stock/custom clang rejected obfuscation flags."
    Write-Host "Use an OLLVM/Hikari NDK build, then:"
    Write-Host "  .\gradlew.bat :native:assembleRelease -Pprotector.llvmObf=true"
    exit 1
}
Write-Host "OK: clang accepts obfuscation flags. Enable with -Pprotector.llvmObf=true"
Remove-Item $tmp, $obj -ErrorAction SilentlyContinue
exit 0
