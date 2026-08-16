# Pack, sign, install, and smoke-test the protected demo APK.
param(
    [string]$Serial = "",
    [string]$SdkRoot = "",
    [switch]$SkipInstall
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

function Resolve-AndroidSdkRoot {
    param([string]$Explicit)

    if (![string]::IsNullOrWhiteSpace($Explicit) -and (Test-Path $Explicit)) {
        return (Resolve-Path $Explicit).Path
    }
    foreach ($envName in @("ANDROID_HOME", "ANDROID_SDK_ROOT")) {
        $v = [Environment]::GetEnvironmentVariable($envName)
        if (![string]::IsNullOrWhiteSpace($v) -and (Test-Path $v)) {
            return (Resolve-Path $v).Path
        }
    }
    $localProps = Join-Path $Root "local.properties"
    if (Test-Path $localProps) {
        foreach ($line in Get-Content $localProps) {
            if ($line -match '^\s*sdk\.dir\s*=\s*(.+)\s*$') {
                $raw = $Matches[1].Trim()
                # Gradle local.properties uses escaped backslashes on Windows
                $path = $raw -replace '\\\\', '\'
                if (Test-Path $path) {
                    return (Resolve-Path $path).Path
                }
            }
        }
    }
    throw "Android SDK not found. Set -SdkRoot, ANDROID_HOME, ANDROID_SDK_ROOT, or sdk.dir in local.properties."
}

$SdkRoot = Resolve-AndroidSdkRoot -Explicit $SdkRoot
Write-Host "==> SDK: $SdkRoot"

Write-Host "==> gradlew protectDemo"
& .\gradlew.bat protectDemo
if ($LASTEXITCODE -ne 0) { throw "protectDemo failed" }

$apk = Join-Path $Root "executable\demo-protected.apk"
if (!(Test-Path $apk)) { throw "missing $apk" }

# protectDemo already signs with debug.keystore + channel=demo.
$signed = $apk

$bt = Get-ChildItem (Join-Path $SdkRoot "build-tools") | Sort-Object Name -Descending | Select-Object -First 1
if ($null -eq $bt) { throw "build-tools not found under $SdkRoot" }
$adb = Join-Path $SdkRoot "platform-tools\adb.exe"

if ($SkipInstall) {
    Write-Host "Signed APK: $signed"
    exit 0
}

$adbArgs = @()
if ($Serial -ne "") { $adbArgs += @("-s", $Serial) }

Write-Host "==> install"
& $adb @adbArgs install -r --no-incremental $signed
if ($LASTEXITCODE -ne 0) { throw "adb install failed" }

& $adb @adbArgs logcat -c
& $adb @adbArgs shell am start -n com.yqsh.protectordemo/.MainActivity
Start-Sleep -Seconds 4
Write-Host "==> logcat"
& $adb @adbArgs logcat -d | Select-String -Pattern "protector-demo|decrypted business SO|DemoApp"
