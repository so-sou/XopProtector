# UniMP Host Demo (XopProtector white-screen regression)

Android host + **uni-app Vue3 (vite / uni CLI)** resource package for validating
XopProtector against **DCloud UniMP SDK 5.14**.

## Layout

| Path | Role |
|------|------|
| `unimp-host/` | Gradle app module (`com.yqsh.unimpdemo`) |
| `uniapp-demo/` | uni-app Vue3 + Vite source (`appid=__UNI__XOPDEMO`) |
| `scripts/protect-unimp-demo.bat` | Build + protect shortcut |
| `scripts/verify-unimp-demo.ps1` | Emulator A/B smoke |
| Gradle `buildUnimpXopDemo` | `npm run build:app` |
| Gradle `syncUnimpXopDemoAssets` | Copy `dist/build/app` → host assets |
| Gradle `syncUnimpSampleAssets` | SDK DEMO `__UNI__F743940` fallback |
| Gradle `checkUnimpDemo` | CI: assembleRelease + packer tests + asset sanity (no device) |
| Gradle `protectUnimpDemo` | balanced + SO safe + payment VMP |

## Prerequisites

1. UniMP Android SDK 5.14 — set `unimp.sdk.libs` in `gradle.properties`
2. **Node.js 18+** (for exporting `__UNI__XOPDEMO`)
3. Once:

```bat
gradlew.bat syncUnimpSampleAssets
cd uniapp-demo && npm install && npm run build:app && cd ..
gradlew.bat syncUnimpXopDemoAssets
```

## Export probe app (no HBuilderX required)

```bat
gradlew.bat buildUnimpXopDemo syncUnimpXopDemoAssets
```

Produces:

- `unimp-host/src/main/assets/apps/__UNI__XOPDEMO/www/`
- `unimp-host/src/main/assets/__UNI__XOPDEMO.wgt` (optional `releaseWgtToRunPath` path)

HBuilderX remains supported — see [scripts/build-wgt.md](scripts/build-wgt.md).

### Probe pages

| Tab | Stress |
|-----|--------|
| 首页 | launch probe, network image, storage, subPackage |
| 列表 | 200+ rows, pull-refresh, `uni.request` |
| WebView | multi-process web-view |
| 主题 | `setTabBarStyle` (classic white-screen tell) |
| 原生 | storage / vibrate / chooseImage |
| 分包 | navigateTo |

Log tag: `[XOP-DEMO] page-show:...`

## Build & protect

```bat
gradlew.bat :unimp-host:assembleDebug
gradlew.bat protectUnimpDemo
powershell -File scripts\verify-unimp-demo.ps1 -Mode protected
```

Install tip (if `adb install` incremental fails):

```bat
adb push executable\unimp-demo-protected.apk /data/local/tmp/unimp.apk
adb shell pm install -r -t /data/local/tmp/unimp.apk
```

Host preference: `__UNI__XOPDEMO` (www or wgt) → else `__UNI__F743940`.

## CI (no device)

```bat
gradlew.bat checkUnimpDemo
```

Runs `:unimp-host:assembleRelease`, `:packer:test`, `exportShellFiles`, and sanity-checks
UniMP assets + packer jar. Use `protectUnimpDemo` for a full pack; use
`scripts\verify-unimp-demo.ps1` on a device/emulator afterwards.

Probe pages call `uni.sendNativeEvent('xop-probe', …)` so host logcat shows
`[XOP-DEMO] page-show:<name>` even when JS `console.log` is hard to filter.
On some x86 emulators Weex/UTS may still race (`initUTS` NPE) — prefer a real
arm64 device for the Phase 4 tab checklist.

Host ships `assets/data/dcloud_properties.xml` (copied from SDK DEMO) so modules
like **File** are registered; otherwise HTML5+ Runtime pops “打包时未添加 xxx 模块”.

`uniapp-demo` CLI packages are pinned to **`3.0.0-5010420260703001` (HBuilderX 5.14)**
to match UniMP Android SDK 5.14 and avoid the “编译器 5.xx 与 SDK 不匹配” dialog.

