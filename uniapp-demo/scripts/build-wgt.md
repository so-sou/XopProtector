# Build / export `__UNI__XOPDEMO`

## Recommended — uni CLI (this repo)

```bat
cd uniapp-demo
npm install
npm run build:app
cd ..
gradlew.bat syncUnimpXopDemoAssets
```

Or one shot:

```bat
gradlew.bat buildUnimpXopDemo syncUnimpXopDemoAssets
```

Output layout for UniMP:

```text
unimp-host/src/main/assets/apps/__UNI__XOPDEMO/www/
unimp-host/src/main/assets/__UNI__XOPDEMO.wgt
```

## Alternative — HBuilderX

1. Open `uniapp-demo/` (or import as uni-app project)
2. Confirm `src/manifest.json` → `appid` = `__UNI__XOPDEMO`
3. 发行 → 原生 App-本地打包 / 制作 wgt
4. Copy `www` or `.wgt` into the paths above

## Host open order

1. assets www markers (`manifest.json` / `app-config-service.js`)
2. else `assets/__UNI__XOPDEMO.wgt` → `releaseWgtToRunPath`
3. else SDK sample `__UNI__F743940`
