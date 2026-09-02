# UniMP host module

See [../uniapp-demo/README.md](../uniapp-demo/README.md) for full instructions.

```bat
gradlew.bat syncUnimpSampleAssets
gradlew.bat buildUnimpXopDemo syncUnimpXopDemoAssets
gradlew.bat :unimp-host:assembleDebug
gradlew.bat protectUnimpDemo
powershell -File scripts\verify-unimp-demo.ps1 -Mode protected
```

Open order: `__UNI__XOPDEMO` (CLI-built www/wgt) → else `__UNI__F743940`.
