# Contributing

Thanks for contributing to Protector. Please read this before opening a PR.

## Prerequisites

| Tool | Purpose |
|------|---------|
| JDK 17+ | Packer jar and Gradle Android builds |
| Android SDK + NDK | `:native`, `:demo`, `exportShellFiles` |
| .NET SDK 7+ | Windows desktop (`desktop/Protector.Desktop`) |
| Inno Setup 6 (optional) | Windows installer |

## Build

From the repository root:

```bat
gradlew.bat :packer:jar
gradlew.bat exportShellFiles
gradlew.bat :demo:assembleRelease
```

Desktop (dev):

```bat
cd desktop
dotnet run --project Protector.Desktop
```

Protected demo smoke (requires `ANDROID_HOME` or `ANDROID_SDK_ROOT`):

```bat
powershell -ExecutionPolicy Bypass -File scripts\release-demo.ps1 -SkipInstall
```

## Pull requests

1. Keep changes focused; prefer small PRs over large mixed refactors.
2. Match existing code style in the module you touch.
3. Do not commit secrets, keystores, customer APKs, or machine-local paths.
4. If you change user-visible desktop strings, update both
   `desktop/Protector.Desktop/Resources/Strings.resx` (English default) and
   `Strings.zh-CN.resx`.
5. Describe *why* the change is needed in the PR description.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0 (see `LICENSE`).
