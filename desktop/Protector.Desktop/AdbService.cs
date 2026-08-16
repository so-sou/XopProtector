using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Protector.Desktop;

/// <summary>
/// Locates adb and lists/installs/launches on USB Android devices.
/// </summary>
internal static class AdbService
{
    public sealed class Device
    {
        public string Serial { get; init; } = "";
        public string Model { get; init; } = "";
        public string DisplayName =>
            string.IsNullOrWhiteSpace(Model) ? Serial : $"{Model} ({Serial})";

        public override string ToString() => DisplayName;
    }

    public sealed class InstallResult
    {
        public bool Ok { get; init; }
        public string Message { get; init; } = "";
        public string? PackageName { get; init; }
        public bool Launched { get; init; }
    }

    private static readonly Regex DeviceLine = new(
        @"^(?<serial>\S+)\s+device(?:\s+(?<props>.*))?$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PropPair = new(
        @"(?<k>\w+):(?<v>\S+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PackageNameRe = new(
        @"package:\s*name='(?<pkg>[^']+)'",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PackageListLine = new(
        @"^package:(?<pkg>\S+)$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex EnginePackageLine = new(
        @"^Package:\s*(?<pkg>[A-Za-z0-9._]+)\s*$",
        RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.Multiline);

    public static string? FindAdb()
    {
        foreach (var root in SdkRoots())
        {
            var candidate = Path.Combine(root, "platform-tools", "adb.exe");
            if (File.Exists(candidate))
                return candidate;
            candidate = Path.Combine(root, "platform-tools", "adb");
            if (File.Exists(candidate))
                return candidate;
        }

        return FindOnPath("adb.exe") ?? FindOnPath("adb");
    }

    public static async Task<IReadOnlyList<Device>> ListDevicesAsync(CancellationToken ct = default)
    {
        var adb = FindAdb();
        if (adb == null)
            return Array.Empty<Device>();

        var (code, stdout, _) = await RunAsync(adb, new[] { "devices", "-l" }, ct).ConfigureAwait(false);
        if (code != 0 || string.IsNullOrWhiteSpace(stdout))
            return Array.Empty<Device>();

        var list = new List<Device>();
        foreach (var raw in stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            if (line.StartsWith("List of devices", StringComparison.OrdinalIgnoreCase))
                continue;

            var m = DeviceLine.Match(line);
            if (!m.Success)
                continue;

            var serial = m.Groups["serial"].Value;
            var model = "";
            var props = m.Groups["props"].Value;
            if (!string.IsNullOrEmpty(props))
            {
                foreach (Match pm in PropPair.Matches(props))
                {
                    var key = pm.Groups["k"].Value;
                    if (key.Equals("model", StringComparison.OrdinalIgnoreCase)
                        || (string.IsNullOrEmpty(model) && key.Equals("device", StringComparison.OrdinalIgnoreCase)))
                    {
                        model = pm.Groups["v"].Value.Replace('_', ' ');
                        if (key.Equals("model", StringComparison.OrdinalIgnoreCase))
                            break;
                    }
                }
            }

            list.Add(new Device { Serial = serial, Model = model });
        }

        return list;
    }

    /// <summary>
    /// Install with flags that work for testOnly + modern adb incremental path,
    /// then launch the app's LAUNCHER activity when possible.
    /// </summary>
    /// <param name="packageHint">Optional package from protect logs / UI cache.</param>
    public static async Task<InstallResult> InstallAndLaunchAsync(
        string serial, string apkPath, string? packageHint = null, CancellationToken ct = default)
    {
        var pkg = FirstNonEmpty(
            packageHint,
            ApkPackageName.TryRead(apkPath),
            await TryResolvePackageViaAaptAsync(apkPath, ct).ConfigureAwait(false));

        HashSet<string>? before = null;
        if (string.IsNullOrWhiteSpace(pkg))
            before = await ListPackagesAsync(serial, ct).ConfigureAwait(false);

        var install = await InstallAsync(serial, apkPath, pkg, ct).ConfigureAwait(false);
        if (!install.Ok)
            return install;

        pkg = FirstNonEmpty(
            install.PackageName,
            pkg,
            await TryResolvePackageViaAaptAsync(apkPath, ct).ConfigureAwait(false),
            ApkPackageName.TryRead(apkPath));

        if (string.IsNullOrWhiteSpace(pkg) && before != null)
        {
            var after = await ListPackagesAsync(serial, ct).ConfigureAwait(false);
            var added = after.Where(p => !before.Contains(p)).ToList();
            if (added.Count == 1)
                pkg = added[0];
        }

        if (string.IsNullOrWhiteSpace(pkg))
        {
            return new InstallResult
            {
                Ok = true,
                PackageName = null,
                Launched = false,
                Message = install.Message + "\n(launch skipped: package name unknown)"
            };
        }

        var launch = await LaunchAsync(serial, pkg, ct).ConfigureAwait(false);
        return new InstallResult
        {
            Ok = true,
            PackageName = pkg,
            Launched = launch.Ok,
            Message = launch.Ok
                ? install.Message + "\n" + launch.Message
                : install.Message + "\nlaunch failed: " + launch.Message
        };
    }

    public static async Task<InstallResult> InstallAsync(
        string serial, string apkPath, string? packageHint = null, CancellationToken ct = default)
    {
        var adb = FindAdb();
        if (adb == null)
            return new InstallResult { Ok = false, Message = "adb not found" };

        if (string.IsNullOrWhiteSpace(serial))
            return new InstallResult { Ok = false, Message = "no device selected" };

        if (string.IsNullOrWhiteSpace(apkPath) || !File.Exists(apkPath))
            return new InstallResult { Ok = false, Message = "apk missing" };

        // --no-incremental: modern adb incremental path often ignores -t (TEST_ONLY).
        // -t: allow android:testOnly APKs (common for debug inputs).
        var (code, stdout, stderr) = await RunAsync(
            adb,
            new[] { "-s", serial, "install", "--no-incremental", "-r", "-t", apkPath },
            ct).ConfigureAwait(false);

        var text = (stdout + "\n" + stderr).Trim();
        var pkg = FirstNonEmpty(
            packageHint,
            ApkPackageName.TryRead(apkPath),
            await TryResolvePackageViaAaptAsync(apkPath, ct).ConfigureAwait(false));

        if (code == 0 && text.Contains("Success", StringComparison.OrdinalIgnoreCase))
            return new InstallResult { Ok = true, Message = text, PackageName = pkg };

        if (code == 0 && string.IsNullOrWhiteSpace(text))
            return new InstallResult { Ok = true, Message = "Success", PackageName = pkg };

        return new InstallResult
        {
            Ok = false,
            PackageName = pkg,
            Message = string.IsNullOrWhiteSpace(text) ? $"adb exit {code}" : text
        };
    }

    public static async Task<InstallResult> LaunchAsync(
        string serial, string packageName, CancellationToken ct = default)
    {
        var adb = FindAdb();
        if (adb == null)
            return new InstallResult { Ok = false, Message = "adb not found" };

        if (string.IsNullOrWhiteSpace(packageName))
            return new InstallResult { Ok = false, Message = "package empty" };

        // Prefer monkey: does not need the concrete activity class name.
        var (code, stdout, stderr) = await RunAsync(
            adb,
            new[]
            {
                "-s", serial, "shell", "monkey",
                "-p", packageName,
                "-c", "android.intent.category.LAUNCHER",
                "1"
            },
            ct).ConfigureAwait(false);

        var text = (stdout + "\n" + stderr).Trim();
        if (code == 0 && !text.Contains("No activities found", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("Error", StringComparison.OrdinalIgnoreCase)
            && !text.Contains("aborted", StringComparison.OrdinalIgnoreCase))
        {
            return new InstallResult
            {
                Ok = true,
                PackageName = packageName,
                Launched = true,
                Message = "launched " + packageName
            };
        }

        // Fallback: resolve LAUNCHER component then am start.
        var (rc2, out2, err2) = await RunAsync(
            adb,
            new[]
            {
                "-s", serial, "shell", "cmd", "package", "resolve-activity",
                "--brief", "-c", "android.intent.category.LAUNCHER", packageName
            },
            ct).ConfigureAwait(false);

        var brief = (out2 + "\n" + err2).Trim();
        var component = brief.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(s => s.Trim())
            .LastOrDefault(s => s.Contains('/'));

        if (rc2 == 0 && !string.IsNullOrWhiteSpace(component))
        {
            var (rc3, out3, err3) = await RunAsync(
                adb,
                new[] { "-s", serial, "shell", "am", "start", "-n", component },
                ct).ConfigureAwait(false);
            var t3 = (out3 + "\n" + err3).Trim();
            if (rc3 == 0 && !t3.Contains("Error type", StringComparison.OrdinalIgnoreCase)
                && !t3.Contains("Exception", StringComparison.OrdinalIgnoreCase))
            {
                return new InstallResult
                {
                    Ok = true,
                    PackageName = packageName,
                    Launched = true,
                    Message = "launched " + component
                };
            }

            return new InstallResult
            {
                Ok = false,
                PackageName = packageName,
                Message = string.IsNullOrWhiteSpace(t3) ? $"am start exit {rc3}" : t3
            };
        }

        return new InstallResult
        {
            Ok = false,
            PackageName = packageName,
            Message = string.IsNullOrWhiteSpace(text) ? $"monkey exit {code}" : text
        };
    }

    public static string? TryParsePackageFromEngineLog(string? logText)
    {
        if (string.IsNullOrWhiteSpace(logText))
            return null;
        var m = EnginePackageLine.Match(logText);
        return m.Success ? m.Groups["pkg"].Value : null;
    }

    public static async Task<string?> TryResolvePackageAsync(string apkPath, CancellationToken ct = default)
    {
        return FirstNonEmpty(
            ApkPackageName.TryRead(apkPath),
            await TryResolvePackageViaAaptAsync(apkPath, ct).ConfigureAwait(false));
    }

    private static async Task<string?> TryResolvePackageViaAaptAsync(string apkPath, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(apkPath) || !File.Exists(apkPath))
            return null;

        foreach (var aapt in FindAllAapt())
        {
            try
            {
                var isAapt2 = Path.GetFileName(aapt).StartsWith("aapt2", StringComparison.OrdinalIgnoreCase);
                // Both support: dump badging <apk>
                var (code, stdout, stderr) = await RunAsync(
                    aapt, new[] { "dump", "badging", apkPath }, ct).ConfigureAwait(false);
                var text = stdout + "\n" + stderr;
                if (code != 0 && string.IsNullOrWhiteSpace(stdout))
                    continue;

                var m = PackageNameRe.Match(text);
                if (m.Success)
                    return m.Groups["pkg"].Value;

                // aapt2 sometimes prints without quotes differently — keep scanning.
                _ = isAapt2;
            }
            catch
            {
                // try next
            }
        }

        return null;
    }

    private static async Task<HashSet<string>> ListPackagesAsync(string serial, CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        var adb = FindAdb();
        if (adb == null)
            return set;

        var (code, stdout, _) = await RunAsync(
            adb, new[] { "-s", serial, "shell", "pm", "list", "packages" }, ct).ConfigureAwait(false);
        if (code != 0 || string.IsNullOrWhiteSpace(stdout))
            return set;

        foreach (var raw in stdout.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var m = PackageListLine.Match(raw.Trim());
            if (m.Success)
                set.Add(m.Groups["pkg"].Value);
        }

        return set;
    }

    public static IEnumerable<string> FindAllAapt()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in SdkRoots())
        {
            var buildTools = Path.Combine(root, "build-tools");
            if (!Directory.Exists(buildTools))
                continue;

            DirectoryInfo? latest = null;
            foreach (var dir in Directory.EnumerateDirectories(buildTools))
            {
                var di = new DirectoryInfo(dir);
                if (latest == null || string.CompareOrdinal(di.Name, latest.Name) > 0)
                    latest = di;
            }

            if (latest == null)
                continue;

            foreach (var name in new[] { "aapt.exe", "aapt", "aapt2.exe", "aapt2" })
            {
                var candidate = Path.Combine(latest.FullName, name);
                if (File.Exists(candidate) && seen.Add(candidate))
                    yield return candidate;
            }
        }

        foreach (var name in new[] { "aapt.exe", "aapt", "aapt2.exe", "aapt2" })
        {
            var onPath = FindOnPath(name);
            if (onPath != null && seen.Add(onPath))
                yield return onPath;
        }
    }

    public static string? FindAapt() => FindAllAapt().FirstOrDefault();

    private static string? FindOnPath(string fileName)
    {
        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var candidate = Path.Combine(dir.Trim(), fileName);
                if (File.Exists(candidate))
                    return candidate;
            }
            catch
            {
                // ignore
            }
        }

        return null;
    }

    private static IEnumerable<string> SdkRoots()
    {
        var roots = new LinkedHashSet();

        foreach (var key in new[] { "ANDROID_HOME", "ANDROID_SDK_ROOT" })
        {
            var v = Environment.GetEnvironmentVariable(key);
            if (!string.IsNullOrWhiteSpace(v))
                roots.Add(v.Trim());
        }

        // If adb is on PATH under .../platform-tools, parent is SDK root.
        var adb = FindOnPath("adb.exe") ?? FindOnPath("adb");
        if (adb != null)
        {
            var pt = Path.GetDirectoryName(adb);
            var sdk = pt != null ? Path.GetDirectoryName(pt) : null;
            if (!string.IsNullOrWhiteSpace(sdk))
                roots.Add(sdk!);
        }

        // Walk up for local.properties (desktop may run with cwd=engine/).
        try
        {
            var dir = new DirectoryInfo(Path.GetFullPath(Environment.CurrentDirectory));
            for (var i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
            {
                var lp = Path.Combine(dir.FullName, "local.properties");
                if (!File.Exists(lp))
                    continue;
                foreach (var line in File.ReadAllLines(lp))
                {
                    var t = line.Trim();
                    if (!t.StartsWith("sdk.dir=", StringComparison.Ordinal))
                        continue;
                    var sdk = t["sdk.dir=".Length..].Trim()
                        .Replace("\\\\", "\\")
                        .Replace("\\:", ":");
                    if (!string.IsNullOrWhiteSpace(sdk))
                        roots.Add(sdk);
                }
            }
        }
        catch
        {
            // ignore
        }

        var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        roots.Add(Path.Combine(local, "Android", "Sdk"));

        var user = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        roots.Add(Path.Combine(user, "AppData", "Local", "Android", "Sdk"));
        roots.Add(Path.Combine(user, "Android", "Sdk"));

        return roots;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }

        return null;
    }

    /// <summary>Tiny insertion-ordered unique string set for SDK roots.</summary>
    private sealed class LinkedHashSet : List<string>
    {
        private readonly HashSet<string> _set = new(StringComparer.OrdinalIgnoreCase);

        public new void Add(string item)
        {
            if (_set.Add(item))
                base.Add(item);
        }
    }

    private static async Task<(int Code, string Stdout, string Stderr)> RunAsync(
        string exe, IEnumerable<string> args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo
        {
            FileName = exe,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args)
            psi.ArgumentList.Add(a);

        using var p = Process.Start(psi);
        if (p == null)
            return (-1, "", "failed to start " + Path.GetFileName(exe));

        var stdoutTask = p.StandardOutput.ReadToEndAsync();
        var stderrTask = p.StandardError.ReadToEndAsync();

        using (ct.Register(() =>
               {
                   try { if (!p.HasExited) p.Kill(entireProcessTree: true); } catch { /* ignore */ }
               }))
        {
            await Task.WhenAll(stdoutTask, stderrTask, p.WaitForExitAsync(ct)).ConfigureAwait(false);
        }

        return (p.ExitCode, await stdoutTask.ConfigureAwait(false), await stderrTask.ConfigureAwait(false));
    }
}
