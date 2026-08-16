using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Protector.Desktop;

/// <summary>
/// Resolves packer jar, shell-files, and java.exe for the subprocess engine.
/// Order: PROTECTOR_ENGINE_HOME → BaseDirectory/engine → repo-relative (dev).
/// </summary>
public sealed class EnginePaths
{
    public string JavaExe { get; init; } = "";
    public string PackerJar { get; init; } = "";
    public string ShellDir { get; init; } = "";
    public string EngineHome { get; init; } = "";

    public static EnginePaths Resolve()
    {
        var candidates = new List<string>();

        var env = Environment.GetEnvironmentVariable("PROTECTOR_ENGINE_HOME");
        if (!string.IsNullOrWhiteSpace(env))
            candidates.Add(env.Trim());

        candidates.Add(Path.Combine(AppContext.BaseDirectory, "engine"));

        // Dev: desktop/Protector.Desktop/bin/.../ → repo root
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 8 && dir != null; i++, dir = dir.Parent)
        {
            var packerLibs = Path.Combine(dir.FullName, "packer", "build", "libs");
            if (Directory.Exists(packerLibs))
            {
                candidates.Add(dir.FullName); // treat repo root specially below
                break;
            }
        }

        foreach (var home in candidates)
        {
            if (TryFromEngineLayout(home, out var paths))
                return paths;
            if (TryFromRepoRoot(home, out paths))
                return paths;
        }

        throw new InvalidOperationException(
            "Cannot locate protector engine. Set PROTECTOR_ENGINE_HOME, or place "
            + "engine/protector-packer.jar + engine/shell-files next to XopProtector.exe, "
            + "or build :packer:jar and exportShellFiles in the repo.");
    }

    private static bool TryFromEngineLayout(string home, out EnginePaths paths)
    {
        paths = null!;
        var jar = Directory.Exists(home)
            ? Directory.GetFiles(home, "protector-packer*.jar")
                .OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc)
                .FirstOrDefault() ?? ""
            : "";
        if (File.Exists(Path.Combine(home, "protector-packer.jar")))
            jar = Path.Combine(home, "protector-packer.jar");
        var shell = Path.Combine(home, "shell-files");
        if (string.IsNullOrEmpty(jar) || !File.Exists(jar) || !Directory.Exists(shell))
            return false;

        var java = FindJava(Path.Combine(home, "runtime"));
        if (java == null)
            return false;

        paths = new EnginePaths
        {
            EngineHome = home,
            PackerJar = jar,
            ShellDir = shell,
            JavaExe = java
        };
        return true;
    }

    private static bool TryFromRepoRoot(string repoRoot, out EnginePaths paths)
    {
        paths = null!;
        var libs = Path.Combine(repoRoot, "packer", "build", "libs");
        var shell = Path.Combine(repoRoot, "executable", "shell-files");
        if (!Directory.Exists(libs) || !Directory.Exists(shell))
            return false;

        var jar = Directory.GetFiles(libs, "protector-packer*.jar")
            .OrderByDescending(f => new FileInfo(f).LastWriteTimeUtc)
            .FirstOrDefault();
        if (jar == null || !File.Exists(jar))
            return false;

        var java = FindJava(null);
        if (java == null)
            return false;

        paths = new EnginePaths
        {
            EngineHome = repoRoot,
            PackerJar = jar,
            ShellDir = shell,
            JavaExe = java
        };
        return true;
    }

    private static string? FindJava(string? bundledRuntimeDir)
    {
        if (!string.IsNullOrEmpty(bundledRuntimeDir))
        {
            var bundled = Path.Combine(bundledRuntimeDir, "bin", "java.exe");
            if (File.Exists(bundled))
                return bundled;
            bundled = Path.Combine(bundledRuntimeDir, "bin", "java");
            if (File.Exists(bundled))
                return bundled;
        }

        var home = Environment.GetEnvironmentVariable("JAVA_HOME");
        if (!string.IsNullOrWhiteSpace(home))
        {
            var j = Path.Combine(home.Trim(), "bin", "java.exe");
            if (File.Exists(j))
                return j;
            j = Path.Combine(home.Trim(), "bin", "java");
            if (File.Exists(j))
                return j;
        }

        // PATH
        var path = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var part in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            var j = Path.Combine(part.Trim(), "java.exe");
            if (File.Exists(j))
                return j;
        }
        return null;
    }
}

public sealed class ProtectJobRequest
{
    public string InputApk { get; set; } = "";
    public string OutputApk { get; set; } = "";
    public string Profile { get; set; } = "balanced";
    public bool ProtectSo { get; set; } = true;
    public string ProtectSoMode { get; set; } = "safe";
    /// <summary>Always forwarded as --payment-auto-vmp / --no-payment-auto-vmp.</summary>
    public bool PaymentAutoVmp { get; set; } = true;
    /// <summary>Always forwarded as --industry-auto-vmp / --no-industry-auto-vmp.</summary>
    public bool IndustryAutoVmp { get; set; }
    /// <summary>When set, pass --protect-so-budget-mb.</summary>
    public double? ProtectSoBudgetMb { get; set; }
    /// <summary>When set, pass --protect-so-max-file-mb.</summary>
    public double? ProtectSoMaxFileMb { get; set; }
    public bool EncryptAssets { get; set; }
    public bool EnableResProtect { get; set; }
    public bool DetectProxy { get; set; }
    public string? PinCertsFile { get; set; }
    public string? Channel { get; set; }
    public string? HollowPrefixes { get; set; }
    public string? VmpPrefixes { get; set; }
    public string? TrueVmpPrefixes { get; set; }
    public string? ApplicationOverride { get; set; }
    public string? CertSha256 { get; set; }
    public string? RiskFlags { get; set; }
    public string? RaspAction { get; set; }
    public string? ReportEnabled { get; set; }
    public string? Keystore { get; set; }
    public string? Alias { get; set; }
    public string? StorePass { get; set; }
    public string? KeyPass { get; set; }
}

public sealed class EngineProgressEvent
{
    public string Type { get; set; } = "";
    public string? Id { get; set; }
    public string? Message { get; set; }
    public int? Percent { get; set; }
    public string? Level { get; set; }
    public string? Output { get; set; }
    public string? SizeReport { get; set; }
}

public sealed class EngineRunner : IAsyncDisposable
{
    private Process? _process;

    public event Action<EngineProgressEvent>? Progress;
    public event Action<string>? RawLog;

    public bool IsRunning => _process is { HasExited: false };

    public async Task<int> RunAsync(EnginePaths paths, ProtectJobRequest job, CancellationToken ct)
    {
        if (IsRunning)
            throw new InvalidOperationException("Engine already running");

        var psi = new ProcessStartInfo
        {
            FileName = paths.JavaExe,
            WorkingDirectory = Path.GetDirectoryName(paths.PackerJar) ?? paths.EngineHome,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in BuildArgList(paths, job))
            psi.ArgumentList.Add(a);

        _process = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _process.Start();

        var stdoutTask = ReadStreamAsync(_process.StandardOutput, isStdout: true, ct);
        var stderrTask = ReadStreamAsync(_process.StandardError, isStdout: false, ct);

        try
        {
            await _process.WaitForExitAsync(ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill();
            throw;
        }

        await Task.WhenAll(stdoutTask, stderrTask).ConfigureAwait(false);
        var code = _process.ExitCode;
        _process.Dispose();
        _process = null;
        return code;
    }

    public void Cancel() => TryKill();

    private void TryKill()
    {
        try
        {
            if (_process is { HasExited: false })
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
            // ignore
        }
    }

    private async Task ReadStreamAsync(StreamReader reader, bool isStdout, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync().ConfigureAwait(false);
            if (line == null)
                break;
            if (isStdout && TryParseJson(line, out var evt))
            {
                Progress?.Invoke(evt);
            }
            else
            {
                RawLog?.Invoke(line);
            }
        }
    }

    private static bool TryParseJson(string line, out EngineProgressEvent evt)
    {
        evt = null!;
        var t = line.TrimStart();
        if (!t.StartsWith('{'))
            return false;
        try
        {
            using var doc = JsonDocument.Parse(t);
            var root = doc.RootElement;
            if (!root.TryGetProperty("type", out var typeEl))
                return false;
            evt = new EngineProgressEvent
            {
                Type = typeEl.GetString() ?? "",
                Id = root.TryGetProperty("id", out var id) ? id.GetString() : null,
                Message = root.TryGetProperty("message", out var msg) ? msg.GetString() : null,
                Percent = root.TryGetProperty("percent", out var p) && p.TryGetInt32(out var pi) ? pi : null,
                Level = root.TryGetProperty("level", out var lv) ? lv.GetString() : null,
                Output = root.TryGetProperty("output", out var o) ? o.GetString() : null,
                SizeReport = root.TryGetProperty("sizeReport", out var sr) ? sr.GetString() : null,
            };
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static List<string> BuildArgList(EnginePaths paths, ProtectJobRequest job)
    {
        var args = new List<string>
        {
            "-jar", paths.PackerJar,
            job.InputApk,
            "-o", job.OutputApk,
            "--shell-dir", paths.ShellDir,
            "--json-progress",
            "--profile", job.Profile,
        };
        args.Add(job.ProtectSo ? "--protect-so" : "--no-protect-so");
        args.Add("--protect-so-mode");
        args.Add(job.ProtectSoMode);

        args.Add(job.PaymentAutoVmp ? "--payment-auto-vmp" : "--no-payment-auto-vmp");
        args.Add(job.IndustryAutoVmp ? "--industry-auto-vmp" : "--no-industry-auto-vmp");

        if (job.ProtectSoBudgetMb is double budgetMb && budgetMb > 0)
        {
            args.Add("--protect-so-budget-mb");
            args.Add(budgetMb.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture));
        }
        if (job.ProtectSoMaxFileMb is double maxFileMb && maxFileMb > 0)
        {
            args.Add("--protect-so-max-file-mb");
            args.Add(maxFileMb.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture));
        }

        AppendPrefixes(args, "--hollow-prefix", job.HollowPrefixes);
        AppendPrefixes(args, "--vmp-prefix", job.VmpPrefixes);
        AppendPrefixes(args, "--true-vmp-prefix", job.TrueVmpPrefixes);

        if (job.EncryptAssets)
            args.Add("--encrypt-assets");
        else
            args.Add("--no-encrypt-assets");

        if (job.EnableResProtect)
            args.Add("--enable-res-protect");
        else
            args.Add("--no-res-protect");

        if (job.DetectProxy)
            args.Add("--detect-proxy");

        if (!string.IsNullOrWhiteSpace(job.PinCertsFile))
        {
            args.Add("--pin-certs");
            args.Add(job.PinCertsFile.Trim());
        }

        if (!string.IsNullOrWhiteSpace(job.Channel))
        {
            args.Add("--channel");
            args.Add(job.Channel.Trim());
        }

        if (!string.IsNullOrWhiteSpace(job.ApplicationOverride))
        {
            args.Add("--application");
            args.Add(job.ApplicationOverride.Trim());
        }
        if (!string.IsNullOrWhiteSpace(job.CertSha256))
        {
            args.Add("--cert-sha256");
            args.Add(job.CertSha256.Trim());
        }
        if (!string.IsNullOrWhiteSpace(job.RiskFlags))
        {
            args.Add("--risk-flags");
            args.Add(job.RiskFlags.Trim());
        }
        if (!string.IsNullOrWhiteSpace(job.RaspAction))
        {
            args.Add("--rasp-action");
            args.Add(job.RaspAction.Trim());
        }
        if (!string.IsNullOrWhiteSpace(job.ReportEnabled))
        {
            args.Add("--report-enabled");
            args.Add(job.ReportEnabled.Trim());
        }

        if (!string.IsNullOrWhiteSpace(job.Keystore))
        {
            args.Add("--keystore");
            args.Add(job.Keystore.Trim());
            if (!string.IsNullOrWhiteSpace(job.Alias))
            {
                args.Add("--alias");
                args.Add(job.Alias.Trim());
            }
            if (!string.IsNullOrWhiteSpace(job.StorePass))
            {
                args.Add("--storepass");
                args.Add(job.StorePass);
            }
            if (!string.IsNullOrWhiteSpace(job.KeyPass))
            {
                args.Add("--keypass");
                args.Add(job.KeyPass);
            }
        }

        return args;
    }

    private static void AppendPrefixes(List<string> args, string flag, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return;
        foreach (var part in raw.Split(new[] { ';', '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries))
        {
            var p = part.Trim();
            if (p.Length == 0) continue;
            args.Add(flag);
            args.Add(p);
        }
    }

    public ValueTask DisposeAsync()
    {
        TryKill();
        _process?.Dispose();
        _process = null;
        return ValueTask.CompletedTask;
    }
}
