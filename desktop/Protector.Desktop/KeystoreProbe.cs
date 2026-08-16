using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

/// <summary>
/// Probe a JKS/PKCS12 keystore via the engine-bundled keytool before packing.
/// </summary>
internal static class KeystoreProbe
{
    public sealed class Result
    {
        public bool Ok { get; init; }
        public string? Error { get; init; }
        public List<string> Aliases { get; init; } = new();
        public string? StoreType { get; init; }
    }

    public static Result Probe(EnginePaths paths, string keystore, string storePass, string? alias = null)
    {
        if (string.IsNullOrWhiteSpace(keystore) || !File.Exists(keystore))
            return new Result { Ok = false, Error = Strings.Ks_FileMissing };
        if (string.IsNullOrEmpty(storePass))
            return new Result { Ok = false, Error = Strings.Ks_PassEmpty };

        var keytool = FindKeytool(paths);
        if (keytool == null)
            return new Result { Ok = false, Error = Strings.Ks_NoKeytool };

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = keytool,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8,
            };
            psi.ArgumentList.Add("-list");
            psi.ArgumentList.Add("-keystore");
            psi.ArgumentList.Add(keystore);
            psi.ArgumentList.Add("-storepass");
            psi.ArgumentList.Add(storePass);

            using var p = Process.Start(psi);
            if (p == null)
                return new Result { Ok = false, Error = Strings.Ks_StartFailed };

            var stdout = p.StandardOutput.ReadToEnd();
            var stderr = p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            var text = stdout + "\n" + stderr;

            if (p.ExitCode != 0)
            {
                var lower = text.ToLowerInvariant();
                if (lower.Contains("password was incorrect") || lower.Contains("password incorrect")
                    || lower.Contains("密码不正确") || lower.Contains("口令不正确"))
                {
                    return new Result
                    {
                        Ok = false,
                        Error = Strings.Ks_BadPassword
                    };
                }
                return new Result
                {
                    Ok = false,
                    Error = string.Format(Strings.Ks_OpenFailed, TrimKeytoolError(text))
                };
            }

            var aliases = ParseAliases(text);
            var storeType = Regex.Match(text, @"Keystore type:\s*(\S+)", RegexOptions.IgnoreCase).Groups[1].Value;
            if (string.IsNullOrEmpty(storeType))
                storeType = Regex.Match(text, @"密钥库类型:\s*(\S+)").Groups[1].Value;

            if (!string.IsNullOrWhiteSpace(alias)
                && aliases.Count > 0
                && !aliases.Any(a => string.Equals(a, alias.Trim(), StringComparison.Ordinal)))
            {
                return new Result
                {
                    Ok = false,
                    Error = string.Format(Strings.Ks_AliasMissing, alias.Trim(), string.Join(", ", aliases)),
                    Aliases = aliases,
                    StoreType = storeType
                };
            }

            return new Result { Ok = true, Aliases = aliases, StoreType = storeType };
        }
        catch (Exception ex)
        {
            return new Result { Ok = false, Error = string.Format(Strings.Ks_ProbeFailed, ex.Message) };
        }
    }

    public static string? FindKeytool(EnginePaths paths)
    {
        var dir = Path.GetDirectoryName(paths.JavaExe);
        if (!string.IsNullOrEmpty(dir))
        {
            var kt = Path.Combine(dir, "keytool.exe");
            if (File.Exists(kt)) return kt;
            kt = Path.Combine(dir, "keytool");
            if (File.Exists(kt)) return kt;
        }
        return null;
    }

    private static List<string> ParseAliases(string text)
    {
        var list = new List<string>();
        // English: "foo, 2024-01-01, PrivateKeyEntry,"
        // Chinese: "foo, 2026年6月16日, PrivateKeyEntry,"
        foreach (Match m in Regex.Matches(text,
                     @"^([A-Za-z0-9_.\-]+),\s+.+(?:PrivateKeyEntry|SecretKeyEntry|trustedCertEntry)",
                     RegexOptions.Multiline))
        {
            var a = m.Groups[1].Value.Trim();
            if (!string.IsNullOrEmpty(a) && !list.Contains(a, StringComparer.Ordinal))
                list.Add(a);
        }
        return list;
    }

    private static string TrimKeytoolError(string text)
    {
        var lines = text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => l.Length > 0 && !l.StartsWith("Warning:", StringComparison.OrdinalIgnoreCase))
            .Take(4);
        return string.Join("\n", lines);
    }
}
