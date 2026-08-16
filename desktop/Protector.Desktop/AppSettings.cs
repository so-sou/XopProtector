using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Protector.Desktop;

/// <summary>
/// Persists UI preferences under %AppData%\XopProtector\settings.json.
/// Passwords are DPAPI-protected (CurrentUser).
/// </summary>
public static class AppSettings
{
    private static readonly string SettingsFile = AppDataPaths.SettingsFile;

    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static string FilePath => SettingsFile;

    public sealed class Data
    {
        public string Theme { get; set; } = "dark";
        /// <summary>system | en | zh-CN</summary>
        public string Language { get; set; } = "system";
        public bool SignCustom { get; set; }
        public string Keystore { get; set; } = "";
        public string Alias { get; set; } = "";
        /// <summary>DPAPI blob (Base64), not plaintext.</summary>
        public string? StorePassProtected { get; set; }
        /// <summary>DPAPI blob (Base64); empty means same as store pass.</summary>
        public string? KeyPassProtected { get; set; }
    }

    public static Data Load()
    {
        lock (Gate)
        {
            try
            {
                if (!File.Exists(SettingsFile)) return new Data();
                var json = File.ReadAllText(SettingsFile);
                return JsonSerializer.Deserialize<Data>(json, JsonOpts) ?? new Data();
            }
            catch
            {
                return new Data();
            }
        }
    }

    public static void Save(Data data)
    {
        lock (Gate)
        {
            try
            {
                var dir = System.IO.Path.GetDirectoryName(SettingsFile);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(SettingsFile, JsonSerializer.Serialize(data, JsonOpts));
            }
            catch
            {
                // ignore disk errors
            }
        }
    }

    public static void Update(Action<Data> mutate)
    {
        lock (Gate)
        {
            var data = LoadUnlocked();
            mutate(data);
            try
            {
                var dir = System.IO.Path.GetDirectoryName(SettingsFile);
                if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(SettingsFile, JsonSerializer.Serialize(data, JsonOpts));
            }
            catch
            {
                // ignore
            }
        }
    }

    private static Data LoadUnlocked()
    {
        try
        {
            if (!File.Exists(SettingsFile)) return new Data();
            var json = File.ReadAllText(SettingsFile);
            return JsonSerializer.Deserialize<Data>(json, JsonOpts) ?? new Data();
        }
        catch
        {
            return new Data();
        }
    }

    public static string ProtectSecret(string? plain)
    {
        if (string.IsNullOrEmpty(plain)) return "";
        try
        {
            var bytes = Encoding.UTF8.GetBytes(plain);
            var enc = ProtectedData.Protect(bytes, optionalEntropy: null, DataProtectionScope.CurrentUser);
            return Convert.ToBase64String(enc);
        }
        catch
        {
            return "";
        }
    }

    public static string UnprotectSecret(string? protectedB64)
    {
        if (string.IsNullOrWhiteSpace(protectedB64)) return "";
        try
        {
            var enc = Convert.FromBase64String(protectedB64);
            var bytes = ProtectedData.Unprotect(enc, optionalEntropy: null, DataProtectionScope.CurrentUser);
            return Encoding.UTF8.GetString(bytes);
        }
        catch
        {
            return "";
        }
    }
}
