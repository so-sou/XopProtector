using System.IO;
using System.Text.Json;

namespace Protector.Desktop;

public sealed class HistoryRecord
{
    public string Id { get; set; } = "";
    public string Status { get; set; } = "done"; // done | failed
    public string InputName { get; set; } = "";
    public string InputPath { get; set; } = "";
    public string OutputPath { get; set; } = "";
    public string Profile { get; set; } = "";
    public bool ProtectSo { get; set; }
    public string ProtectSoMode { get; set; } = "";
    public bool PaymentAutoVmp { get; set; } = true;
    public bool IndustryAutoVmp { get; set; }
    public double? ProtectSoBudgetMb { get; set; }
    public double? ProtectSoMaxFileMb { get; set; }
    public bool EncryptAssets { get; set; }
    public bool EnableResProtect { get; set; }
    public bool DetectProxy { get; set; }
    public string? Channel { get; set; }
    public bool Signed { get; set; }
    public string StartedAt { get; set; } = "";
    public string FinishedAt { get; set; } = "";
    public long DurationMs { get; set; }
    public long InputBytes { get; set; }
    public long OutputBytes { get; set; }
    public string? SizeReport { get; set; }
    public string? ProtectLog { get; set; }
    public string? Error { get; set; }
    public int ExitCode { get; set; }
}

public static class HistoryStore
{
    private static readonly string HistoryPath = AppDataPaths.HistoryFile;

    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static event Action? Changed;

    public static IReadOnlyList<HistoryRecord> Load()
    {
        lock (Gate)
        {
            try
            {
                if (!File.Exists(HistoryPath)) return Array.Empty<HistoryRecord>();
                var json = File.ReadAllText(HistoryPath);
                var list = JsonSerializer.Deserialize<List<HistoryRecord>>(json, JsonOpts);
                return list ?? new List<HistoryRecord>();
            }
            catch
            {
                return Array.Empty<HistoryRecord>();
            }
        }
    }

    public static void Add(HistoryRecord record)
    {
        lock (Gate)
        {
            var list = LoadMutable();
            list.Insert(0, record);
            // Keep recent 200
            if (list.Count > 200)
                list.RemoveRange(200, list.Count - 200);
            Save(list);
        }
        Changed?.Invoke();
    }

    public static void Clear()
    {
        lock (Gate)
        {
            Save(new List<HistoryRecord>());
        }
        Changed?.Invoke();
    }

    private static List<HistoryRecord> LoadMutable()
    {
        try
        {
            if (!File.Exists(HistoryPath)) return new List<HistoryRecord>();
            var json = File.ReadAllText(HistoryPath);
            return JsonSerializer.Deserialize<List<HistoryRecord>>(json, JsonOpts) ?? new List<HistoryRecord>();
        }
        catch
        {
            return new List<HistoryRecord>();
        }
    }

    private static void Save(List<HistoryRecord> list)
    {
        try
        {
            var dir = Path.GetDirectoryName(HistoryPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllText(HistoryPath, JsonSerializer.Serialize(list, JsonOpts));
        }
        catch
        {
            // ignore disk errors
        }
    }

    public static string NewId()
    {
        // Second-only stamps collided when the same APK was protected twice quickly;
        // reports then shared one Id and the UI always showed the newest detail.
        return "T-" + DateTime.Now.ToString("yyyyMMdd-HHmmss-fff") + "-" +
               Random.Shared.Next(0x1000, 0x10000).ToString("x4");
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes <= 0) return "—";
        var mb = bytes / 1024.0 / 1024.0;
        return mb >= 1 ? $"{mb:F2} MB" : $"{bytes / 1024.0:F1} KB";
    }

    public static string FormatDuration(long ms)
    {
        if (ms <= 0) return "—";
        var ts = TimeSpan.FromMilliseconds(ms);
        if (ts.TotalMinutes >= 1)
            return $"{(int)ts.TotalMinutes}m {ts.Seconds:D2}s";
        return $"{ts.Seconds}.{ts.Milliseconds / 100}s";
    }
}
