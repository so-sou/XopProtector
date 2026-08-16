using System.IO;

namespace Protector.Desktop;

/// <summary>
/// %AppData%\XopProtector — settings, history, logs.
/// One-time migrate from legacy %AppData%\XOP Protector or AppShield when present.
/// </summary>
internal static class AppDataPaths
{
    public const string DirName = "XopProtector";
    public const string LegacyDirName = "XOP Protector";
    public const string LegacyDirNameAppShield = "AppShield";

    private static readonly object Gate = new();
    private static bool _ready;

    public static string Root
    {
        get
        {
            EnsureReady();
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                DirName);
        }
    }

    public static string SettingsFile => Path.Combine(Root, "settings.json");
    public static string HistoryFile => Path.Combine(Root, "history.json");
    public static string LogsDir => Path.Combine(Root, "logs");

    /// <summary>Create root (and migrate legacy) before first read/write.</summary>
    public static void EnsureReady()
    {
        lock (Gate)
        {
            if (_ready) return;
            _ready = true;
            try
            {
                var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                var neu = Path.Combine(appData, DirName);
                var legacySpaced = Path.Combine(appData, LegacyDirName);
                var legacyShield = Path.Combine(appData, LegacyDirNameAppShield);

                MigrateLegacy(legacySpaced, neu);
                MigrateLegacy(legacyShield, neu);

                Directory.CreateDirectory(neu);
            }
            catch
            {
                // ignore; callers still try CreateDirectory on write
            }
        }
    }

    private static void MigrateLegacy(string legacy, string neu)
    {
        if (!Directory.Exists(legacy)) return;
        if (!Directory.Exists(neu))
        {
            try
            {
                Directory.Move(legacy, neu);
            }
            catch
            {
                CopyTree(legacy, neu);
            }
        }
        else
        {
            MergeMissing(legacy, neu);
        }
    }

    private static void CopyTree(string src, string dst)
    {
        Directory.CreateDirectory(dst);
        foreach (var file in Directory.GetFiles(src))
        {
            var name = Path.GetFileName(file);
            var dest = Path.Combine(dst, name);
            if (!File.Exists(dest))
                File.Copy(file, dest, overwrite: false);
        }
        foreach (var dir in Directory.GetDirectories(src))
        {
            var name = Path.GetFileName(dir);
            CopyTree(dir, Path.Combine(dst, name!));
        }
    }

    private static void MergeMissing(string src, string dst)
    {
        foreach (var file in Directory.GetFiles(src))
        {
            var dest = Path.Combine(dst, Path.GetFileName(file));
            if (!File.Exists(dest))
            {
                try { File.Copy(file, dest, overwrite: false); }
                catch { /* ignore */ }
            }
        }
        foreach (var dir in Directory.GetDirectories(src))
        {
            var name = Path.GetFileName(dir);
            var destDir = Path.Combine(dst, name!);
            if (!Directory.Exists(destDir))
            {
                try { CopyTree(dir, destDir); }
                catch { /* ignore */ }
            }
            else
            {
                MergeMissing(dir, destDir);
            }
        }
    }
}
