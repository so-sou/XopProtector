using System.Diagnostics;
using System.IO;
using System.Windows;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

internal static class ShellUtil
{
    /// <summary>
    /// Open the folder that contains <paramref name="path"/> (and select the file
    /// when it still exists). Never throws to the UI.
    /// </summary>
    public static void RevealInExplorer(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(Strings.Msg_PathEmpty, Strings.ProductName, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            path = path.Trim();
            string? dir;
            string? selectFile = null;

            if (File.Exists(path))
            {
                selectFile = path;
                dir = Path.GetDirectoryName(path);
            }
            else if (Directory.Exists(path))
            {
                dir = path;
            }
            else
            {
                // Output APK may have been moved; still open its parent folder if present.
                dir = Path.GetDirectoryName(path);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
                {
                    MessageBox.Show(string.Format(Strings.Msg_DirMissing, path), Strings.ProductName,
                        MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
            }

            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir))
            {
                MessageBox.Show(Strings.Msg_DirMissingShort, Strings.ProductName,
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            OpenExplorer(dir, selectFile);
        }
        catch (Exception ex)
        {
            MessageBox.Show(string.Format(Strings.Msg_ExplorerFailed, ex.Message), Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private static void OpenExplorer(string directory, string? selectFile)
    {
        var explorer = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "explorer.exe");
        // Avoid inheriting the app's cwd (e.g. ...\desktop) which can cause
        // "Access denied" when launching explorer on some locked-down machines.
        var safeCwd = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        var psi = new ProcessStartInfo
        {
            FileName = File.Exists(explorer) ? explorer : "explorer.exe",
            UseShellExecute = true,
            WorkingDirectory = safeCwd,
        };

        if (!string.IsNullOrEmpty(selectFile) && File.Exists(selectFile))
            psi.Arguments = "/select,\"" + selectFile + "\"";
        else
            psi.Arguments = "\"" + directory + "\"";

        Process.Start(psi);
    }
}
