using System.Windows;
using System.Windows.Media;

namespace Protector.Desktop;

public enum AppTheme
{
    Dark,
    Light
}

public static class ThemeService
{
    public static AppTheme Current { get; private set; } = AppTheme.Dark;

    public static event Action<AppTheme>? ThemeChanged;

    public static void Initialize()
    {
        Apply(LoadSaved(), persist: false);
    }

    public static void Apply(AppTheme theme, bool persist = true)
    {
        Current = theme;
        var app = Application.Current;
        if (app == null) return;

        var uri = theme == AppTheme.Light
            ? new Uri("Themes/Light.xaml", UriKind.Relative)
            : new Uri("Themes/Dark.xaml", UriKind.Relative);

        var dict = new ResourceDictionary { Source = uri };

        // Remove previous theme dict(s)
        for (var i = app.Resources.MergedDictionaries.Count - 1; i >= 0; i--)
        {
            var d = app.Resources.MergedDictionaries[i];
            if (d.Source != null &&
                (d.Source.OriginalString.Contains("Themes/Dark.xaml") ||
                 d.Source.OriginalString.Contains("Themes/Light.xaml")))
            {
                app.Resources.MergedDictionaries.RemoveAt(i);
            }
        }

        app.Resources.MergedDictionaries.Insert(0, dict);

        if (persist)
        {
            AppSettings.Update(d => d.Theme = theme == AppTheme.Light ? "light" : "dark");
        }
        ThemeChanged?.Invoke(theme);
    }

    public static Brush Brush(string key)
    {
        if (Application.Current?.TryFindResource(key) is Brush b)
            return b;
        return System.Windows.Media.Brushes.Gray;
    }

    /// <summary>
    /// Clone+freeze a theme brush for per-item bindings. Sharing the live
    /// ResourceDictionary brush across many local Backgrounds can throw
    /// Freezable ownership exceptions under WPF.
    /// </summary>
    public static Brush BrushClone(string key)
    {
        var src = Brush(key);
        try
        {
            var clone = src.CloneCurrentValue();
            if (clone.CanFreeze && !clone.IsFrozen)
                clone.Freeze();
            return clone;
        }
        catch
        {
            return src;
        }
    }

    private static AppTheme LoadSaved()
    {
        var s = AppSettings.Load().Theme;
        if (string.Equals(s, "light", StringComparison.OrdinalIgnoreCase))
            return AppTheme.Light;
        return AppTheme.Dark;
    }
}
