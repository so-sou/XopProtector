using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Protector.Desktop.Pages;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

public partial class MainWindow : Window
{
    private readonly HardenPage _harden = new();
    private readonly HistoryPage _history = new();
    private readonly ReportsPage _reports = new();
    private readonly SettingsPage _settings = new();
    private string _nav = "harden";

    public MainWindow()
    {
        InitializeComponent();
        PageHost.Content = _harden;
        SidebarEngineVer.Text = ResolveAppVersion();
        Loaded += (_, _) =>
        {
            try
            {
                var paths = EnginePaths.Resolve();
                EngineStatusText.Text = Strings.EngineReady;
                EngineStatusText.SetResourceReference(TextBlock.ForegroundProperty, "TextDim");
                _harden.BindEngine(paths);
                _settings.BindEngine(paths);
            }
            catch (Exception ex)
            {
                EngineStatusText.Text = Strings.EngineNotFound;
                EngineStatusText.SetResourceReference(TextBlock.ForegroundProperty, "Danger");
                _harden.ShowEngineError(ex.Message);
            }
        };
    }

    private static string ResolveAppVersion()
    {
        var asm = typeof(App).Assembly;
        var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(info))
        {
            var plus = info.IndexOf('+');
            return plus > 0 ? info[..plus] : info;
        }
        var v = asm.GetName().Version;
        return v == null ? "0.6.26" : $"{v.Major}.{v.Minor}.{v.Build}";
    }

    private void Nav_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string tag)
            return;
        _nav = tag;
        SetNavStyles();
        PageHost.Content = tag switch
        {
            "history" => _history,
            "reports" => _reports,
            "settings" => _settings,
            _ => _harden
        };
        if (tag == "history")
            _history.Reload();
        if (tag == "reports")
            _reports.Reload();
    }

    private void SetNavStyles()
    {
        ApplyNav(NavHarden, _nav == "harden");
        ApplyNav(NavHistory, _nav == "history");
        ApplyNav(NavReports, _nav == "reports");
        ApplyNav(NavSettings, _nav == "settings");
    }

    private static void ApplyNav(Button btn, bool active)
    {
        btn.Style = (Style)Application.Current.FindResource(active ? "NavButtonActive" : "NavButton");
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        // E922 = maximize, E923 = restore
        MaxBtn.Content = WindowState == WindowState.Maximized ? "\uE923" : "\uE922";
        MaxBtn.ToolTip = WindowState == WindowState.Maximized ? Strings.TooltipRestore : Strings.TooltipMaximize;
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void CloseBtn_MouseEnter(object sender, MouseEventArgs e)
    {
        CloseBtn.Background = ThemeService.Brush("DangerHover");
        CloseBtn.Foreground = ThemeService.Brush("DangerHoverFg");
    }

    private void CloseBtn_MouseLeave(object sender, MouseEventArgs e)
    {
        CloseBtn.Background = Brushes.Transparent;
        CloseBtn.SetResourceReference(ForegroundProperty, "TextPrimary");
    }
}
