using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using Protector.Desktop.Resources;

namespace Protector.Desktop.Pages;

public partial class HistoryPage
{
    private string _filter = "all";
    private List<HistoryRecord> _all = new();

    public HistoryPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Reload();
        HistoryStore.Changed += () => Dispatcher.Invoke(Reload);
        StyleFilterButtons();
    }

    public void Reload()
    {
        _all = HistoryStore.Load().ToList();
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        IEnumerable<HistoryRecord> q = _all;
        if (_filter == "done") q = q.Where(r => r.Status == "done");
        else if (_filter == "failed") q = q.Where(r => r.Status == "failed");

        var rows = q.Select(ToRow).ToList();
        HistoryList.ItemsSource = rows;
        CountText.Text = string.Format(Strings.History_Count, _all.Count);
        EmptyState.Visibility = rows.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ListScroll.Visibility = rows.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        StyleFilterButtons();
    }

    private void Filter_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string tag) return;
        _filter = tag;
        ApplyFilter();
    }

    private void Clear_Click(object sender, RoutedEventArgs e)
    {
        if (_all.Count == 0) return;
        var r = MessageBox.Show(Strings.History_ConfirmClear, Strings.ProductName,
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (r != MessageBoxResult.Yes) return;
        HistoryStore.Clear();
    }

    private void Item_Click(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (sender is not FrameworkElement fe) return;
        var row = fe.Tag as HistoryRowVm ?? fe.DataContext as HistoryRowVm;
        if (row == null) return;

        // Open the protected APK's folder (prefer output path).
        var path = !string.IsNullOrEmpty(row.OutputPath) ? row.OutputPath : row.InputPath;
        Dispatcher.BeginInvoke(new Action(() => ShellUtil.RevealInExplorer(path)));
    }

    private void StyleFilterButtons()
    {
        StyleChip(FilterAllBtn, _filter == "all");
        StyleChip(FilterDoneBtn, _filter == "done");
        StyleChip(FilterFailedBtn, _filter == "failed");
    }

    private static void StyleChip(Button b, bool on)
    {
        b.Background = ThemeService.Brush(on ? "AccentBg" : "GhostBg");
        b.Foreground = ThemeService.Brush(on ? "Accent" : "TextMuted");
        b.BorderBrush = ThemeService.Brush(on ? "AccentBorder" : "BorderSoft");
        b.BorderThickness = new Thickness(1);
        b.Template = CreateChipTemplate();
    }

    private static ControlTemplate CreateChipTemplate()
    {
        var template = new ControlTemplate(typeof(Button));
        var border = new FrameworkElementFactory(typeof(Border));
        border.SetValue(Border.BackgroundProperty, new TemplateBindingExtension(BackgroundProperty));
        border.SetValue(Border.BorderBrushProperty, new TemplateBindingExtension(BorderBrushProperty));
        border.SetValue(Border.BorderThicknessProperty, new TemplateBindingExtension(BorderThicknessProperty));
        border.SetValue(Border.CornerRadiusProperty, new CornerRadius(5));
        border.SetValue(Border.PaddingProperty, new TemplateBindingExtension(PaddingProperty));
        var presenter = new FrameworkElementFactory(typeof(ContentPresenter));
        presenter.SetValue(ContentPresenter.HorizontalAlignmentProperty, HorizontalAlignment.Center);
        presenter.SetValue(ContentPresenter.VerticalAlignmentProperty, VerticalAlignment.Center);
        border.AppendChild(presenter);
        template.VisualTree = border;
        return template;
    }

    private static HistoryRowVm ToRow(HistoryRecord r)
    {
        var ok = r.Status == "done";
        var opts = new List<string> { string.Format(Strings.Meta_Profile, r.Profile) };
        if (r.ProtectSo) opts.Add(string.Format(Strings.Meta_SoOn, r.ProtectSoMode));
        else opts.Add(Strings.Meta_SoOff);
        opts.Add(string.Format(Strings.Meta_Vmp,
            r.PaymentAutoVmp ? Strings.Meta_On : Strings.Meta_Off,
            r.IndustryAutoVmp ? Strings.Meta_On : Strings.Meta_Off));
        if (r.EncryptAssets) opts.Add(Strings.Meta_Assets);
        if (r.EnableResProtect) opts.Add(Strings.Meta_Res);
        if (r.DetectProxy) opts.Add(Strings.Meta_Proxy);
        if (!string.IsNullOrWhiteSpace(r.Channel)) opts.Add(string.Format(Strings.Meta_Channel, r.Channel));
        opts.Add(r.Signed ? Strings.Meta_Signed : Strings.Meta_Unsigned);

        return new HistoryRowVm
        {
            InputName = string.IsNullOrEmpty(r.InputName) ? Path.GetFileName(r.InputPath) : r.InputName,
            InputPath = r.InputPath,
            OutputPath = r.OutputPath,
            StatusLabel = ok ? Strings.History_StatusDone : Strings.History_StatusFailed,
            StatusBg = ThemeService.BrushClone(ok ? "StageDoneBg" : "DangerHover"),
            StatusBorder = ThemeService.BrushClone(ok ? "SuccessBorder" : "Danger"),
            StatusFg = ThemeService.BrushClone(ok ? "SuccessMeta" : "DangerHoverFg"),
            MetaLine = $"{r.Id}  ·  {HistoryStore.FormatBytes(r.InputBytes)} → {HistoryStore.FormatBytes(r.OutputBytes)}  ·  {string.Join(" · ", opts)}",
            PathLine = ok
                ? (string.IsNullOrEmpty(r.OutputPath) ? r.InputPath : r.OutputPath)
                : (r.Error ?? string.Format(Strings.Meta_ExitCode, r.ExitCode)),
            TimeLabel = r.FinishedAt,
            DurationLabel = HistoryStore.FormatDuration(r.DurationMs)
        };
    }

    private sealed class HistoryRowVm
    {
        public string InputName { get; set; } = "";
        public string InputPath { get; set; } = "";
        public string OutputPath { get; set; } = "";
        public string StatusLabel { get; set; } = "";
        public Brush StatusBg { get; set; } = Brushes.Transparent;
        public Brush StatusBorder { get; set; } = Brushes.Transparent;
        public Brush StatusFg { get; set; } = Brushes.Gray;
        public string MetaLine { get; set; } = "";
        public string PathLine { get; set; } = "";
        public string TimeLabel { get; set; } = "";
        public string DurationLabel { get; set; } = "";
    }
}
