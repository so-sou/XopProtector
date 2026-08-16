using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using Protector.Desktop.Resources;

namespace Protector.Desktop.Pages;

public partial class ReportsPage
{
    private List<(HistoryRecord Job, ReportDetail Detail)> _reports = new();
    private string? _selectedId;
    private ReportDetail? _current;

    public ReportsPage()
    {
        InitializeComponent();
        Loaded += (_, _) => Reload();
        HistoryStore.Changed += () => Dispatcher.Invoke(Reload);
    }

    public void Reload()
    {
        var jobs = ReportBuilder.SuccessfulJobs();
        _reports = jobs.Select(j => (j, ReportBuilder.Build(j))).ToList();
        ListCountText.Text = string.Format(Strings.Reports_Count, _reports.Count);
        EmptyList.Visibility = _reports.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        if (_reports.Count == 0)
        {
            _selectedId = null;
            _current = null;
            ReportList.ItemsSource = null;
            ShowEmptyDetail();
            return;
        }

        if (_selectedId == null || _reports.All(r => r.Detail.Id != _selectedId))
            _selectedId = _reports[0].Detail.Id;

        BindList();
        var sel = _reports.First(r => r.Detail.Id == _selectedId);
        ShowDetail(sel.Detail);
    }

    private void BindList()
    {
        ReportList.ItemsSource = _reports.Select(r =>
        {
            var on = r.Detail.Id == _selectedId;
            var scoreBrush = ScoreBrush(r.Detail.Score);
            return new ReportListVm
            {
                Id = r.Detail.Id,
                AppName = r.Detail.AppName,
                SubLine = $"{r.Detail.Date}  ·  {r.Detail.Id}",
                ScoreText = r.Detail.Score.ToString(),
                ScoreBrush = scoreBrush,
                TitleFg = ThemeService.BrushClone(on ? "AccentSoft" : "TextMuted"),
                RowBg = on ? ThemeService.BrushClone("AccentBg") : Brushes.Transparent
            };
        }).ToList();
    }

    private void ReportItem_Click(object sender, MouseButtonEventArgs e)
    {
        e.Handled = true;
        if (sender is not FrameworkElement fe) return;
        var vm = fe.Tag as ReportListVm ?? fe.DataContext as ReportListVm;
        if (vm == null) return;

        // Capture id before rebinding — replacing ItemsSource mid-click tears
        // down the sender Border and can crash the WPF dispatcher.
        var id = vm.Id;
        _selectedId = id;
        Dispatcher.BeginInvoke(new Action(() =>
        {
            BindList();
            var hit = _reports.FirstOrDefault(r => r.Detail.Id == id);
            if (hit.Detail != null) ShowDetail(hit.Detail);
        }));
    }

    private void ShowEmptyDetail()
    {
        EmptyDetail.Visibility = Visibility.Visible;
        DetailScroll.Visibility = Visibility.Collapsed;
    }

    private void ShowDetail(ReportDetail d)
    {
        _current = d;
        EmptyDetail.Visibility = Visibility.Collapsed;
        DetailScroll.Visibility = Visibility.Visible;

        DetailTitle.Text = d.AppName;
        DetailMeta.Text = string.Format(Strings.Reports_DetailMeta,
            d.Id,
            d.Profile,
            d.ProtectSo ? d.ProtectSoMode : Strings.Meta_Off,
            d.Signed ? Strings.Meta_Signed : Strings.Meta_Unsigned,
            d.Duration);
        DetailSize.Text = d.SizeSummary ?? $"{d.InputSize} → {d.OutputSize}";
        ScoreText.Text = d.Score.ToString();
        ScoreLabel.Text = d.ScoreLabel;
        ScoreText.Foreground = ScoreBrush(d.Score);
        ScoreLabel.Foreground = ScoreBrush(d.Score);
        PassText.Text = d.PassCount.ToString();
        WarnText.Text = d.WarnCount.ToString();
        FailText.Text = d.FailCount.ToString();

        SummaryBar.Children.Clear();
        SummaryBar.ColumnDefinitions.Clear();
        AddBarSeg(0, d.PassCount, ThemeService.Brush("Success"));
        AddBarSeg(1, d.WarnCount, new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)));
        AddBarSeg(2, d.FailCount, ThemeService.Brush("Danger"));

        CategoryList.ItemsSource = d.Categories.Select(c => new
        {
            c.Title,
            Items = c.Items.Select(ToCheckVm).ToList()
        }).ToList();
    }

    private void AddBarSeg(int col, int weight, Brush brush)
    {
        SummaryBar.ColumnDefinitions.Add(new ColumnDefinition
        {
            Width = weight > 0 ? new GridLength(weight, GridUnitType.Star) : new GridLength(0)
        });
        if (weight <= 0) return;
        var rect = new Rectangle { Fill = brush };
        Grid.SetColumn(rect, col);
        SummaryBar.Children.Add(rect);
    }

    private static CheckVm ToCheckVm(ReportCheck c)
    {
        return c.Status switch
        {
            "warn" => new CheckVm
            {
                Name = c.Name,
                Detail = c.Detail,
                Icon = "!",
                IconFg = new SolidColorBrush(Color.FromRgb(0xFB, 0xBF, 0x24)),
                IconBg = new SolidColorBrush(Color.FromArgb(0x22, 0xF5, 0x9E, 0x0B)),
                IconBorder = new SolidColorBrush(Color.FromArgb(0x55, 0xF5, 0x9E, 0x0B))
            },
            "fail" => new CheckVm
            {
                Name = c.Name,
                Detail = c.Detail,
                Icon = "✕",
                IconFg = ThemeService.Brush("Danger"),
                IconBg = ThemeService.Brush("DangerHover"),
                IconBorder = ThemeService.Brush("Danger")
            },
            _ => new CheckVm
            {
                Name = c.Name,
                Detail = c.Detail,
                Icon = "✓",
                IconFg = ThemeService.Brush("Success"),
                IconBg = ThemeService.Brush("StageDoneBg"),
                IconBorder = ThemeService.Brush("SuccessBorder")
            }
        };
    }

    private static Brush ScoreBrush(int score)
    {
        if (score >= 90) return ThemeService.Brush("Success");
        if (score >= 75) return ThemeService.Brush("Accent");
        return new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
    }

    private void OpenSizeReport_Click(object sender, RoutedEventArgs e)
    {
        var path = _current?.SizeReportPath;
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
        {
            MessageBox.Show(Strings.Reports_NoSizeReport, Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        try
        {
            Process.Start(new ProcessStartInfo { FileName = path, UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(Strings.Reports_CannotOpen + ex.Message, Strings.ProductName,
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OpenOutput_Click(object sender, RoutedEventArgs e)
    {
        var path = _current?.OutputPath;
        if (string.IsNullOrEmpty(path))
        {
            MessageBox.Show(Strings.Reports_NoOutput, Strings.ProductName, MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ShellUtil.RevealInExplorer(path);
    }

    private sealed class ReportListVm
    {
        public string Id { get; set; } = "";
        public string AppName { get; set; } = "";
        public string SubLine { get; set; } = "";
        public string ScoreText { get; set; } = "";
        public Brush ScoreBrush { get; set; } = Brushes.Gray;
        public Brush TitleFg { get; set; } = Brushes.Gray;
        public Brush RowBg { get; set; } = Brushes.Transparent;
    }

    private sealed class CheckVm
    {
        public string Name { get; set; } = "";
        public string Detail { get; set; } = "";
        public string Icon { get; set; } = "";
        public Brush IconFg { get; set; } = Brushes.Gray;
        public Brush IconBg { get; set; } = Brushes.Transparent;
        public Brush IconBorder { get; set; } = Brushes.Gray;
    }
}
