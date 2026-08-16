using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using Protector.Desktop.Resources;

namespace Protector.Desktop.Pages;

public partial class SettingsPage : UserControl
{
    public SettingsPage()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            RefreshThemeButtons();
            RefreshLanguageButtons();
        };
        ThemeService.ThemeChanged += _ => Dispatcher.Invoke(RefreshThemeButtons);
    }

    public void BindEngine(EnginePaths paths)
    {
        JarPathText.Text = paths.PackerJar;
        ShellPathText.Text = paths.ShellDir;
        JavaPathText.Text = paths.JavaExe;
    }

    private void Tab_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not Button btn || btn.Tag is not string tag) return;
        PanelAppearance.Visibility = tag == "appearance" ? Visibility.Visible : Visibility.Collapsed;
        PanelLanguage.Visibility = tag == "language" ? Visibility.Visible : Visibility.Collapsed;
        PanelAbout.Visibility = tag == "about" ? Visibility.Visible : Visibility.Collapsed;
        TabAppearance.Style = (Style)FindResource(tag == "appearance" ? "NavButtonActive" : "NavButton");
        TabLanguage.Style = (Style)FindResource(tag == "language" ? "NavButtonActive" : "NavButton");
        TabAbout.Style = (Style)FindResource(tag == "about" ? "NavButtonActive" : "NavButton");
    }

    private void ThemeDark_Click(object sender, RoutedEventArgs e) => ThemeService.Apply(AppTheme.Dark);

    private void ThemeLight_Click(object sender, RoutedEventArgs e) => ThemeService.Apply(AppTheme.Light);

    private void LangSystem_Click(object sender, RoutedEventArgs e) => SetLanguage(LocalizationService.System);

    private void LangEn_Click(object sender, RoutedEventArgs e) => SetLanguage(LocalizationService.English);

    private void LangZh_Click(object sender, RoutedEventArgs e) => SetLanguage(LocalizationService.ChineseSimplified);

    private void SetLanguage(string preference)
    {
        var next = LocalizationService.Normalize(preference);
        if (next == LocalizationService.Preference)
        {
            RefreshLanguageButtons();
            return;
        }

        LocalizationService.SetPreference(next);
        RefreshLanguageButtons();

        var quit = MessageBox.Show(
            Strings.Settings_RestartMsg,
            Strings.Settings_RestartTitle,
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (quit == MessageBoxResult.Yes)
            Application.Current.Shutdown();
    }

    private void RefreshThemeButtons()
    {
        var dark = ThemeService.Current == AppTheme.Dark;
        StyleChoiceButton(ThemeDarkBtn, dark);
        StyleChoiceButton(ThemeLightBtn, !dark);
    }

    private void RefreshLanguageButtons()
    {
        var pref = LocalizationService.Preference;
        StyleChoiceButton(LangSystemBtn, pref == LocalizationService.System);
        StyleChoiceButton(LangEnBtn, pref == LocalizationService.English);
        StyleChoiceButton(LangZhBtn, pref == LocalizationService.ChineseSimplified);
    }

    private static void StyleChoiceButton(Button b, bool selected)
    {
        b.Background = ThemeService.Brush(selected ? "AccentBg" : "CardBg");
        b.Foreground = ThemeService.Brush(selected ? "Accent" : "TextDim");
        b.BorderBrush = ThemeService.Brush(selected ? "AccentBorder" : "BorderSoft");
    }
}
