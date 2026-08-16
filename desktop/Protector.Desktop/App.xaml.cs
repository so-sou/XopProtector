using System.Windows;
using System.Windows.Threading;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        AppDataPaths.EnsureReady();
        LocalizationService.Initialize();
        base.OnStartup(e);
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception ex)
                TryShowFatal(ex);
        };
        ThemeService.Initialize();
    }

    private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        TryShowFatal(e.Exception);
        e.Handled = true;
    }

    private static void TryShowFatal(Exception ex)
    {
        try
        {
            MessageBox.Show(
                string.Format(Strings.Msg_UnhandledError, ex.GetType().Name, ex.Message),
                Strings.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        catch
        {
            // ignore
        }
    }
}
