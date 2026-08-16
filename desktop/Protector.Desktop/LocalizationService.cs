using System.Globalization;
using Protector.Desktop.Resources;

namespace Protector.Desktop;

public static class LocalizationService
{
    public const string System = "system";
    public const string English = "en";
    public const string ChineseSimplified = "zh-CN";

    public static string Preference { get; private set; } = System;

    public static CultureInfo CurrentUiCulture { get; private set; } = CultureInfo.InvariantCulture;

    public static void Initialize()
    {
        var pref = AppSettings.Load().Language;
        if (string.IsNullOrWhiteSpace(pref)) pref = System;
        Apply(pref, persist: false);
    }

    /// <summary>
    /// Persist language preference. UI strings already loaded in XAML need an app restart.
    /// </summary>
    public static void SetPreference(string preference)
    {
        Apply(preference, persist: true);
    }

    private static void Apply(string preference, bool persist)
    {
        Preference = Normalize(preference);
        CurrentUiCulture = ResolveCulture(Preference);

        CultureInfo.DefaultThreadCurrentUICulture = CurrentUiCulture;
        CultureInfo.DefaultThreadCurrentCulture = CurrentUiCulture;
        CultureInfo.CurrentUICulture = CurrentUiCulture;
        CultureInfo.CurrentCulture = CurrentUiCulture;
        Strings.Culture = CurrentUiCulture;

        if (persist)
            AppSettings.Update(d => d.Language = Preference);
    }

    public static string Normalize(string? preference)
    {
        if (string.IsNullOrWhiteSpace(preference)) return System;
        preference = preference.Trim();
        if (preference.Equals(English, StringComparison.OrdinalIgnoreCase)
            || preference.Equals("en-US", StringComparison.OrdinalIgnoreCase))
            return English;
        if (preference.Equals(ChineseSimplified, StringComparison.OrdinalIgnoreCase)
            || preference.Equals("zh", StringComparison.OrdinalIgnoreCase)
            || preference.StartsWith("zh-", StringComparison.OrdinalIgnoreCase))
            return ChineseSimplified;
        if (preference.Equals(System, StringComparison.OrdinalIgnoreCase))
            return System;
        return System;
    }

    private static CultureInfo ResolveCulture(string preference)
    {
        if (preference == English)
            return CultureInfo.GetCultureInfo("en");
        if (preference == ChineseSimplified)
            return CultureInfo.GetCultureInfo("zh-CN");

        var os = CultureInfo.CurrentUICulture;
        if (os.Name.StartsWith("zh", StringComparison.OrdinalIgnoreCase))
            return CultureInfo.GetCultureInfo("zh-CN");
        return CultureInfo.GetCultureInfo("en");
    }
}
