using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Threading;

namespace Protector.Desktop;

/// <summary>
/// Keeps scrollbars invisible until the user scrolls (or hovers the bar), then fades them out after idle.
/// </summary>
public static class ScrollBarAutoHide
{
    private const double HideDelayMs = 900;
    private const double FadeMs = 160;

    private static readonly DependencyProperty StateProperty =
        DependencyProperty.RegisterAttached(
            "State", typeof(AutoHideState), typeof(ScrollBarAutoHide));

    public static readonly DependencyProperty IsEnabledProperty =
        DependencyProperty.RegisterAttached(
            "IsEnabled", typeof(bool), typeof(ScrollBarAutoHide),
            new PropertyMetadata(false, OnIsEnabledChanged));

    public static bool GetIsEnabled(DependencyObject obj) => (bool)obj.GetValue(IsEnabledProperty);
    public static void SetIsEnabled(DependencyObject obj, bool value) => obj.SetValue(IsEnabledProperty, value);

    private static void OnIsEnabledChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
    {
        if (d is not ScrollViewer viewer) return;

        if ((bool)e.NewValue)
        {
            viewer.Loaded += ViewerOnLoaded;
            viewer.Unloaded += ViewerOnUnloaded;
            if (viewer.IsLoaded) Attach(viewer);
        }
        else
        {
            viewer.Loaded -= ViewerOnLoaded;
            viewer.Unloaded -= ViewerOnUnloaded;
            Detach(viewer);
        }
    }

    private static void ViewerOnLoaded(object sender, RoutedEventArgs e)
    {
        if (sender is ScrollViewer viewer) Attach(viewer);
    }

    private static void ViewerOnUnloaded(object sender, RoutedEventArgs e)
    {
        if (sender is ScrollViewer viewer) Detach(viewer);
    }

    private static void Attach(ScrollViewer viewer)
    {
        if (viewer.GetValue(StateProperty) is AutoHideState) return;

        var state = new AutoHideState(viewer);
        viewer.SetValue(StateProperty, state);
        state.Attach();
    }

    private static void Detach(ScrollViewer viewer)
    {
        if (viewer.GetValue(StateProperty) is not AutoHideState state) return;
        state.Detach();
        viewer.ClearValue(StateProperty);
    }

    private sealed class AutoHideState
    {
        private readonly ScrollViewer _viewer;
        private readonly DispatcherTimer _hideTimer;
        private ScrollBar? _vertical;
        private ScrollBar? _horizontal;
        private bool _visible;

        public AutoHideState(ScrollViewer viewer)
        {
            _viewer = viewer;
            _hideTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(HideDelayMs) };
            _hideTimer.Tick += (_, _) =>
            {
                _hideTimer.Stop();
                if (_vertical?.IsMouseOver == true || _horizontal?.IsMouseOver == true) return;
                SetVisible(false);
            };
        }

        public void Attach()
        {
            _viewer.ApplyTemplate();
            _vertical = FindScrollBar(_viewer, Orientation.Vertical);
            _horizontal = FindScrollBar(_viewer, Orientation.Horizontal);

            HideImmediate(_vertical);
            HideImmediate(_horizontal);

            _viewer.ScrollChanged += OnScrollChanged;
            WireBar(_vertical);
            WireBar(_horizontal);
        }

        public void Detach()
        {
            _hideTimer.Stop();
            _viewer.ScrollChanged -= OnScrollChanged;
            UnwireBar(_vertical);
            UnwireBar(_horizontal);
            _vertical = null;
            _horizontal = null;
        }

        private void WireBar(ScrollBar? bar)
        {
            if (bar == null) return;
            bar.MouseEnter += OnBarMouseEnter;
            bar.MouseLeave += OnBarMouseLeave;
        }

        private void UnwireBar(ScrollBar? bar)
        {
            if (bar == null) return;
            bar.MouseEnter -= OnBarMouseEnter;
            bar.MouseLeave -= OnBarMouseLeave;
        }

        private void OnScrollChanged(object sender, ScrollChangedEventArgs e)
        {
            if (Math.Abs(e.VerticalChange) < 0.1 && Math.Abs(e.HorizontalChange) < 0.1) return;
            SetVisible(true);
            RestartHideTimer();
        }

        private void OnBarMouseEnter(object sender, System.Windows.Input.MouseEventArgs e)
        {
            _hideTimer.Stop();
            SetVisible(true);
        }

        private void OnBarMouseLeave(object sender, System.Windows.Input.MouseEventArgs e)
        {
            RestartHideTimer();
        }

        private void RestartHideTimer()
        {
            _hideTimer.Stop();
            _hideTimer.Start();
        }

        private void SetVisible(bool visible)
        {
            if (_visible == visible) return;
            _visible = visible;
            Animate(_vertical, visible);
            Animate(_horizontal, visible);
        }

        private static void HideImmediate(ScrollBar? bar)
        {
            if (bar == null) return;
            bar.BeginAnimation(UIElement.OpacityProperty, null);
            bar.Opacity = 0;
            bar.IsHitTestVisible = false;
        }

        private static void Animate(ScrollBar? bar, bool visible)
        {
            if (bar == null) return;
            bar.IsHitTestVisible = visible;
            var anim = new DoubleAnimation
            {
                To = visible ? 1 : 0,
                Duration = TimeSpan.FromMilliseconds(FadeMs),
                FillBehavior = FillBehavior.HoldEnd,
            };
            bar.BeginAnimation(UIElement.OpacityProperty, anim);
        }

        private static ScrollBar? FindScrollBar(DependencyObject root, Orientation orientation)
        {
            var count = VisualTreeHelper.GetChildrenCount(root);
            for (var i = 0; i < count; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is ScrollBar bar && bar.Orientation == orientation)
                    return bar;
                var nested = FindScrollBar(child, orientation);
                if (nested != null) return nested;
            }
            return null;
        }
    }
}
