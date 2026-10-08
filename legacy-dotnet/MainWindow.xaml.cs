// SailHighSea Firewall - main window, application entry point and the small helper types the UI needs.
// MIT License - see the LICENSE file in the repository root.

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace SailHighSeaFireWall;

// ==========================================================================================
//  Entry point (the project has no App.xaml; see <StartupObject> in SailHighSea-FireWall.csproj)
// ==========================================================================================

public static class Program
{
    [STAThread]
    public static int Main(string[] args)
    {
        // Anything that escapes is written to crash.log in the data folder.
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            CrashLog.Write("Unhandled exception", e.ExceptionObject as Exception);
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            CrashLog.Write("Unobserved task exception", e.Exception);
            e.SetObserved();
        };

        // Emergency switch: "SailHighSeaFireWall.exe --disable-filters" removes the default-deny
        // filters and exits, without opening the window.
        if (args.Any(a => string.Equals(a, "--disable-filters", StringComparison.OrdinalIgnoreCase)))
            return DisableFiltersAndExit();

        var app = new Application();

        app.DispatcherUnhandledException += (_, e) =>
        {
            CrashLog.Write("UI exception", e.Exception);
            MessageBox.Show(
                $"SailHighSea Firewall hit an unexpected error:\n\n{e.Exception.Message}\n\nDetails were written to {CrashLog.FilePath}",
                "SailHighSea Firewall",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            e.Handled = true;
        };

        return app.Run(new MainWindow());
    }

    private static int DisableFiltersAndExit()
    {
        try
        {
            using var firewall = new AppFirewall();
            firewall.DisableFilters();

            MessageBox.Show(
                "The filters are disabled. Applications can reach the network again.",
                "SailHighSea Firewall",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            return 0;
        }
        catch (Exception ex)
        {
            CrashLog.Write("--disable-filters failed", ex);
            MessageBox.Show(
                $"Could not disable the filters:\n\n{ex.Message}",
                "SailHighSea Firewall",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return 1;
        }
    }
}

/// <summary>Appends unexpected errors to crash.log so a crash leaves something to look at.</summary>
internal static class CrashLog
{
    public static string FilePath => System.IO.Path.Combine(AppPaths.DataDirectory, "crash.log");

    public static void Write(string title, Exception? exception)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.DataDirectory);
            File.AppendAllText(
                FilePath,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {title}{Environment.NewLine}{exception}{Environment.NewLine}{Environment.NewLine}");
        }
        catch (Exception)
        {
            // Logging must never throw.
        }
    }
}

// ==========================================================================================
//  Main window
// ==========================================================================================

public partial class MainWindow : Window
{
    private enum StatusFilter { All, Blocked, Allowed }

    private readonly ObservableCollection<AppEntry> _apps = new();
    private readonly ObservableCollection<RunningApp> _pickerItems = new();
    private readonly RuleStore _store = new();
    private readonly AppFirewall _firewall;
    private readonly DispatcherTimer _refreshTimer = new() { Interval = TimeSpan.FromSeconds(10) };

    private readonly ICollectionView _view;
    private readonly ICollectionView _pickerView;

    private AppSettings _settings = AppSettings.Load();
    private StatusFilter _statusFilter = StatusFilter.All;
    private string _backendLabel = "Checking…";
    private bool _scanning;
    private int _pickerScanId;

    private bool _engineAvailable;
    private bool _filtersEnabled;
    private bool _watching;
    private bool _closing;
    private bool _crashNotice;

    // Blocked-connection notifications
    private readonly Queue<BlockedAttempt> _notifyQueue = new();
    private readonly Dictionary<string, DateTime> _snoozed = new(StringComparer.OrdinalIgnoreCase);
    private NotificationWindow? _notifyShowing;

    public MainWindow()
    {
        InitializeComponent();

        _firewall = new AppFirewall(
            new WfpOptions { Persistent = _settings.PermanentRules },
            message => Dispatcher.InvokeAsync(() => SetMessage(message)));

        _view = CollectionViewSource.GetDefaultView(_apps);
        _view.Filter = FilterEntry;
        // Allowed applications first, then alphabetical. Clicking a column header overrides this.
        _view.SortDescriptions.Add(new SortDescription(nameof(AppEntry.IsAllowed), ListSortDirection.Descending));
        _view.SortDescriptions.Add(new SortDescription(nameof(AppEntry.Name), ListSortDirection.Ascending));
        AppsGrid.ItemsSource = _view;

        _pickerView = CollectionViewSource.GetDefaultView(_pickerItems);
        _pickerView.Filter = PickerMatches;
        PickerGrid.ItemsSource = _pickerView;

        _refreshTimer.Tick += async (_, _) =>
        {
            if (AddOverlay.Visibility != Visibility.Visible && SettingsOverlay.Visibility != Visibility.Visible)
                await RefreshProcessesAsync(silent: true);
        };
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        DarkTitleBar.Apply(this);
    }

    protected override void OnClosed(EventArgs e)
    {
        _closing = true;
        _refreshTimer.Stop();
        _notifyQueue.Clear();
        _notifyShowing?.Close();

        // Filters deliberately stay in place: closing the window must not switch the firewall off.
        _firewall.Dispose();
        DeleteWatcherMarker();   // a clean exit: nothing crashed while listening
        base.OnClosed(e);
    }

    protected override void OnPreviewKeyDown(KeyEventArgs e)
    {
        if (e.Key == Key.Escape && HideOverlays())
            e.Handled = true;
        else
            base.OnPreviewKeyDown(e);
    }

    // ------------------------------------------------------------------ startup

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        try
        {
            foreach (StoredRule rule in _store.Rules)
            {
                _apps.Add(new AppEntry(rule.Name, rule.Path)
                {
                    IsAllowed = true,
                    RuleKey = rule.RuleKey,
                });
            }

            // The last run died while it was listening for blocked connections: do not listen again
            // until the user turns notifications back on.
            if (File.Exists(AppPaths.WatcherMarker))
            {
                _crashNotice = true;
                _settings.Notifications = false;
                SaveSettings();
                DeleteWatcherMarker();
            }

            UpdateSummary();
            ApplySettings();

            await ProbeFirewallAsync();
            await RefreshProcessesAsync();

            if (_crashNotice)
                SetMessage("Notifications were switched off because the app stopped unexpectedly while listening for blocked connections. Use the Notifications button to turn them back on.");
        }
        catch (Exception ex)
        {
            CrashLog.Write("Startup problem", ex);
            SetMessage($"Startup problem: {ex.Message}");
        }
    }

    private async Task ProbeFirewallAsync()
    {
        bool available = false;
        bool enabled = false;
        bool? permanent = null;

        try
        {
            (available, enabled, permanent) = await Task.Run<(bool, bool, bool?)>(() =>
            {
                if (!_firewall.Probe())
                    return (false, false, null);

                bool on = _firewall.AreFiltersEnabled();
                return (true, on, on ? _firewall.AreFiltersPermanent() : null);
            });
        }
        catch (Exception ex)
        {
            SetMessage($"Could not check the filtering engine: {ex.Message}");
        }

        _engineAvailable = available;

        if (!available)
        {
            _backendLabel = "Not available (the Base Filtering Engine could not be reached)";
            FilterButton.IsEnabled = false;
            AddButton.IsEnabled = false;
            SetStatus("Filtering Unavailable", "DangerBrush",
                "The Windows Filtering Platform could not be reached. Check that the Base Filtering Engine service is running and that the app runs as administrator.");
            return;
        }

        _backendLabel = "Windows Filtering Platform";
        _filtersEnabled = enabled;

        // Filters that are already installed decide whether new rules are permanent too.
        if (enabled && permanent is bool installedPermanent)
            _settings.PermanentRules = installedPermanent;
        _firewall.SetPermanent(_settings.PermanentRules);

        if (enabled)
        {
            // Temporary rules vanish on reboot; bring back the permits of every allowed app.
            List<(Guid RuleKey, string Path)> allowed = AllowedApps();
            try
            {
                int restored = await Task.Run(() => _firewall.EnsureApplicationRules(allowed));
                if (restored > 0)
                    SetMessage($"Restored {restored} application rule{(restored == 1 ? "" : "s")}.");
            }
            catch (Exception ex)
            {
                SetMessage($"Could not restore the application rules: {ex.Message}");
            }
        }

        ApplyFilterState();
    }

    private List<(Guid RuleKey, string Path)> AllowedApps() =>
        _apps.Where(a => a.IsAllowed && a.RuleKey is not null)
             .Select(a => (a.RuleKey.GetValueOrDefault(), a.Path))
             .ToList();

    private void SetStatus(string text, string brushKey, string? toolTip)
    {
        StatusText.Text = text;
        StatusDot.Fill = (Brush)FindResource(brushKey);
        StatusPill.ToolTip = toolTip;
    }

    private void SetMessage(string message) => FooterMessage.Text = message;

    /// <summary>Brings the status pill, the Enable/Disable button, the rows and the watcher in line with <c>_filtersEnabled</c>.</summary>
    private void ApplyFilterState()
    {
        foreach (AppEntry entry in _apps)
            entry.FiltersEnabled = _filtersEnabled;

        if (_filtersEnabled)
        {
            SetStatus("Filtering Active", "SuccessBrush",
                "Default deny is on: only allowed applications (plus localhost, DHCP and DNS) can reach the network.");
            FilterButtonText.Text = "Disable Filters";
            FilterButtonIcon.Text = "";   // unlock
        }
        else
        {
            SetStatus("Filters Disabled", "WarningBrush",
                "Nothing is being blocked. Click Enable Filters to block every application that is not allowed.");
            FilterButtonText.Text = "Enable Filters";
            FilterButtonIcon.Text = "";   // lock
        }

        _view.Refresh();
        UpdateSummary();
        UpdateWatcher();
    }

    // ------------------------------------------------------------------ enable / disable filters

    private async void OnFilterToggleClick(object sender, RoutedEventArgs e)
    {
        if (!_engineAvailable)
            return;

        FilterButton.IsEnabled = false;
        try
        {
            if (_filtersEnabled)
                await DisableFiltersAsync();
            else
                await EnableFiltersAsync();
        }
        finally
        {
            FilterButton.IsEnabled = _engineAvailable;
        }
    }

    private async Task DisableFiltersAsync()
    {
        try
        {
            await Task.Run(_firewall.DisableFilters);
            _filtersEnabled = false;
            ApplyFilterState();
            SetMessage("Filters disabled. Every application can reach the network again; your allow rules are kept.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not disable the filters", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private async Task EnableFiltersAsync()
    {
        string noApps = _apps.Any(a => a.IsAllowed)
            ? string.Empty
            : "\n\nNo applications are allowed yet, so everything except localhost, DHCP and DNS will be blocked until you allow something. Disable Filters undoes this at any time.";

        MessageBoxResult answer = MessageBox.Show(
            this,
            "This will deny network access to every application that is not on your allowed list." +
            "\n\nYes: permanent rules (kept until you disable them, also after a reboot)" +
            "\nNo: temporary rules (reset by the next reboot)" +
            "\nCancel: do nothing" + noApps,
            "Enable filters",
            MessageBoxButton.YesNoCancel,
            MessageBoxImage.Question,
            MessageBoxResult.Cancel);

        if (answer == MessageBoxResult.Cancel)
            return;

        bool permanent = answer == MessageBoxResult.Yes;
        List<(Guid RuleKey, string Path)> allowed = AllowedApps();
        bool allowDns = _settings.AllowDns;

        try
        {
            await Task.Run(() => _firewall.EnableFilters(permanent, allowDns, allowed));

            _settings.PermanentRules = permanent;
            SaveSettings();

            _filtersEnabled = true;
            ApplyFilterState();
            SetMessage(permanent
                ? "Filters enabled (permanent). Only allowed applications can reach the network."
                : "Filters enabled (temporary, until the next reboot). Only allowed applications can reach the network.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Could not enable the filters", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    // ------------------------------------------------------------------ overlays

    private void ShowOverlay(Grid overlay)
    {
        MainContent.IsEnabled = false;
        overlay.Visibility = Visibility.Visible;
    }

    /// <summary>Closes any open panel. Returns true if one was open.</summary>
    private bool HideOverlays()
    {
        bool wasOpen = AddOverlay.Visibility == Visibility.Visible
                    || SettingsOverlay.Visibility == Visibility.Visible;

        AddOverlay.Visibility = Visibility.Collapsed;
        SettingsOverlay.Visibility = Visibility.Collapsed;
        MainContent.IsEnabled = true;

        if (wasOpen)
            _pickerScanId++;   // discard a picker scan that is still running

        return wasOpen;
    }

    // ------------------------------------------------------------------ process list

    private async void OnRefreshClick(object sender, RoutedEventArgs e) => await RefreshProcessesAsync();

    private async Task RefreshProcessesAsync(bool silent = false)
    {
        if (_scanning)
            return;

        _scanning = true;
        RefreshButton.IsEnabled = false;
        if (!silent)
            SetMessage("Scanning running processes…");

        try
        {
            List<RunningApp> running = await Task.Run(ProcessScanner.Scan);
            MergeRunning(running);

            if (!silent)
                SetMessage($"Found {running.Count} running application{(running.Count == 1 ? "" : "s")}.");
        }
        catch (Exception ex)
        {
            SetMessage($"Process scan failed: {ex.Message}");
        }
        finally
        {
            _scanning = false;
            RefreshButton.IsEnabled = true;
            UpdateSummary();
        }
    }

    /// <summary>
    /// Brings the grid in line with the running processes: updates the "running" dots, adds newly
    /// started programs and drops entries that only existed because they were running.
    /// Entries that have an allow rule are never removed.
    /// </summary>
    private void MergeRunning(IReadOnlyList<RunningApp> running)
    {
        var runningPaths = new HashSet<string>(running.Select(r => r.Path), StringComparer.OrdinalIgnoreCase);

        foreach (AppEntry entry in _apps.ToList())
        {
            entry.IsRunning = runningPaths.Contains(entry.Path);

            bool hidden = _settings.HideWindowsApps && ProcessScanner.IsWindowsComponent(entry.Path);
            if (!entry.IsAllowed && !entry.IsBusy && (!entry.IsRunning || hidden))
                _apps.Remove(entry);
        }

        var known = new HashSet<string>(_apps.Select(a => a.Path), StringComparer.OrdinalIgnoreCase);
        foreach (RunningApp app in running)
        {
            if (known.Contains(app.Path))
                continue;
            if (_settings.HideWindowsApps && ProcessScanner.IsWindowsComponent(app.Path))
                continue;

            _apps.Add(new AppEntry(app.Name, app.Path) { IsRunning = true, FiltersEnabled = _filtersEnabled });
        }
    }

    // ------------------------------------------------------------------ search / filter

    private bool FilterEntry(object item)
    {
        if (item is not AppEntry entry)
            return false;

        if (_statusFilter == StatusFilter.Blocked && entry.IsAllowed)
            return false;
        if (_statusFilter == StatusFilter.Allowed && !entry.IsAllowed)
            return false;

        string query = SearchBox.Text.Trim();
        if (query.Length == 0)
            return true;

        return entry.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
            || entry.Path.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (_view is null)
            return;

        _view.Refresh();
        UpdateSummary();
    }

    private void OnFilterChanged(object sender, RoutedEventArgs e)
    {
        // Checked fires once while the XAML is still being loaded, before _view exists.
        if (_view is null)
            return;

        _statusFilter = ReferenceEquals(sender, FilterBlocked) ? StatusFilter.Blocked
                      : ReferenceEquals(sender, FilterAllowed) ? StatusFilter.Allowed
                      : StatusFilter.All;

        _view.Refresh();
        UpdateSummary();
    }

    private void UpdateSummary()
    {
        int total = _apps.Count;
        int allowed = _apps.Count(a => a.IsAllowed);
        int shown = _view.Cast<object>().Count();

        SummaryText.Text = shown == total
            ? $"{total} apps · {allowed} allowed"
            : $"{shown} of {total} apps · {allowed} allowed";
    }

    // ------------------------------------------------------------------ "Add Application" panel

    private async void OnAddApplicationClick(object sender, RoutedEventArgs e)
    {
        PickerSearchBox.Text = string.Empty;
        PickerAllowButton.IsEnabled = false;
        PickerStatus.Text = "Scanning running processes…";
        _pickerItems.Clear();
        ShowOverlay(AddOverlay);
        PickerSearchBox.Focus();

        int scanId = ++_pickerScanId;
        try
        {
            List<RunningApp> apps = await Task.Run(ProcessScanner.Scan);
            if (scanId != _pickerScanId)
                return;   // panel was closed (or reopened) while scanning

            foreach (RunningApp app in apps)
                _pickerItems.Add(app);

            PickerStatus.Text = $"{apps.Count} running applications. Double-click one to allow it, or use Browse… for a program that is not running.";
        }
        catch (Exception ex)
        {
            if (scanId == _pickerScanId)
                PickerStatus.Text = $"Could not list running processes: {ex.Message}";
        }
    }

    private bool PickerMatches(object item)
    {
        if (item is not RunningApp app)
            return false;

        string query = PickerSearchBox.Text.Trim();
        return query.Length == 0
            || app.Name.Contains(query, StringComparison.OrdinalIgnoreCase)
            || app.Path.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void OnPickerSearchChanged(object sender, TextChangedEventArgs e) => _pickerView?.Refresh();

    private void OnPickerSelectionChanged(object sender, SelectionChangedEventArgs e) =>
        PickerAllowButton.IsEnabled = PickerGrid.SelectedItem is RunningApp;

    private async void OnPickerDoubleClick(object sender, MouseButtonEventArgs e)
    {
        // Ignore double-clicks on the header or empty space.
        if (PickerGrid.SelectedItem is RunningApp && e.OriginalSource is DependencyObject source && IsInsideRow(source))
            await CompletePickAsync();
    }

    private static bool IsInsideRow(DependencyObject? element)
    {
        while (element is not null)
        {
            if (element is DataGridRow)
                return true;

            // Run / Inline elements are not Visuals; walk the logical tree for those.
            element = element is Visual or System.Windows.Media.Media3D.Visual3D
                ? VisualTreeHelper.GetParent(element)
                : LogicalTreeHelper.GetParent(element);
        }

        return false;
    }

    private async void OnPickerAllowClick(object sender, RoutedEventArgs e) => await CompletePickAsync();

    private void OnPickerCancelClick(object sender, RoutedEventArgs e) => HideOverlays();

    private async void OnPickerBrowseClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Choose the executable to allow",
            Filter = "Applications (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
        };

        if (dialog.ShowDialog(this) != true)
            return;

        HideOverlays();
        await AllowPathAsync(dialog.FileName);
    }

    private async Task CompletePickAsync()
    {
        if (PickerGrid.SelectedItem is not RunningApp app)
            return;

        HideOverlays();
        await AllowPathAsync(app.Path);
    }

    // ------------------------------------------------------------------ allow / remove

    /// <summary>Adds the executable to the list (if needed) and allows it.</summary>
    private async Task AllowPathAsync(string path)
    {
        AppEntry? entry = _apps.FirstOrDefault(a => PathsEqual(a.Path, path));
        bool created = false;

        if (entry is null)
        {
            entry = new AppEntry(ProcessScanner.GetDisplayName(path), path) { FiltersEnabled = _filtersEnabled };
            _apps.Add(entry);
            created = true;
        }

        if (entry.IsAllowed)
        {
            SetMessage($"{entry.Name} is already allowed.");
        }
        else
        {
            bool ok = await SetAllowedAsync(entry, true);
            if (!ok && created)
            {
                _apps.Remove(entry);
                return;
            }
        }

        if (_view.Cast<object>().Contains(entry))
        {
            AppsGrid.SelectedItem = entry;
            AppsGrid.ScrollIntoView(entry);
        }

        await RefreshProcessesAsync(silent: true);   // updates the "running" dot of a browsed entry
    }

    private async void OnRemoveRuleClick(object sender, RoutedEventArgs e)
    {
        List<AppEntry> targets = AppsGrid.SelectedItems.OfType<AppEntry>().Where(a => a.IsAllowed).ToList();
        if (targets.Count == 0)
        {
            SetMessage("Select one or more allowed applications first, then click Remove Rule.");
            return;
        }

        int removed = 0;
        foreach (AppEntry entry in targets)
        {
            if (!await SetAllowedAsync(entry, false))
                continue;

            removed++;
            if (!entry.IsRunning)
                _apps.Remove(entry);   // it was only listed because of its rule
        }

        UpdateSummary();
        SetMessage(_filtersEnabled
            ? $"Removed {removed} rule{(removed == 1 ? "" : "s")}; those applications are now blocked."
            : $"Removed {removed} rule{(removed == 1 ? "" : "s")}.");
    }

    private async void OnToggleClick(object sender, RoutedEventArgs e)
    {
        if (sender is not ToggleButton toggle || toggle.DataContext is not AppEntry entry)
            return;

        bool ok = await SetAllowedAsync(entry, !entry.IsAllowed);

        // The click already flipped the switch visually; put it back if nothing changed.
        if (!ok)
            toggle.SetCurrentValue(ToggleButton.IsCheckedProperty, entry.IsAllowed);
    }

    /// <summary>Creates or removes the allow rule for <paramref name="entry"/>. Returns true on success.</summary>
    private async Task<bool> SetAllowedAsync(AppEntry entry, bool allow)
    {
        if (entry.IsBusy)
            return false;

        if (!allow && _filtersEnabled && ProcessScanner.IsWindowsComponent(entry.Path))
        {
            MessageBoxResult answer = MessageBox.Show(
                this,
                $"\"{entry.Name}\" is part of Windows.\n\nBlocking it can break networking, Windows Update or sign-in. Remove its allow rule anyway?",
                "Windows component",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning,
                MessageBoxResult.No);

            if (answer != MessageBoxResult.Yes)
                return false;
        }

        entry.IsBusy = true;
        try
        {
            if (allow)
            {
                Guid key = await Task.Run(() => _firewall.AllowApplication(entry.Path));

                entry.RuleKey = key;
                entry.IsAllowed = true;
                RememberRule(entry);

                SetMessage(_filtersEnabled
                    ? $"Allowed {entry.Name} to use the network."
                    : $"Allowed {entry.Name}. The rule takes effect once you enable filters.");
            }
            else
            {
                bool removed = true;
                if (entry.RuleKey is Guid key)
                    removed = await Task.Run(() => _firewall.RemoveApplication(key));

                entry.IsAllowed = false;
                entry.RuleKey = null;
                ForgetRule(entry);

                SetMessage(removed
                    ? $"Removed the rule for {entry.Name}."
                    : $"{entry.Name} had no active rule any more; it is marked as not allowed.");
            }

            return true;
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                ex.Message,
                allow ? "Could not allow the application" : "Could not remove the rule",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return false;
        }
        finally
        {
            entry.IsBusy = false;
            if (_statusFilter != StatusFilter.All)
                _view.Refresh();
            UpdateSummary();
        }
    }

    private void RememberRule(AppEntry entry)
    {
        if (entry.RuleKey is not Guid key)
            return;

        try
        {
            _store.Upsert(new StoredRule(entry.Name, entry.Path, key));
        }
        catch (Exception ex)
        {
            SetMessage($"The rule is active, but saving the rule list failed: {ex.Message}");
        }
    }

    private void ForgetRule(AppEntry entry)
    {
        try
        {
            _store.Remove(entry.Path);
        }
        catch (Exception ex)
        {
            SetMessage($"The rule was removed, but saving the rule list failed: {ex.Message}");
        }
    }

    private static bool PathsEqual(string a, string b) =>
        string.Equals(a, b, StringComparison.OrdinalIgnoreCase);

    // ------------------------------------------------------------------ notifications

    private void OnNotificationsToggleClick(object sender, RoutedEventArgs e)
    {
        _settings.Notifications = !_settings.Notifications;
        SaveSettings();
        ApplySettings();
        UpdateWatcher();

        SetMessage(_settings.Notifications
            ? "Notifications on: you will be offered to allow applications that get blocked."
            : "Notifications off: blocked applications are dropped silently.");
    }

    /// <summary>Starts or stops listening for drop events: only useful while filters are on.</summary>
    private void UpdateWatcher()
    {
        bool want = _engineAvailable && _filtersEnabled && _settings.Notifications;

        try
        {
            if (want && !_watching)
            {
                WriteWatcherMarker();
                _firewall.StartWatching(attempt => Dispatcher.InvokeAsync(() => OnBlockedAttempt(attempt)));
                _watching = true;
            }
            else if (!want && _watching)
            {
                _firewall.StopWatching();
                _watching = false;
                DeleteWatcherMarker();
                _notifyQueue.Clear();
                _notifyShowing?.Close();
            }
        }
        catch (Exception ex)
        {
            _watching = false;
            DeleteWatcherMarker();
            CrashLog.Write("Could not start notifications", ex);
            SetMessage($"Notifications are not available: {ex.Message}");
        }
    }

    private static void WriteWatcherMarker()
    {
        try
        {
            Directory.CreateDirectory(AppPaths.DataDirectory);
            File.WriteAllText(AppPaths.WatcherMarker, DateTime.UtcNow.ToString("O"));
        }
        catch (Exception)
        {
            // Best effort: the marker only exists to detect a crash.
        }
    }

    private static void DeleteWatcherMarker()
    {
        try
        {
            File.Delete(AppPaths.WatcherMarker);
        }
        catch (Exception)
        {
            // Best effort.
        }
    }

    private void OnBlockedAttempt(BlockedAttempt attempt)
    {
        if (_closing || !_settings.Notifications || !_filtersEnabled)
            return;

        string path = attempt.Path;

        if (PathsEqual(path, Environment.ProcessPath ?? string.Empty))
            return;
        if (_apps.Any(a => a.IsAllowed && PathsEqual(a.Path, path)))
            return;
        if (_snoozed.TryGetValue(path, out DateTime until) && until > DateTime.UtcNow)
            return;
        if (_notifyQueue.Any(q => PathsEqual(q.Path, path)))
            return;
        if (_notifyShowing is not null && PathsEqual(_notifyShowing.Attempt.Path, path))
            return;
        if (!File.Exists(path))
            return;

        _notifyQueue.Enqueue(attempt);
        ShowNextNotification();
    }

    private void ShowNextNotification()
    {
        if (_closing || _notifyShowing is not null || _notifyQueue.Count == 0)
            return;

        BlockedAttempt attempt = _notifyQueue.Dequeue();
        var window = new NotificationWindow(this, attempt, ProcessScanner.GetDisplayName(attempt.Path));
        _notifyShowing = window;

        window.Closed += async (_, _) =>
        {
            _notifyShowing = null;
            if (_closing)
                return;

            if (window.Decision == NotificationDecision.Allow)
                await AllowPathAsync(attempt.Path);
            else
                _snoozed[attempt.Path] = DateTime.UtcNow.AddMinutes(5);   // do not nag about it again right away

            ShowNextNotification();
        };

        window.Show();
    }

    // ------------------------------------------------------------------ settings panel

    private void OnSettingsClick(object sender, RoutedEventArgs e)
    {
        HideWindowsSwitch.IsChecked = _settings.HideWindowsApps;
        AutoRefreshSwitch.IsChecked = _settings.AutoRefresh;
        AllowDnsSwitch.IsChecked = _settings.AllowDns;
        SettingsBackendText.Text = _backendLabel;
        SettingsDataFolderText.Text = AppPaths.DataDirectory;
        ShowOverlay(SettingsOverlay);
    }

    private void OnSettingsCancelClick(object sender, RoutedEventArgs e) => HideOverlays();

    private async void OnSettingsSaveClick(object sender, RoutedEventArgs e)
    {
        bool dnsChanged = _settings.AllowDns != (AllowDnsSwitch.IsChecked == true);

        _settings.HideWindowsApps = HideWindowsSwitch.IsChecked == true;
        _settings.AutoRefresh = AutoRefreshSwitch.IsChecked == true;
        _settings.AllowDns = AllowDnsSwitch.IsChecked == true;
        HideOverlays();

        SaveSettings();
        ApplySettings();

        if (dnsChanged && _filtersEnabled)
            SetMessage("The DNS setting applies the next time you enable filters (disable, then enable them again).");

        await RefreshProcessesAsync();
    }

    private void SaveSettings()
    {
        try
        {
            _settings.Save();
        }
        catch (Exception ex)
        {
            SetMessage($"Could not save settings: {ex.Message}");
        }
    }

    private void ApplySettings()
    {
        if (_settings.AutoRefresh)
            _refreshTimer.Start();
        else
            _refreshTimer.Stop();

        NotificationsText.Text = _settings.Notifications ? "Notifications: On" : "Notifications: Off";
        NotificationsButton.Opacity = _settings.Notifications ? 1.0 : 0.65;
    }
}

// ==========================================================================================
//  Grid row model
// ==========================================================================================

/// <summary>One row in the main grid: an application and the state of its allow rule.</summary>
public sealed class AppEntry : INotifyPropertyChanged
{
    private bool _isAllowed;
    private bool _filtersEnabled;
    private bool _isRunning;
    private bool _isBusy;

    public AppEntry(string name, string path)
    {
        Name = name;
        Path = path;
    }

    public string Name { get; }

    /// <summary>Full path of the executable (the identity of the entry).</summary>
    public string Path { get; }

    /// <summary>Rule GUID returned by <see cref="AppFirewall"/>; null while no rule exists.</summary>
    public Guid? RuleKey { get; set; }

    /// <summary>True while the application has an allow rule.</summary>
    public bool IsAllowed
    {
        get => _isAllowed;
        set
        {
            if (_isAllowed == value)
                return;

            _isAllowed = value;
            OnStateChanged();
        }
    }

    /// <summary>True while default-deny filtering is switched on (set by the window for every row).</summary>
    public bool FiltersEnabled
    {
        get => _filtersEnabled;
        set
        {
            if (_filtersEnabled == value)
                return;

            _filtersEnabled = value;
            OnStateChanged();
        }
    }

    /// <summary>Not allowed while filtering is on, i.e. the application is actually being blocked.</summary>
    public bool IsDenied => _filtersEnabled && !_isAllowed;

    public bool IsRunning
    {
        get => _isRunning;
        set
        {
            if (_isRunning == value)
                return;

            _isRunning = value;
            OnPropertyChanged();
        }
    }

    /// <summary>True while an allow/remove operation for this entry is in flight.</summary>
    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (_isBusy == value)
                return;

            _isBusy = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsNotBusy));
        }
    }

    public bool IsNotBusy => !_isBusy;

    public string StatusText => _isAllowed ? "Allowed" : _filtersEnabled ? "Blocked" : "No rule";

    // The WFP layer used by WfpEngine (ALE_AUTH_CONNECT) only covers outgoing connections.
    public string DirectionText => _isAllowed || _filtersEnabled ? "Outbound" : "—";

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnStateChanged()
    {
        OnPropertyChanged(nameof(IsAllowed));
        OnPropertyChanged(nameof(FiltersEnabled));
        OnPropertyChanged(nameof(IsDenied));
        OnPropertyChanged(nameof(StatusText));
        OnPropertyChanged(nameof(DirectionText));
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

// ==========================================================================================
//  "Application blocked" pop-up (built in code, no XAML)
// ==========================================================================================

internal enum NotificationDecision { Ignore, Allow }

/// <summary>
/// Small always-on-top window in the bottom-right corner that offers to allow an application
/// that was just blocked. Closes itself after a while; the outcome is in <see cref="Decision"/>.
/// </summary>
internal sealed class NotificationWindow : Window
{
    private readonly DispatcherTimer _timer = new() { Interval = TimeSpan.FromSeconds(30) };

    public NotificationWindow(Window owner, BlockedAttempt attempt, string appName)
    {
        Attempt = attempt;

        Brush Res(string key) => (Brush)owner.FindResource(key);

        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        ShowInTaskbar = false;
        ShowActivated = false;      // do not steal focus from what the user is doing
        Topmost = true;
        SizeToContent = SizeToContent.WidthAndHeight;
        MinWidth = 340;
        MaxWidth = 440;
        Background = Res("SurfaceBrush");
        Foreground = Res("TextBrush");
        FontFamily = owner.FontFamily;
        UseLayoutRounding = true;
        Title = "SailHighSea Firewall";

        var allow = new Button
        {
            Content = "Allow",
            MinWidth = 90,
            Style = (Style)owner.FindResource("AccentButton"),
        };
        allow.Click += (_, _) =>
        {
            Decision = NotificationDecision.Allow;
            Close();
        };

        var ignore = new Button
        {
            Content = "Ignore",
            MinWidth = 90,
            Margin = new Thickness(8, 0, 0, 0),
            Style = (Style)owner.FindResource(typeof(Button)),
        };
        ignore.Click += (_, _) => Close();

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 14, 0, 0),
            Children = { allow, ignore },
        };

        var panel = new StackPanel { Margin = new Thickness(18) };
        panel.Children.Add(new TextBlock
        {
            Text = "Connection blocked",
            FontSize = 11,
            FontWeight = FontWeights.SemiBold,
            Foreground = Res("DangerBrush"),
        });
        panel.Children.Add(new TextBlock
        {
            Text = appName,
            FontSize = 16,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 4, 0, 0),
            TextTrimming = TextTrimming.CharacterEllipsis,
        });
        panel.Children.Add(new TextBlock
        {
            Text = attempt.Path,
            FontSize = 11,
            Margin = new Thickness(0, 2, 0, 0),
            Foreground = Res("TextDimBrush"),
            TextTrimming = TextTrimming.CharacterEllipsis,
            ToolTip = attempt.Path,
        });
        panel.Children.Add(new TextBlock
        {
            Text = $"Tried to reach {attempt.RemoteAddress}:{attempt.RemotePort} ({attempt.Protocol})",
            FontSize = 12,
            Margin = new Thickness(0, 10, 0, 0),
            Foreground = Res("TextDimBrush"),
            TextWrapping = TextWrapping.Wrap,
        });
        panel.Children.Add(buttons);

        Content = new Border
        {
            BorderBrush = Res("LineBrush"),
            BorderThickness = new Thickness(1),
            Child = panel,
        };

        Loaded += (_, _) =>
        {
            Reposition();
            _timer.Start();
        };
        SizeChanged += (_, _) => Reposition();
        _timer.Tick += (_, _) => Close();
        Closed += (_, _) => _timer.Stop();
    }

    public BlockedAttempt Attempt { get; }

    public NotificationDecision Decision { get; private set; } = NotificationDecision.Ignore;

    private void Reposition()
    {
        Rect area = SystemParameters.WorkArea;
        Left = area.Right - ActualWidth - 16;
        Top = area.Bottom - ActualHeight - 16;
    }
}

// ==========================================================================================
//  Running-process discovery
// ==========================================================================================

/// <summary>An executable that currently has at least one running process.</summary>
public sealed record RunningApp(string Name, string Path, int Instances);

/// <summary>Enumerates running processes (Process.GetProcesses) and folds them into distinct executables.</summary>
internal static class ProcessScanner
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    /// <summary>
    /// Returns one entry per distinct executable path, sorted by display name.
    /// Slow-ish (version-info lookups): call from a background thread.
    /// </summary>
    public static List<RunningApp> Scan()
    {
        var byPath = new Dictionary<string, (string Path, int Count)>(StringComparer.OrdinalIgnoreCase);

        foreach (Process process in Process.GetProcesses())
        {
            try
            {
                if (process.Id is 0 or 4)   // System Idle Process, System
                    continue;

                string? path = TryGetImagePath(process);
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                    continue;

                byPath[path] = byPath.TryGetValue(path, out var existing)
                    ? (existing.Path, existing.Count + 1)
                    : (path, 1);
            }
            catch (Exception)
            {
                // The process exited while we looked at it, or access was denied. Skip it.
            }
            finally
            {
                process.Dispose();
            }
        }

        return byPath.Values
            .Select(v => new RunningApp(GetDisplayName(v.Path), v.Path, v.Count))
            .OrderBy(a => a.Name, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    /// <summary>"Google Chrome" for chrome.exe; falls back to the file name.</summary>
    public static string GetDisplayName(string path)
    {
        try
        {
            FileVersionInfo info = FileVersionInfo.GetVersionInfo(path);
            string? name = !string.IsNullOrWhiteSpace(info.FileDescription) ? info.FileDescription : info.ProductName;
            if (!string.IsNullOrWhiteSpace(name))
                return name.Trim();
        }
        catch (Exception)
        {
            // Fall through to the file name.
        }

        return System.IO.Path.GetFileNameWithoutExtension(path);
    }

    /// <summary>True for anything under the Windows directory (System32, SysWOW64, WinSxS, ...).</summary>
    public static bool IsWindowsComponent(string path)
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrEmpty(windows))
            return false;

        return path.StartsWith(windows.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);
    }

    private static string? TryGetImagePath(Process process)
    {
        // QueryFullProcessImageName works for far more processes than Process.MainModule
        // (which fails for protected processes and needs module enumeration).
        IntPtr handle = OpenProcess(ProcessQueryLimitedInformation, false, process.Id);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var buffer = new StringBuilder(1024);
                uint size = (uint)buffer.Capacity;
                if (QueryFullProcessImageName(handle, 0, buffer, ref size))
                    return buffer.ToString(0, (int)size);
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        try
        {
            return process.MainModule?.FileName;
        }
        catch (Exception)
        {
            return null;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageName(IntPtr process, uint flags, StringBuilder exeName, ref uint size);
}

// ==========================================================================================
//  Persistence: allowed-application list and settings (%ProgramData%\SailHighSeaFireWall)
// ==========================================================================================

/// <summary>Where SailHighSea Firewall keeps its own data (machine-wide, so every elevated session sees the same rules).</summary>
internal static class AppPaths
{
    public static string DataDirectory { get; } =
        System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SailHighSeaFireWall");

    /// <summary>
    /// Exists while the app is listening for blocked connections. If it is still there at the next
    /// start, the previous run died while listening, and notifications are switched off.
    /// </summary>
    public static string WatcherMarker { get; } = System.IO.Path.Combine(DataDirectory, "watching.lock");
}

/// <summary>An application with an allow rule, remembered so the grid can show it again after a restart.</summary>
public sealed record StoredRule(string Name, string Path, Guid RuleKey);

/// <summary>
/// JSON file with the applications that have an allow rule. WFP itself only knows filter GUIDs
/// and display names, so this file is how the UI gets friendly names and rule keys back.
/// </summary>
public sealed class RuleStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string _file;
    private readonly List<StoredRule> _rules;

    public RuleStore()
    {
        Directory.CreateDirectory(AppPaths.DataDirectory);
        _file = System.IO.Path.Combine(AppPaths.DataDirectory, "allowed-apps.json");
        _rules = Load();
    }

    public IReadOnlyList<StoredRule> Rules => _rules;

    public void Upsert(StoredRule rule)
    {
        _rules.RemoveAll(r => string.Equals(r.Path, rule.Path, StringComparison.OrdinalIgnoreCase));
        _rules.Add(rule);
        Save();
    }

    public void Remove(string path)
    {
        if (_rules.RemoveAll(r => string.Equals(r.Path, path, StringComparison.OrdinalIgnoreCase)) > 0)
            Save();
    }

    private List<StoredRule> Load()
    {
        try
        {
            if (!File.Exists(_file))
                return new List<StoredRule>();

            using FileStream stream = File.OpenRead(_file);
            return JsonSerializer.Deserialize<List<StoredRule>>(stream, JsonOptions) ?? new List<StoredRule>();
        }
        catch (JsonException)
        {
            // Keep the unreadable file for inspection instead of silently overwriting it later.
            try { File.Move(_file, _file + ".bad", overwrite: true); } catch (IOException) { }
            return new List<StoredRule>();
        }
        catch (IOException)
        {
            return new List<StoredRule>();
        }
    }

    private void Save()
    {
        string temp = _file + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(_rules, JsonOptions));
        File.Move(temp, _file, overwrite: true);
    }
}

/// <summary>User preferences, stored next to the rule list.</summary>
public sealed class AppSettings
{
    private static string FilePath => System.IO.Path.Combine(AppPaths.DataDirectory, "settings.json");

    /// <summary>Re-scan running processes every few seconds.</summary>
    public bool AutoRefresh { get; set; }

    /// <summary>Keep programs under the Windows folder out of the list.</summary>
    public bool HideWindowsApps { get; set; }

    /// <summary>Offer to allow an application when it gets blocked.</summary>
    public bool Notifications { get; set; } = true;

    /// <summary>Keep DNS (remote port 53) open for every application while filters are on.</summary>
    public bool AllowDns { get; set; } = true;

    /// <summary>Whether rules created now survive a reboot (the choice made when filters were last enabled).</summary>
    public bool PermanentRules { get; set; } = true;

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch (Exception)
        {
            // A damaged settings file just means defaults.
        }

        return new AppSettings();
    }

    public void Save()
    {
        Directory.CreateDirectory(AppPaths.DataDirectory);
        File.WriteAllText(FilePath, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
    }
}

// ==========================================================================================
//  Dark native title bar
// ==========================================================================================

/// <summary>Asks Windows 10 (20H1+) / 11 to draw the native title bar in dark mode.</summary>
internal static class DarkTitleBar
{
    private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

    public static void Apply(Window window)
    {
        IntPtr hwnd = new WindowInteropHelper(window).Handle;
        if (hwnd == IntPtr.Zero)
            return;

        int enabled = 1;
        _ = DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, ref enabled, sizeof(int));
    }

    [DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attribute, ref int value, int size);
}
