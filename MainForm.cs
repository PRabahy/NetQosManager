using System.Diagnostics;

namespace NetQosManager;

internal sealed class MainForm : Form
{
    private NetworkMonitor? _monitor;
    private readonly System.Windows.Forms.Timer _timer = new() { Interval = 1000 };

    private readonly ListView _traffic = new DoubleBufferedListView { MultiSelect = false };
    private readonly ListView _policies = new DoubleBufferedListView { MultiSelect = true, ShowItemToolTips = true };
    private readonly CheckBox _groupByProcess = new() { Text = "Group by process", AutoSize = true, Margin = new Padding(3, 7, 12, 3) };
    private readonly CheckBox _hideIdle = new() { Text = "Hide idle (10 s)", AutoSize = true, Checked = true, Margin = new Padding(3, 7, 12, 3) };
    private readonly Button _throttle = new() { Text = "Throttle selected…", AutoSize = true };
    private readonly Label _totals = new() { AutoSize = true, Margin = new Padding(16, 7, 3, 3) };
    private readonly Button _delete = new() { Text = "Delete selected", AutoSize = true };
    private readonly Button _deleteAll = new() { Text = "Delete all…", AutoSize = true };
    private readonly Button _refresh = new() { Text = "Refresh policies", AutoSize = true };
    private readonly Panel _banner = new() { Dock = DockStyle.Top, Height = 38, Visible = false };
    private readonly Label _bannerText = new() { Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft, Padding = new Padding(8, 0, 0, 0) };
    private readonly Button _bannerButton = new() { Text = "Restart as administrator", Dock = DockStyle.Right, Width = 190 };
    private readonly ToolStripStatusLabel _status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    private readonly SplitContainer _split = new() { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };

    private readonly Dictionary<ConnKey, (long Sent, long Recv)> _prev = new();
    private long _prevTick;
    private List<TrafficRow> _connRows = new();
    private List<QosPolicy> _policyList = new();
    private readonly Dictionary<string, double> _policyRates = new();
    private bool _busy;
    private bool _menuOpen;

    // Tree view state for "Group by process".
    private const int ImgCollapsed = 0, ImgExpanded = 1, ImgBlank = 2;
    private readonly HashSet<int> _expanded = new();

    // Column indexes.
    private const int TProcess = 0, TPid = 1, TProto = 2, TLocal = 3, TRemote = 4, TUp = 5, TDown = 6, TSent = 7, TRecv = 8;
    private const int PName = 0, PLifetime = 1, PMatch = 2, PLimit = 3, PCurrent = 4, POwner = 5;

    private readonly SortState _trafficSort;
    private readonly SortState _policySort;

    public MainForm()
    {
        Text = "Network QoS Manager";
        Width = 1250;
        Height = 800;
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);

        _traffic.SmallImageList = BuildTreeImages();
        _traffic.Columns.Add("Process", 190);
        _traffic.Columns.Add("PID", 60, HorizontalAlignment.Right);
        _traffic.Columns.Add("Proto", 55);
        _traffic.Columns.Add("Local", 200);
        _traffic.Columns.Add("Remote", 240);
        _traffic.Columns.Add("Upload", 100, HorizontalAlignment.Right);
        _traffic.Columns.Add("Download", 100, HorizontalAlignment.Right);
        _traffic.Columns.Add("Sent", 90, HorizontalAlignment.Right);
        _traffic.Columns.Add("Received", 90, HorizontalAlignment.Right);

        _policies.Columns.Add("Name", 200);
        _policies.Columns.Add("Lifetime", 150);
        _policies.Columns.Add("Matches", 360);
        _policies.Columns.Add("Upload limit", 100, HorizontalAlignment.Right);
        _policies.Columns.Add("Current upload", 110, HorizontalAlignment.Right);
        _policies.Columns.Add("Owner", 160);

        // Traffic starts "busiest first" (no column marked); numeric columns sort high-first on first click.
        _trafficSort = new SortState(_traffic, -1, true, TPid, TUp, TDown, TSent, TRecv);
        _policySort = new SortState(_policies, PName, false, PLimit, PCurrent);
        _policies.ListViewItemSorter = Comparer<ListViewItem>.Create(ComparePolicyItems);

        var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(6, 4, 6, 4), WrapContents = false };
        toolbar.Controls.AddRange(new Control[] { _groupByProcess, _hideIdle, _throttle, _totals });

        _split.Panel1.Controls.Add(_traffic);
        var policyButtons = new FlowLayoutPanel { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(2) };
        policyButtons.Controls.AddRange(new Control[] { _delete, _deleteAll, _refresh });
        var group = new GroupBox
        {
            Text = "QoS policies — Windows throttles upload (outbound) traffic only",
            Dock = DockStyle.Fill,
            Padding = new Padding(6),
        };
        group.Controls.Add(_policies);
        group.Controls.Add(policyButtons);
        _policies.BringToFront();
        _split.Panel2.Controls.Add(group);

        _banner.Controls.Add(_bannerText);
        _banner.Controls.Add(_bannerButton);
        _bannerText.BringToFront();

        var statusStrip = new StatusStrip();
        statusStrip.Items.Add(_status);

        Controls.Add(_split);
        Controls.Add(toolbar);
        Controls.Add(_banner);
        Controls.Add(statusStrip);
        _split.BringToFront();

        _traffic.ContextMenuStrip = BuildTrafficMenu();
        _policies.ContextMenuStrip = BuildPolicyMenu();

        _timer.Tick += (_, _) => OnTick();
        _throttle.Click += async (_, _) => await ThrottleAsync(SelectedTrafficRow(), ThrottleFocus.Auto);
        _traffic.DoubleClick += async (_, _) =>
        {
            var r = SelectedTrafficRow();
            if (r is { IsGroup: true }) ToggleGroup(r.Pid);
            else await ThrottleAsync(r, ThrottleFocus.Auto);
        };
        _traffic.MouseClick += (_, e) =>
        {
            if (e.Button != MouseButtons.Left) return;
            var hit = _traffic.HitTest(e.Location);
            if (hit.Item?.Tag is TrafficRow { IsGroup: true } g &&
                (hit.Location == ListViewHitTestLocations.Image || e.X - hit.Item.Bounds.Left < 22))
                ToggleGroup(g.Pid);
        };
        _traffic.KeyDown += OnTrafficKeyDown;
        _traffic.ColumnClick += (_, e) =>
        {
            _trafficSort.Click(e.Column);
            RenderTraffic();
        };
        _policies.ColumnClick += (_, e) =>
        {
            _policySort.Click(e.Column);
            _policies.Sort();
        };
        _policies.DoubleClick += async (_, _) => await ChangeLimitAsync();
        _delete.Click += async (_, _) => await DeleteSelectedAsync();
        _deleteAll.Click += async (_, _) => await DeleteAllAsync();
        _refresh.Click += async (_, _) => await RefreshPoliciesAsync();
        _groupByProcess.CheckedChanged += (_, _) => RenderTraffic();
        _hideIdle.CheckedChanged += (_, _) => RenderTraffic();
        _bannerButton.Click += (_, _) =>
        {
            if (Admin.RestartElevated()) Close();
        };

        Load += async (_, _) => await OnLoadAsync();
        FormClosed += (_, _) =>
        {
            _timer.Stop();
            _monitor?.Dispose();
        };
    }

    private async Task OnLoadAsync()
    {
        try { _split.SplitterDistance = (int)(_split.Height * 0.6); } catch (InvalidOperationException) { }

        if (!Admin.IsElevated)
        {
            ShowBanner("Not running as administrator. Measuring traffic and changing QoS policies both need admin rights.", true);
            _throttle.Enabled = _delete.Enabled = _deleteAll.Enabled = _refresh.Enabled = false;
            _status.Text = "Read-only: restart as administrator.";
            return;
        }

        try
        {
            _monitor = new NetworkMonitor();
            _monitor.Start();
            _timer.Start();
            _status.Text = "Measuring network traffic…";
        }
        catch (Exception ex)
        {
            _monitor?.Dispose();
            _monitor = null;
            ShowBanner("Traffic measurement could not start: " + ex.Message, false);
        }

        await RefreshPoliciesAsync();
    }

    private void ShowBanner(string text, bool offerRestart)
    {
        _bannerText.Text = text;
        _banner.BackColor = offerRestart ? Color.FromArgb(255, 244, 206) : Color.FromArgb(253, 222, 222);
        _bannerButton.Visible = offerRestart;
        _banner.Visible = true;
    }

    // ---------------------------------------------------------------- traffic

    private TrafficRow? SelectedTrafficRow() =>
        _traffic.SelectedItems.Count > 0 ? _traffic.SelectedItems[0].Tag as TrafficRow : null;

    private void OnTick()
    {
        if (_monitor == null) return;
        if (_monitor.ConsumerExited)
        {
            _timer.Stop();
            ShowBanner($"Traffic measurement stopped unexpectedly (ProcessTrace status {_monitor.ProcessTraceStatus}).", false);
            return;
        }

        long now = Environment.TickCount64;
        double secs = _prevTick == 0 ? 1.0 : Math.Max(0.2, (now - _prevTick) / 1000.0);
        _prevTick = now;
        _monitor.DetectPortOrder();

        var snap = _monitor.Snapshot();
        var rows = new List<TrafficRow>(snap.Count);
        var seen = new Dictionary<ConnKey, (long, long)>(snap.Count);
        foreach (var s in snap)
        {
            _prev.TryGetValue(s.Key, out var p);
            seen[s.Key] = (s.Sent, s.Recv);
            var k = s.Key;
            var localIp = k.LocalAddress;
            var remoteIp = k.RemoteAddress;
            int localPort = _monitor.Port(k.LPortRaw);
            int remotePort = _monitor.Port(k.RPortRaw);
            string proto = k.Proto == 6 ? "TCP" : "UDP";
            string local = Fmt.Endpoint(localIp, localPort);
            string remote = Fmt.Endpoint(remoteIp, remotePort);
            rows.Add(new TrafficRow
            {
                Key = $"{k.Pid}|{proto}|{local}|{remote}",
                Pid = k.Pid,
                Process = ProcessNames.Get(k.Pid),
                Proto = proto,
                Local = local,
                Remote = remote,
                LocalIp = localIp,
                LocalPort = localPort,
                RemoteIp = remoteIp,
                RemotePort = remotePort,
                UpBytesPerSec = Math.Max(0, (s.Sent - p.Sent) / secs),
                DownBytesPerSec = Math.Max(0, (s.Recv - p.Recv) / secs),
                Sent = s.Sent,
                Recv = s.Recv,
                LastSeen = s.LastSeen,
            });
        }
        _prev.Clear();
        foreach (var kv in seen) _prev[kv.Key] = kv.Value;
        _monitor.Prune(120_000);

        _connRows = rows;
        _totals.Text = $"Total  ↑ {Fmt.Rate(rows.Sum(r => r.UpBytesPerSec)),-12}  ↓ {Fmt.Rate(rows.Sum(r => r.DownBytesPerSec))}";
        if (!_menuOpen) RenderTraffic(); // don't reshuffle rows under an open right-click menu
        UpdatePolicyRates();
    }

    private static int ByActivity(TrafficRow a, TrafficRow b)
    {
        int c = (b.UpBytesPerSec + b.DownBytesPerSec).CompareTo(a.UpBytesPerSec + a.DownBytesPerSec);
        return c != 0 ? c : (b.Sent + b.Recv).CompareTo(a.Sent + a.Recv);
    }

    private int CompareTraffic(TrafficRow a, TrafficRow b)
    {
        int c = _trafficSort.Column switch
        {
            TProcess => string.Compare(a.Process, b.Process, StringComparison.OrdinalIgnoreCase),
            TPid => a.Pid.CompareTo(b.Pid),
            TProto => string.CompareOrdinal(a.Proto, b.Proto),
            TLocal => a.IsGroup || b.IsGroup
                ? a.Connections.CompareTo(b.Connections)
                : Fmt.CompareEndpoints(a.LocalIp, a.LocalPort, b.LocalIp, b.LocalPort),
            TRemote => Fmt.CompareEndpoints(a.RemoteIp, a.RemotePort, b.RemoteIp, b.RemotePort),
            TUp => a.UpBytesPerSec.CompareTo(b.UpBytesPerSec),
            TDown => a.DownBytesPerSec.CompareTo(b.DownBytesPerSec),
            TSent => a.Sent.CompareTo(b.Sent),
            TRecv => a.Recv.CompareTo(b.Recv),
            _ => 0,
        };
        if (_trafficSort.Column >= 0) c = _trafficSort.Apply(c);
        if (c == 0) c = ByActivity(a, b);
        return c != 0 ? c : string.CompareOrdinal(a.Key, b.Key); // stable order, no jitter between refreshes
    }

    private static ListViewItem MakeItem(TrafficRow r, int image, int indent, bool showProcess) =>
        new(new[]
        {
            showProcess ? r.Process : "", showProcess ? r.Pid.ToString() : "", r.Proto, r.Local, r.Remote,
            Fmt.Rate(r.UpBytesPerSec), Fmt.Rate(r.DownBytesPerSec), Fmt.Bytes(r.Sent), Fmt.Bytes(r.Recv),
        }, image)
        { Name = r.Key, Tag = r, IndentCount = indent };

    private void ToggleGroup(int pid)
    {
        if (!_expanded.Remove(pid)) _expanded.Add(pid);
        RenderTraffic();
    }

    private void SetAllExpanded(bool expand)
    {
        _expanded.Clear();
        if (expand) foreach (var pid in _connRows.Select(r => r.Pid).Distinct()) _expanded.Add(pid);
        RenderTraffic();
    }

    private void RenderTraffic()
    {
        long now = Environment.TickCount64;
        IEnumerable<TrafficRow> conns = _connRows;
        if (_hideIdle.Checked) conns = conns.Where(r => now - r.LastSeen <= 10_000);
        var connList = conns.ToList();
        connList.Sort(CompareTraffic);

        var items = new List<ListViewItem>(connList.Count);
        if (_groupByProcess.Checked)
        {
            // Tree: one row per process, its connections indented underneath when expanded.
            var parents = GroupByProcess(connList).ToList();
            parents.Sort(CompareTraffic);
            var byPid = connList.ToLookup(r => r.Pid);
            foreach (var p in parents)
            {
                bool open = _expanded.Contains(p.Pid);
                items.Add(MakeItem(p, open ? ImgExpanded : ImgCollapsed, 0, true));
                if (open)
                    foreach (var c in byPid[p.Pid])
                        items.Add(MakeItem(c, ImgBlank, 1, false));
            }
        }
        else
        {
            foreach (var r in connList) items.Add(MakeItem(r, ImgBlank, 0, true));
        }

        string? selected = _traffic.SelectedItems.Count > 0 ? _traffic.SelectedItems[0].Name : null;
        string? top = _traffic.TopItem?.Name;

        _traffic.BeginUpdate();
        _traffic.Items.Clear();
        _traffic.Items.AddRange(items.ToArray());
        if (selected != null && _traffic.Items.ContainsKey(selected))
        {
            var it = _traffic.Items[selected]!;
            it.Selected = true;
            it.Focused = true;
        }
        if (top != null && _traffic.Items.ContainsKey(top))
        {
            try { _traffic.TopItem = _traffic.Items[top]; } catch (InvalidOperationException) { }
        }
        _traffic.EndUpdate();
    }

    private static IEnumerable<TrafficRow> GroupByProcess(IEnumerable<TrafficRow> rows) =>
        rows.GroupBy(r => r.Pid).Select(g =>
        {
            var remotes = g.Select(r => r.RemoteIp).Distinct().ToList();
            var ports = g.Select(r => (r.Proto, r.RemotePort)).Distinct().ToList();
            var first = g.First();
            int n = g.Count();
            return new TrafficRow
            {
                Key = "P|" + g.Key,
                IsGroup = true,
                Pid = g.Key,
                Process = first.Process,
                Proto = string.Join("/", g.Select(r => r.Proto).Distinct().OrderBy(x => x)),
                Local = $"{n} connection{(n == 1 ? "" : "s")}",
                Connections = n,
                Remote = remotes.Count == 1 ? first.Remote : $"{remotes.Count} remote addresses",
                RemoteIp = remotes.Count == 1 ? first.RemoteIp : null,
                RemotePort = ports.Count == 1 ? first.RemotePort : 0,
                UpBytesPerSec = g.Sum(r => r.UpBytesPerSec),
                DownBytesPerSec = g.Sum(r => r.DownBytesPerSec),
                Sent = g.Sum(r => r.Sent),
                Recv = g.Sum(r => r.Recv),
                LastSeen = g.Max(r => r.LastSeen),
            };
        });

    private void OnTrafficKeyDown(object? sender, KeyEventArgs e)
    {
        if (SelectedTrafficRow() is not TrafficRow r) return;
        if (r.IsGroup && e.KeyCode == Keys.Right && !_expanded.Contains(r.Pid)) { ToggleGroup(r.Pid); e.Handled = true; }
        else if (r.IsGroup && e.KeyCode == Keys.Left && _expanded.Contains(r.Pid)) { ToggleGroup(r.Pid); e.Handled = true; }
        else if (!r.IsGroup && e.KeyCode == Keys.Left && _groupByProcess.Checked)
        {
            // Jump from a connection up to its process row.
            var parent = _traffic.Items["P|" + r.Pid];
            if (parent != null)
            {
                _traffic.SelectedItems.Clear();
                parent.Selected = parent.Focused = true;
                parent.EnsureVisible();
                e.Handled = true;
            }
        }
        else if (e.Control && e.KeyCode == Keys.C)
        {
            CopyToClipboard(RowText(_traffic.SelectedItems[0]));
            e.Handled = true;
        }
    }

    private ContextMenuStrip BuildTrafficMenu()
    {
        var menu = new ContextMenuStrip();
        var throttleApp = new ToolStripMenuItem("Throttle this application…");
        var throttlePort = new ToolStripMenuItem("Throttle this port…");
        var expand = new ToolStripMenuItem("Expand");
        var expandAll = new ToolStripMenuItem("Expand all");
        var collapseAll = new ToolStripMenuItem("Collapse all");
        var copyRow = new ToolStripMenuItem("Copy row") { ShortcutKeyDisplayString = "Ctrl+C" };
        var copyRemote = new ToolStripMenuItem("Copy remote address");
        var copyProcess = new ToolStripMenuItem("Copy process name");
        var openLocation = new ToolStripMenuItem("Open file location");
        var sepTree = new ToolStripSeparator();

        menu.Items.AddRange(new ToolStripItem[]
        {
            throttleApp, throttlePort, sepTree, expand, expandAll, collapseAll,
            new ToolStripSeparator(), copyRow, copyRemote, copyProcess,
            new ToolStripSeparator(), openLocation,
        });

        TrafficRow? row = null;
        menu.Opening += (_, e) =>
        {
            row = SelectedTrafficRow();
            if (row == null)
            {
                e.Cancel = true;
                return;
            }
            _menuOpen = true;
            bool admin = Admin.IsElevated && !_busy;
            bool kernel = row.Pid is 0 or 4;
            bool grouped = _groupByProcess.Checked;

            throttleApp.Text = kernel ? "Throttle this application… (not possible for System traffic)" : $"Throttle {row.Process}.exe…";
            throttleApp.Enabled = admin && !kernel;
            throttlePort.Text = row.RemotePort > 0 ? $"Throttle all {row.Proto} uploads to port {row.RemotePort}…" : "Throttle this port… (several ports)";
            throttlePort.Enabled = admin && row.RemotePort > 0 && row.Proto is "TCP" or "UDP";

            sepTree.Visible = expand.Visible = expandAll.Visible = collapseAll.Visible = grouped;
            expand.Visible = grouped && row.IsGroup;
            expand.Text = _expanded.Contains(row.Pid) ? "Collapse" : "Expand";

            copyRemote.Enabled = row.RemoteIp != null;
            openLocation.Enabled = !kernel;
        };
        menu.Closed += (_, _) => _menuOpen = false;

        throttleApp.Click += async (_, _) => await ThrottleAsync(row, ThrottleFocus.App);
        throttlePort.Click += async (_, _) => await ThrottleAsync(row, ThrottleFocus.Port);
        expand.Click += (_, _) => { if (row != null) ToggleGroup(row.Pid); };
        expandAll.Click += (_, _) => SetAllExpanded(true);
        collapseAll.Click += (_, _) => SetAllExpanded(false);
        copyRow.Click += (_, _) => { if (_traffic.SelectedItems.Count > 0) CopyToClipboard(RowText(_traffic.SelectedItems[0])); };
        copyRemote.Click += (_, _) => { if (row?.RemoteIp != null) CopyToClipboard(row.RemotePort > 0 ? row.Remote : row.RemoteIp.ToString()); };
        copyProcess.Click += (_, _) => { if (row != null) CopyToClipboard(row.Process); };
        openLocation.Click += (_, _) => { if (row != null) OpenFileLocation(row.Pid); };
        return menu;
    }

    private static string RowText(ListViewItem item) =>
        string.Join("\t", item.SubItems.Cast<ListViewItem.ListViewSubItem>().Select(s => s.Text));

    private void CopyToClipboard(string text)
    {
        try
        {
            Clipboard.SetText(text);
            _status.Text = "Copied to clipboard.";
        }
        catch (Exception ex)
        {
            _status.Text = "Couldn't copy: " + ex.Message;
        }
    }

    private void OpenFileLocation(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            string? path = p.MainModule?.FileName;
            if (string.IsNullOrEmpty(path)) throw new InvalidOperationException("path unavailable");
            Process.Start("explorer.exe", $"/select,\"{path}\"");
        }
        catch (Exception ex)
        {
            _status.Text = "Couldn't find the program's file: " + ex.Message;
        }
    }

    // ---------------------------------------------------------------- policies

    private int ComparePolicyItems(ListViewItem? x, ListViewItem? y)
    {
        if (x?.Tag is not QosPolicy a || y?.Tag is not QosPolicy b) return 0;
        int c = _policySort.Column switch
        {
            PName => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase),
            PLifetime => string.Compare(a.Lifetime, b.Lifetime, StringComparison.OrdinalIgnoreCase),
            PMatch => string.Compare(a.Match, b.Match, StringComparison.OrdinalIgnoreCase),
            PLimit => a.ThrottleBps.CompareTo(b.ThrottleBps),
            PCurrent => _policyRates.GetValueOrDefault(a.Name).CompareTo(_policyRates.GetValueOrDefault(b.Name)),
            POwner => string.Compare(a.Owner, b.Owner, StringComparison.OrdinalIgnoreCase),
            _ => 0,
        };
        c = _policySort.Apply(c);
        return c != 0 ? c : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
    }

    private List<QosPolicy> SelectedPolicies() =>
        _policies.SelectedItems.Cast<ListViewItem>().Select(i => (QosPolicy)i.Tag!).ToList();

    private ContextMenuStrip BuildPolicyMenu()
    {
        var menu = new ContextMenuStrip();
        var change = new ToolStripMenuItem("Change limit…");
        var delete = new ToolStripMenuItem("Delete") { ShortcutKeyDisplayString = "Del" };
        var deleteAll = new ToolStripMenuItem("Delete all…");
        var copyPs = new ToolStripMenuItem("Copy as PowerShell command");
        var refresh = new ToolStripMenuItem("Refresh");
        menu.Items.AddRange(new ToolStripItem[] { change, delete, deleteAll, new ToolStripSeparator(), copyPs, refresh });

        menu.Opening += (_, _) =>
        {
            var sel = SelectedPolicies();
            bool admin = Admin.IsElevated && !_busy;
            change.Enabled = admin && sel.Count == 1 && sel[0].Removable;
            delete.Enabled = admin && sel.Any(p => p.Removable);
            delete.Text = sel.Count > 1 ? $"Delete {sel.Count} policies" : "Delete";
            deleteAll.Enabled = admin && _policyList.Any(p => p.Removable);
            copyPs.Enabled = sel.Count > 0;
            copyPs.Text = sel.Count > 1 ? $"Copy {sel.Count} as PowerShell commands" : "Copy as PowerShell command";
            refresh.Enabled = admin;
        };

        change.Click += async (_, _) => await ChangeLimitAsync();
        delete.Click += async (_, _) => await DeleteSelectedAsync();
        deleteAll.Click += async (_, _) => await DeleteAllAsync();
        copyPs.Click += (_, _) => CopyToClipboard(string.Join(Environment.NewLine, SelectedPolicies().Select(QosService.ToPowerShell)));
        refresh.Click += async (_, _) => await RefreshPoliciesAsync();

        _policies.KeyDown += async (_, e) =>
        {
            if (e.KeyCode == Keys.Delete) { e.Handled = true; await DeleteSelectedAsync(); }
            else if (e.Control && e.KeyCode == Keys.C && _policies.SelectedItems.Count > 0)
            {
                e.Handled = true;
                CopyToClipboard(string.Join(Environment.NewLine, SelectedPolicies().Select(QosService.ToPowerShell)));
            }
        };
        return menu;
    }

    private void SetBusy(bool busy, string? message = null)
    {
        _busy = busy;
        bool enable = !busy && Admin.IsElevated;
        _throttle.Enabled = _delete.Enabled = _deleteAll.Enabled = _refresh.Enabled = enable;
        UseWaitCursor = busy;
        if (message != null) _status.Text = message;
    }

    private async Task RefreshPoliciesAsync(string? afterMessage = null)
    {
        if (_busy) return;
        SetBusy(true, "Reading QoS policies…");
        try
        {
            var result = await QosService.ListAsync();
            _policyList = result.Policies;
            FillPolicies();
            string summary = $"{_policyList.Count} QoS polic{(_policyList.Count == 1 ? "y" : "ies")}";
            if (result.Errors.Count > 0) summary += " — errors: " + string.Join(" | ", result.Errors);
            _status.Text = afterMessage != null ? afterMessage + "   (" + summary + ")" : summary;
        }
        catch (Exception ex)
        {
            _status.Text = "Could not read QoS policies: " + ex.Message;
        }
        finally
        {
            SetBusy(false);
        }
    }

    private void FillPolicies()
    {
        var selected = new HashSet<string>(SelectedPolicies().Select(p => p.Name));
        _policies.BeginUpdate();
        _policies.Items.Clear();
        foreach (var p in _policyList)
        {
            var item = new ListViewItem(new[] { p.Name, p.Lifetime, p.Match, p.LimitText, p.Evaluable ? "" : "n/a", p.Owner })
            {
                Name = p.Name,
                Tag = p,
                Selected = selected.Contains(p.Name),
                ForeColor = !p.Removable ? SystemColors.GrayText
                    : p.IsCatchAll && p.ThrottleBps > 0 && !p.Lifetime.Contains("not active") ? Color.Firebrick
                    : SystemColors.WindowText,
                ToolTipText = p.IsCatchAll ? "No application or port condition: this limits all upload traffic on the PC." : "",
            };
            _policies.Items.Add(item);
        }
        _policies.EndUpdate();
        UpdatePolicyRates();
    }

    private void UpdatePolicyRates()
    {
        foreach (ListViewItem item in _policies.Items)
        {
            if (item.Tag is not QosPolicy p || !p.Evaluable) continue;
            double up = _connRows.Where(p.Matches).Sum(r => r.UpBytesPerSec);
            _policyRates[p.Name] = up;
            string text = _monitor == null ? "" : up > 0 ? Fmt.Rate(up) : "idle";
            if (item.SubItems[PCurrent].Text != text) item.SubItems[PCurrent].Text = text;
        }
        if (_policySort.Column == PCurrent && !_menuOpen) _policies.Sort();
    }

    private async Task ThrottleAsync(TrafficRow? row, ThrottleFocus focus)
    {
        if (_busy || !Admin.IsElevated) return;

        using var dlg = new ThrottleDialog(row, _policyList.Select(p => p.Name).ToList(), focus);
        if (dlg.ShowDialog(this) != DialogResult.OK || dlg.Result == null) return;

        SetBusy(true, $"Creating policy \"{dlg.Result.Name}\"…");
        (bool ok, string error) result;
        try
        {
            result = await QosService.CreateAsync(dlg.Result);
        }
        catch (Exception ex)
        {
            result = (false, ex.Message);
        }
        SetBusy(false);

        if (!result.ok)
        {
            MessageBox.Show(this, "Windows did not create the policy:\n\n" + result.error, "Throttle upload",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            await RefreshPoliciesAsync();
            return;
        }
        await RefreshPoliciesAsync($"Created \"{dlg.Result.Name}\" ({Fmt.Bits(dlg.Result.BitsPerSecond)}).");
    }

    private async Task ChangeLimitAsync()
    {
        if (_busy || !Admin.IsElevated) return;
        var sel = SelectedPolicies();
        if (sel.Count != 1 || !sel[0].Removable) return;
        var policy = sel[0];

        using var dlg = new LimitDialog(policy);
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        SetBusy(true, $"Changing \"{policy.Name}\"…");
        (bool ok, string error) result;
        try
        {
            result = await QosService.SetLimitAsync(policy, dlg.BitsPerSecond);
        }
        catch (Exception ex)
        {
            result = (false, ex.Message);
        }
        SetBusy(false);

        if (!result.ok)
            MessageBox.Show(this, "Windows did not change the policy:\n\n" + result.error, "Change upload limit",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        await RefreshPoliciesAsync(result.ok ? $"\"{policy.Name}\" now limited to {Fmt.Bits(dlg.BitsPerSecond)}." : null);
    }

    private async Task DeleteSelectedAsync()
    {
        if (_busy || !Admin.IsElevated) return;
        var selected = SelectedPolicies();
        if (selected.Count == 0)
        {
            _status.Text = "Select one or more policies to delete.";
            return;
        }
        var removable = selected.Where(p => p.Removable).Select(p => p.Name).Distinct().ToList();
        if (removable.Count == 0)
        {
            MessageBox.Show(this, "Those policies come from Group Policy and can't be deleted here.", "Delete policies",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        await DeleteAsync(removable);
    }

    private async Task DeleteAllAsync()
    {
        if (_busy || !Admin.IsElevated) return;
        var removable = _policyList.Where(p => p.Removable).Select(p => p.Name).Distinct().ToList();
        if (removable.Count == 0)
        {
            _status.Text = "There are no policies this app can delete.";
            return;
        }
        await DeleteAsync(removable);
    }

    private async Task DeleteAsync(List<string> names)
    {
        bool anyGpo = _policyList.Any(p => !p.Removable);
        string text = $"Delete {names.Count} QoS polic{(names.Count == 1 ? "y" : "ies")}?\n\n" +
                      string.Join("\n", names.Take(15).Select(n => "  • " + n)) +
                      (names.Count > 15 ? $"\n  … and {names.Count - 15} more" : "") +
                      (anyGpo ? "\n\nGroup Policy entries are skipped." : "");
        if (MessageBox.Show(this, text, "Delete policies", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return;

        SetBusy(true, "Deleting…");
        List<string> messages;
        try
        {
            messages = await QosService.DeleteAsync(names);
        }
        catch (Exception ex)
        {
            messages = new List<string> { ex.Message };
        }
        SetBusy(false);
        await RefreshPoliciesAsync(messages.Count > 0 ? string.Join("; ", messages) : "Nothing was removed.");
    }

    // ---------------------------------------------------------------- images

    private static ImageList BuildTreeImages()
    {
        var list = new ImageList { ImageSize = new Size(16, 16), ColorDepth = ColorDepth.Depth32Bit };
        list.Images.Add(Arrow(expanded: false));
        list.Images.Add(Arrow(expanded: true));
        list.Images.Add(new Bitmap(16, 16));
        return list;
    }

    private static Bitmap Arrow(bool expanded)
    {
        var bmp = new Bitmap(16, 16);
        using var g = Graphics.FromImage(bmp);
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using var brush = new SolidBrush(Color.FromArgb(96, 96, 96));
        Point[] pts = expanded
            ? new[] { new Point(4, 6), new Point(12, 6), new Point(8, 11) }
            : new[] { new Point(6, 4), new Point(11, 8), new Point(6, 12) };
        g.FillPolygon(brush, pts);
        return bmp;
    }
}
