using System.Text.RegularExpressions;

namespace NetQosManager;

/// <summary>
/// Creates a temporary (ActiveStore) throttle policy.
/// Tested on this PC (Windows 11 Home): ActiveStore silently drops IP address conditions (an address-only rule
/// throttles ALL upload), and the permanent store is saved but not enforced. So only application, protocol and
/// remote port are offered.
/// </summary>
internal enum ThrottleFocus { Auto, App, Port }

internal sealed class ThrottleDialog : Form
{
    private readonly ThrottleFocus _focus;
    private readonly TextBox _name = new() { Width = 300 };
    private readonly CheckBox _useApp = new() { Text = "Match application (exe name or full path)", AutoSize = true };
    private readonly TextBox _app = new() { Width = 300 };
    private readonly CheckBox _usePort = new() { Text = "Match remote port", AutoSize = true };
    private readonly TextBox _remotePort = new() { Width = 70 };
    private readonly ComboBox _proto = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 70 };
    private readonly NumericUpDown _rate = new() { Minimum = 0.1m, Maximum = 100000m, DecimalPlaces = 1, Increment = 10m, Value = 100m, Width = 90 };
    private readonly Label _scope = new() { AutoSize = true, MaximumSize = new Size(470, 0), Margin = new Padding(3, 8, 3, 3) };
    private readonly IReadOnlyCollection<string> _existingNames;
    private readonly TrafficRow? _row;

    public PolicyRequest? Result { get; private set; }

    public ThrottleDialog(TrafficRow? row, IReadOnlyCollection<string> existingNames, ThrottleFocus focus = ThrottleFocus.Auto)
    {
        _focus = focus;
        _row = row;
        _existingNames = existingNames;
        Text = "Throttle upload";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = new Font("Segoe UI", 9f);
        Padding = new Padding(10);

        _proto.Items.AddRange(new object[] { "TCP", "UDP", "Both" });
        _proto.SelectedIndex = 0;

        var grid = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));

        void Row(string label, Control c)
        {
            grid.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 7, 3, 3) });
            grid.Controls.Add(c);
        }
        void Span(Control c)
        {
            grid.Controls.Add(c);
            grid.SetColumnSpan(c, 2);
        }

        Row("Policy name:", _name);
        Span(_useApp);
        Row("    Application:", _app);
        Span(_usePort);
        var port = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
        port.Controls.Add(_remotePort);
        port.Controls.Add(new Label { Text = "Protocol:", AutoSize = true, Margin = new Padding(8, 7, 3, 3) });
        port.Controls.Add(_proto);
        Row("    Remote port:", port);
        var rate = new FlowLayoutPanel { AutoSize = true, WrapContents = false, Margin = Padding.Empty };
        rate.Controls.Add(_rate);
        rate.Controls.Add(new Label { Text = "Mbps", AutoSize = true, Margin = new Padding(4, 7, 3, 3) });
        Row("Upload limit:", rate);
        Span(_scope);

        var note = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(470, 0),
            ForeColor = SystemColors.GrayText,
            Margin = new Padding(3, 10, 3, 6),
            Text = "Upload (outbound) only. The limit lasts until you delete it or reboot.\n" +
                   "Windows on this PC can't limit by remote address: it silently ignores address conditions, " +
                   "so a port rule applies to that port on every device. Traffic sent by the System process " +
                   "(file sharing / SMB, e.g. NAS backups) can only be matched by port.",
        };
        Span(note);

        var ok = new Button { Text = "Create policy", AutoSize = true, DialogResult = DialogResult.None };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        ok.Click += (_, _) => Accept();
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Dock = DockStyle.Fill };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        Span(buttons);

        Controls.Add(grid);
        AcceptButton = ok;
        CancelButton = cancel;

        _useApp.CheckedChanged += (_, _) => { _app.Enabled = _useApp.Checked; UpdateScope(); };
        _usePort.CheckedChanged += (_, _) => { port.Enabled = _usePort.Checked; UpdateScope(); };
        _app.TextChanged += (_, _) => UpdateScope();
        _remotePort.TextChanged += (_, _) => UpdateScope();
        _proto.SelectedIndexChanged += (_, _) => UpdateScope();

        Prefill(row);
        _app.Enabled = _useApp.Checked;
        port.Enabled = _usePort.Checked;
        UpdateScope();
    }

    private void Prefill(TrafficRow? row)
    {
        if (row == null)
        {
            _name.Text = "Throttle";
            return;
        }

        if (row.RemotePort > 0)
        {
            _remotePort.Text = row.RemotePort.ToString();
            _proto.SelectedItem = row.Proto is "TCP" or "UDP" ? row.Proto : "Both";
        }

        bool kernelTraffic = row.Pid is 0 or 4;
        bool sharedHost = row.Process.Equals("svchost", StringComparison.OrdinalIgnoreCase);
        if (kernelTraffic)
        {
            _useApp.Enabled = false;
        }
        else
        {
            _app.Text = row.Process + ".exe";
        }

        bool byApp = _focus switch
        {
            ThrottleFocus.App => !kernelTraffic,
            ThrottleFocus.Port => false,
            _ => !kernelTraffic && !sharedHost,
        };
        _useApp.Checked = byApp;
        _usePort.Checked = !byApp && row.RemotePort > 0;

        string baseName = byApp ? $"Limit {row.Process}" : $"Limit port {row.RemotePort}";
        _name.Text = Sanitize(baseName);
    }

    /// <summary>Explains in plain words what the rule will actually throttle.</summary>
    private void UpdateScope()
    {
        string app = _useApp.Checked ? _app.Text.Trim() : "";
        string port = _usePort.Checked ? _remotePort.Text.Trim() : "";
        string proto = (string)_proto.SelectedItem!;
        string text;
        if (app.Length == 0 && port.Length == 0)
            text = "Choose an application and/or a remote port.";
        else if (app.Length > 0 && port.Length > 0)
            text = $"Will throttle: {app}'s {proto} uploads to port {port}, to any address.";
        else if (app.Length > 0)
            text = $"Will throttle: all uploads by {app}.";
        else
            text = $"Will throttle: every {proto} upload to port {port} from any program, to any address" +
                   (port == "445" ? " (all Windows file sharing / SMB)." : ".");
        if (_row?.RemoteIp != null && port.Length > 0)
            text += $"\nThe selected connection goes to {_row.RemoteIp}, but other devices on port {port} are included too.";
        _scope.Text = text;
    }

    private static string Sanitize(string s)
    {
        var cleaned = Regex.Replace(s, @"[^A-Za-z0-9 _.()\-]", "-");
        return cleaned.Length > 64 ? cleaned[..64] : cleaned;
    }

    private void Fail(string message, Control focus)
    {
        MessageBox.Show(this, message, "Throttle upload", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        focus.Focus();
    }

    private void Accept()
    {
        string name = _name.Text.Trim();
        if (!Regex.IsMatch(name, @"^[A-Za-z0-9 _.()\-]{1,64}$"))
        {
            Fail("Use 1-64 letters, digits, spaces or . _ - ( ) for the name.", _name);
            return;
        }
        // Windows lower-cases names in the temporary store, so compare case-insensitively.
        if (_existingNames.Contains(name, StringComparer.OrdinalIgnoreCase))
        {
            Fail($"A policy named \"{name}\" already exists.", _name);
            return;
        }

        string? app = null;
        if (_useApp.Checked)
        {
            app = _app.Text.Trim();
            if (app.Length == 0 || app.IndexOfAny(Path.GetInvalidPathChars()) >= 0)
            {
                Fail("Enter an exe name such as Overwatch.exe, or a full path.", _app);
                return;
            }
        }

        int port = 0;
        if (_usePort.Checked)
        {
            string portText = _remotePort.Text.Trim();
            if (!int.TryParse(portText, out port) || port < 1 || port > 65535)
            {
                Fail("The remote port must be a number from 1 to 65535.", _remotePort);
                return;
            }
        }

        // Never create a rule without a condition: Windows would throttle all upload traffic.
        if (app == null && port == 0)
        {
            Fail("Choose an application, a remote port, or both. A rule with neither would throttle all upload traffic.", _useApp);
            return;
        }

        string proto = port > 0 ? (string)_proto.SelectedItem! : "Any";
        ulong bps = (ulong)Math.Round(_rate.Value * 1_000_000m);
        Result = new PolicyRequest(name, app, null, port, proto, bps, Temporary: true);
        DialogResult = DialogResult.OK;
        Close();
    }
}
