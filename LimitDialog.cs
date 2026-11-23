namespace NetQosManager;

/// <summary>Asks for a new upload limit in Mbps for an existing policy.</summary>
internal sealed class LimitDialog : Form
{
    private readonly NumericUpDown _rate = new() { Minimum = 0.1m, Maximum = 100000m, DecimalPlaces = 1, Increment = 10m, Width = 100 };

    public ulong BitsPerSecond => (ulong)Math.Round(_rate.Value * 1_000_000m);

    public LimitDialog(QosPolicy policy)
    {
        Text = "Change upload limit";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Font = new Font("Segoe UI", 9f);
        Padding = new Padding(10);

        decimal current = policy.ThrottleBps > 0 ? policy.ThrottleBps / 1_000_000m : 100m;
        _rate.Value = Math.Clamp(Math.Round(current, 1), _rate.Minimum, _rate.Maximum);

        var layout = new FlowLayoutPanel { FlowDirection = FlowDirection.TopDown, AutoSize = true, WrapContents = false };
        layout.Controls.Add(new Label { Text = $"Policy: {policy.Name}", AutoSize = true });
        layout.Controls.Add(new Label { Text = policy.Match, AutoSize = true, ForeColor = SystemColors.GrayText, Margin = new Padding(3, 0, 3, 8) });
        var row = new FlowLayoutPanel { AutoSize = true, WrapContents = false };
        row.Controls.Add(new Label { Text = "New limit:", AutoSize = true, Margin = new Padding(3, 7, 3, 3) });
        row.Controls.Add(_rate);
        row.Controls.Add(new Label { Text = "Mbps", AutoSize = true, Margin = new Padding(3, 7, 3, 3) });
        layout.Controls.Add(row);

        var ok = new Button { Text = "Apply", AutoSize = true, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "Cancel", AutoSize = true, DialogResult = DialogResult.Cancel };
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.RightToLeft, Anchor = AnchorStyles.Right };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        layout.Controls.Add(buttons);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
    }
}
