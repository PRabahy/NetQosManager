using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;

namespace NetQosManager;

internal sealed class TrafficRow
{
    public string Key = "";
    public bool IsGroup;
    public int Pid;
    public string Process = "";
    public string Proto = "";
    public string Local = "";
    public string Remote = "";
    public IPAddress? LocalIp;
    public int LocalPort;
    public IPAddress? RemoteIp;
    public int RemotePort;
    public int Connections = 1;
    public string State = "";
    public double UpBytesPerSec;
    public double DownBytesPerSec;
    public long Sent;
    public long Recv;
    public long LastSeen;
}

internal static class Fmt
{
    public static string Rate(double bytesPerSec)
    {
        double bits = bytesPerSec * 8;
        if (bits < 1) return "";
        return Bits(bits);
    }

    public static string Bits(double bits)
    {
        if (bits >= 1e9) return $"{bits / 1e9:0.00} Gbps";
        if (bits >= 1e6) return $"{bits / 1e6:0.0} Mbps";
        if (bits >= 1e3) return $"{bits / 1e3:0.0} kbps";
        return $"{bits:0} bps";
    }

    public static string Bytes(long b)
    {
        if (b >= 1L << 30) return $"{b / (double)(1L << 30):0.00} GB";
        if (b >= 1L << 20) return $"{b / (double)(1L << 20):0.0} MB";
        if (b >= 1L << 10) return $"{b / 1024.0:0.0} KB";
        return b == 0 ? "" : $"{b} B";
    }

    public static string Endpoint(IPAddress a, int port) =>
        a.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{a}]:{port}" : $"{a}:{port}";

    /// <summary>Orders addresses numerically (IPv4 before IPv6), then by port. Nulls sort last.</summary>
    public static int CompareEndpoints(IPAddress? a, int aPort, IPAddress? b, int bPort)
    {
        if (a == null || b == null) return a == null ? (b == null ? 0 : 1) : -1;
        int c = a.AddressFamily.CompareTo(b.AddressFamily);
        if (c != 0) return c;
        c = a.GetAddressBytes().AsSpan().SequenceCompareTo(b.GetAddressBytes());
        return c != 0 ? c : aPort.CompareTo(bPort);
    }
}

/// <summary>Remembers which column a list is sorted by and shows ▲/▼ in that header.</summary>
internal sealed class SortState
{
    private readonly ListView _list;
    private readonly string[] _titles;
    private readonly HashSet<int> _descFirst;

    public int Column { get; private set; }
    public bool Descending { get; private set; }

    public SortState(ListView list, int column, bool descending, params int[] descendingFirstColumns)
    {
        _list = list;
        _titles = list.Columns.Cast<ColumnHeader>().Select(c => c.Text).ToArray();
        _descFirst = new HashSet<int>(descendingFirstColumns);
        Column = column;
        Descending = descending;
        UpdateHeaders();
    }

    /// <summary>Same column flips direction; a new column starts in its natural direction (numbers high-first).</summary>
    public void Click(int column)
    {
        if (column == Column) Descending = !Descending;
        else
        {
            Column = column;
            Descending = _descFirst.Contains(column);
        }
        UpdateHeaders();
    }

    public int Apply(int comparison) => Descending ? -comparison : comparison;

    private void UpdateHeaders()
    {
        for (int i = 0; i < _titles.Length; i++)
            _list.Columns[i].Text = i == Column ? _titles[i] + (Descending ? " ▼" : " ▲") : _titles[i];
    }
}

internal static class ProcessNames
{
    private static readonly Dictionary<int, string> Cache = new();
    private static long _clearedAt = Environment.TickCount64;

    public static string Get(int pid)
    {
        if (pid == 0) return "Idle / kernel";
        if (pid == 4) return "System";
        if (Environment.TickCount64 - _clearedAt > 60_000)
        {
            Cache.Clear();
            _clearedAt = Environment.TickCount64;
        }
        if (Cache.TryGetValue(pid, out var name)) return name;
        try
        {
            using var p = Process.GetProcessById(pid);
            name = p.ProcessName;
        }
        catch (ArgumentException)
        {
            name = $"(exited {pid})";
        }
        catch (InvalidOperationException)
        {
            name = $"(exited {pid})";
        }
        Cache[pid] = name;
        return name;
    }
}

internal static class Admin
{
    public static bool IsElevated
    {
        get
        {
            using var id = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    /// <summary>Relaunches elevated. Returns false if the user declined the UAC prompt.</summary>
    public static bool RestartElevated()
    {
        try
        {
            Process.Start(new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas" });
            return true;
        }
        catch (Win32Exception)
        {
            return false;
        }
    }
}

internal sealed class DoubleBufferedListView : ListView
{
    public DoubleBufferedListView()
    {
        DoubleBuffered = true;
        View = View.Details;
        FullRowSelect = true;
        HideSelection = false;
        Dock = DockStyle.Fill;
    }
}
