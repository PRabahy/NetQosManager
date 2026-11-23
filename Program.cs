using System.Net.NetworkInformation;
using System.Text;

namespace NetQosManager;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        int i = Array.FindIndex(args, a => a.Equals("--selftest", StringComparison.OrdinalIgnoreCase));
        if (i >= 0)
        {
            string path = i + 1 < args.Length ? args[i + 1] : Path.Combine(AppContext.BaseDirectory, "selftest-report.txt");
            return SelfTest.Run(path);
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
        return 0;
    }
}

/// <summary>
/// Headless, read-only check: measures traffic for a few seconds and lists QoS policies, then writes a report.
/// Run elevated:  NetQosManager.exe --selftest [report-path]
/// </summary>
internal static class SelfTest
{
    public static int Run(string path)
    {
        var sb = new StringBuilder();
        void L(string s) => sb.AppendLine(s);

        L($"NetQosManager self-test {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        L($"Elevated: {Admin.IsElevated}; 64-bit: {Environment.Is64BitProcess}; OS: {Environment.OSVersion.VersionString}");
        L("Struct layout: " + EtwLayout.Describe());
        L("");

        try
        {
            var table = ConnectionTable.Read();
            L($"Connection table (no admin needed): {table.Count} entries — " +
              string.Join(", ", table.GroupBy(t => t.Proto + " " + (t.LocalIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "v6" : "v4"))
                  .Select(g => $"{g.Key}: {g.Count()}")));
            foreach (var t in table.Where(t => t.State == "Established").OrderBy(t => t.Pid).Take(15))
                L($"  {ProcessNames.Get(t.Pid),-22} pid {t.Pid,-6} {t.Proto} {Fmt.Endpoint(t.LocalIp, t.LocalPort),-26} -> {Fmt.Endpoint(t.RemoteIp!, t.RemotePort),-30} {t.State}");
            var adapters = new AdapterCounter();
            adapters.Sample();
            Thread.Sleep(2000);
            var (up, down) = adapters.Sample();
            L($"Adapter totals over 2 s: up {Fmt.Rate(up)}, down {Fmt.Rate(down)}");
        }
        catch (Exception ex)
        {
            L("CONNECTION TABLE ERROR: " + ex);
        }
        L("");

        try
        {
            using var mon = new NetworkMonitor();
            mon.Start();
            L("ETW session started.");
            long t0 = Environment.TickCount64;
            Thread.Sleep(6000);
            mon.DetectPortOrder();
            var snap = mon.Snapshot();
            double secs = (Environment.TickCount64 - t0) / 1000.0;
            L($"Captured {secs:0.0} s. Consumer running: {!mon.ConsumerExited} (status {mon.ProcessTraceStatus}).");
            L("Port byte order: " + mon.PortOrderDescription);
            L("Event counts by ID: " + mon.EventCountsDescription());
            L($"Connections seen: {snap.Count}");
            foreach (var s in snap.OrderByDescending(s => s.Sent + s.Recv).Take(25))
            {
                var k = s.Key;
                L($"  {ProcessNames.Get(k.Pid),-22} pid {k.Pid,-6} {(k.Proto == 6 ? "TCP" : "UDP")} " +
                  $"{Fmt.Endpoint(k.LocalAddress, mon.Port(k.LPortRaw)),-26} -> {Fmt.Endpoint(k.RemoteAddress, mon.Port(k.RPortRaw)),-44} " +
                  $"up {Fmt.Rate(s.Sent / secs),-11} down {Fmt.Rate(s.Recv / secs)}");
            }
            L("Windows TCP table (established, first 15) for comparison:");
            foreach (var c in IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                         .Where(c => c.State == TcpState.Established).Take(15))
                L($"  {c.LocalEndPoint} -> {c.RemoteEndPoint}");
        }
        catch (Exception ex)
        {
            L("CAPTURE ERROR: " + ex);
        }

        L("");
        try
        {
            var r = QosService.ListAsync().GetAwaiter().GetResult();
            L($"QoS policies: {r.Policies.Count}");
            foreach (var p in r.Policies)
                L($"  {p.Name} | {p.Lifetime} | owner '{p.Owner}' | {p.Match} | limit {p.LimitText} ({p.ThrottleBps} bps raw) | live-rate check: {p.Evaluable}");
            foreach (var e in r.Errors) L("  ERROR: " + e);
            L("Raw stdout: " + r.Raw);
            if (r.Stderr.Length > 0) L("Raw stderr: " + r.Stderr);
        }
        catch (Exception ex)
        {
            L("POLICY ERROR: " + ex);
        }

        try
        {
            File.WriteAllText(path, sb.ToString());
        }
        catch
        {
            File.WriteAllText(Path.Combine(Path.GetTempPath(), "NetQosManager-selftest.txt"), sb.ToString());
        }
        return 0;
    }
}
