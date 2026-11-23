using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace NetQosManager;

internal sealed record TableEntry(int Pid, string Proto, IPAddress LocalIp, int LocalPort, IPAddress? RemoteIp, int RemotePort, string State);

/// <summary>
/// Reads the TCP/UDP connection tables with owning process IDs (GetExtendedTcpTable / GetExtendedUdpTable).
/// Works without administrator rights, but has no byte counts.
/// </summary>
internal static unsafe class ConnectionTable
{
    private const int AF_INET = 2, AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;
    private const uint ERROR_INSUFFICIENT_BUFFER = 122;

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedUdpTable(IntPtr table, ref int size, bool order, int af, int tableClass, uint reserved);

    private static readonly string[] TcpStates =
    {
        "", "Closed", "Listening", "SYN sent", "SYN received", "Established", "FIN wait 1", "FIN wait 2",
        "Close wait", "Closing", "Last ACK", "Time wait", "Delete TCB",
    };

    public static List<TableEntry> Read()
    {
        var list = new List<TableEntry>();
        Fill(true, AF_INET, list);
        Fill(true, AF_INET6, list);
        Fill(false, AF_INET, list);
        Fill(false, AF_INET6, list);
        return list;
    }

    private static int Port(uint raw) => (int)(((raw & 0xFF) << 8) | ((raw >> 8) & 0xFF));

    private static IPAddress V4(uint addr) => new(BitConverter.GetBytes(addr));

    private static IPAddress V6(byte* p, uint scope)
    {
        var bytes = new ReadOnlySpan<byte>(p, 16).ToArray();
        return new IPAddress(bytes, scope);
    }

    private static string State(uint s) => s < TcpStates.Length ? TcpStates[s] : s.ToString();

    private static void Fill(bool tcp, int af, List<TableEntry> list)
    {
        int size = 0;
        uint err = tcp
            ? GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
            : GetExtendedUdpTable(IntPtr.Zero, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
        if (err != ERROR_INSUFFICIENT_BUFFER && err != 0) return;

        for (int attempt = 0; attempt < 3; attempt++)
        {
            size += 4096; // the table can grow between calls
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                err = tcp
                    ? GetExtendedTcpTable(buf, ref size, false, af, TCP_TABLE_OWNER_PID_ALL, 0)
                    : GetExtendedUdpTable(buf, ref size, false, af, UDP_TABLE_OWNER_PID, 0);
                if (err == ERROR_INSUFFICIENT_BUFFER) continue;
                if (err != 0) return;
                Parse(tcp, af, (byte*)buf, list);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
    }

    private static void Parse(bool tcp, int af, byte* buf, List<TableEntry> list)
    {
        uint count = *(uint*)buf;
        byte* row = buf + 4;
        for (uint i = 0; i < count; i++)
        {
            if (tcp && af == AF_INET)
            {
                // MIB_TCPROW_OWNER_PID: state, localAddr, localPort, remoteAddr, remotePort, pid
                uint* r = (uint*)row;
                list.Add(new TableEntry((int)r[5], "TCP", V4(r[1]), Port(r[2]), V4(r[3]), Port(r[4]), State(r[0])));
                row += 24;
            }
            else if (tcp)
            {
                // MIB_TCP6ROW_OWNER_PID: localAddr[16], localScope, localPort, remoteAddr[16], remoteScope, remotePort, state, pid
                uint localScope = *(uint*)(row + 16), localPort = *(uint*)(row + 20);
                uint remoteScope = *(uint*)(row + 40), remotePort = *(uint*)(row + 44);
                uint state = *(uint*)(row + 48), pid = *(uint*)(row + 52);
                list.Add(new TableEntry((int)pid, "TCP", V6(row, localScope), Port(localPort),
                    V6(row + 24, remoteScope), Port(remotePort), State(state)));
                row += 56;
            }
            else if (af == AF_INET)
            {
                // MIB_UDPROW_OWNER_PID: localAddr, localPort, pid
                uint* r = (uint*)row;
                list.Add(new TableEntry((int)r[2], "UDP", V4(r[0]), Port(r[1]), null, 0, ""));
                row += 12;
            }
            else
            {
                // MIB_UDP6ROW_OWNER_PID: localAddr[16], localScope, localPort, pid
                uint scope = *(uint*)(row + 16), port = *(uint*)(row + 20), pid = *(uint*)(row + 24);
                list.Add(new TableEntry((int)pid, "UDP", V6(row, scope), Port(port), null, 0, ""));
                row += 28;
            }
        }
    }
}

/// <summary>Total upload/download speed of all active physical adapters (no admin needed).</summary>
internal sealed class AdapterCounter
{
    private long _sent = -1, _recv, _tick;

    public (double Up, double Down) Sample()
    {
        long sent = 0, recv = 0;
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            try
            {
                var s = ni.GetIPStatistics();
                sent += s.BytesSent;
                recv += s.BytesReceived;
            }
            catch (NetworkInformationException)
            {
            }
        }

        long now = Environment.TickCount64;
        (double, double) result = (0, 0);
        if (_sent >= 0 && now > _tick)
        {
            double secs = (now - _tick) / 1000.0;
            result = (Math.Max(0, (sent - _sent) / secs), Math.Max(0, (recv - _recv) / secs));
        }
        _sent = sent;
        _recv = recv;
        _tick = now;
        return result;
    }
}
