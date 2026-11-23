using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;

namespace NetQosManager;

/// <summary>Identifies one flow: process + protocol + local endpoint + remote endpoint. Ports are kept raw (as logged).</summary>
internal readonly struct ConnKey : IEquatable<ConnKey>
{
    public readonly int Pid;
    public readonly byte Proto; // 6 = TCP, 17 = UDP
    public readonly bool V6;
    public readonly ulong L0, L1, R0, R1;
    public readonly ushort LPortRaw, RPortRaw;

    public ConnKey(int pid, byte proto, bool v6, ulong l0, ulong l1, ushort lPort, ulong r0, ulong r1, ushort rPort)
    {
        Pid = pid; Proto = proto; V6 = v6;
        L0 = l0; L1 = l1; LPortRaw = lPort;
        R0 = r0; R1 = r1; RPortRaw = rPort;
    }

    public bool Equals(ConnKey o) =>
        Pid == o.Pid && Proto == o.Proto && V6 == o.V6 && L0 == o.L0 && L1 == o.L1 &&
        R0 == o.R0 && R1 == o.R1 && LPortRaw == o.LPortRaw && RPortRaw == o.RPortRaw;

    public override bool Equals(object? obj) => obj is ConnKey k && Equals(k);

    public override int GetHashCode()
    {
        var h = new HashCode();
        h.Add(Pid); h.Add(Proto); h.Add(L0); h.Add(L1); h.Add(R0); h.Add(R1); h.Add(LPortRaw); h.Add(RPortRaw);
        return h.ToHashCode();
    }

    public IPAddress LocalAddress => ToIp(V6, L0, L1);
    public IPAddress RemoteAddress => ToIp(V6, R0, R1);

    public static IPAddress ToIp(bool v6, ulong a0, ulong a1)
    {
        if (!v6) return new IPAddress(BitConverter.GetBytes((uint)a0));
        var b = new byte[16];
        BitConverter.TryWriteBytes(b.AsSpan(0, 8), a0);
        BitConverter.TryWriteBytes(b.AsSpan(8, 8), a1);
        return new IPAddress(b);
    }
}

internal readonly record struct ConnSnapshot(ConnKey Key, long Sent, long Recv, long LastSeen);

/// <summary>
/// Real-time ETW consumer for Microsoft-Windows-Kernel-Network. Counts bytes per process and connection
/// for TCP and UDP, IPv4 and IPv6 (event IDs 10/11/26/27 and 42/43/58/59). Requires administrator rights.
/// </summary>
internal sealed unsafe class NetworkMonitor : IDisposable
{
    public static readonly Guid ProviderGuid = new("7dd42a49-5329-4832-8dfd-43d979153a88");
    public const string SessionName = "NetQosManager-KernelNetwork";

    private sealed class Counters { public long Sent, Recv, LastSeen; }

    private readonly object _lock = new();
    private readonly Dictionary<ConnKey, Counters> _conns = new();
    private readonly long[] _eventCounts = new long[64];

    private volatile HashSet<(bool, ulong, ulong)> _localAddresses = new();
    private long _localRefreshedAt;

    // Port byte order: -1 unknown (assume network order), 0 = host order, 1 = network order (swap).
    private volatile int _portMode = -1;
    private readonly object _sampleLock = new();
    private readonly List<ushort> _portSamples = new();

    private EventRecordCallback? _callback;
    private EVENT_TRACE_LOGFILEW* _logfile;
    private IntPtr _namePtr;
    private ulong _traceHandle = Etw.INVALID_PROCESSTRACE_HANDLE;
    private Thread? _thread;
    private volatile bool _consumerExited;
    private bool _started, _disposed;

    public uint ProcessTraceStatus { get; private set; }
    public bool ConsumerExited => _consumerExited;
    public string PortOrderDescription { get; private set; } = "not yet detected (assuming network byte order)";

    public void Start()
    {
        if (!Environment.Is64BitProcess) throw new PlatformNotSupportedException("A 64-bit process is required.");
        EtwLayout.Verify();
        RefreshLocalAddresses();

        StopSession(); // clean up a session left behind by a crashed earlier run

        uint err = StartSession(out ulong sessionHandle);
        if (err == Etw.ERROR_ALREADY_EXISTS)
        {
            StopSession();
            err = StartSession(out sessionHandle);
        }
        if (err != 0) throw new Win32Exception((int)err, $"StartTrace failed (error {err})");

        Guid provider = ProviderGuid;
        err = Etw.EnableTraceEx2(sessionHandle, ref provider, Etw.EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            5 /* verbose */, 0x30 /* IPv4 | IPv6 */, 0, 0, IntPtr.Zero);
        if (err != 0)
        {
            StopSession();
            throw new Win32Exception((int)err, $"EnableTraceEx2 failed (error {err})");
        }
        _started = true;

        _callback = OnEvent;
        _logfile = (EVENT_TRACE_LOGFILEW*)NativeMemory.AllocZeroed((nuint)sizeof(EVENT_TRACE_LOGFILEW));
        _namePtr = Marshal.StringToHGlobalUni(SessionName);
        _logfile->LoggerName = _namePtr;
        _logfile->ProcessTraceMode = Etw.PROCESS_TRACE_MODE_REAL_TIME | Etw.PROCESS_TRACE_MODE_EVENT_RECORD;
        _logfile->EventRecordCallback = Marshal.GetFunctionPointerForDelegate(_callback);

        _traceHandle = Etw.OpenTraceW(_logfile);
        if (_traceHandle == Etw.INVALID_PROCESSTRACE_HANDLE)
        {
            int e = Marshal.GetLastPInvokeError();
            Stop();
            throw new Win32Exception(e, $"OpenTrace failed (error {e})");
        }

        _thread = new Thread(ConsumeLoop) { IsBackground = true, Name = "ETW consumer" };
        _thread.Start();
    }

    private static uint StartSession(out ulong handle)
    {
        var tp = new TraceProperties();
        tp.Props.Wnode.BufferSize = (uint)sizeof(TraceProperties);
        tp.Props.Wnode.Flags = Etw.WNODE_FLAG_TRACED_GUID;
        tp.Props.Wnode.ClientContext = 1; // QPC timestamps
        tp.Props.BufferSize = 64;         // KB
        tp.Props.MinimumBuffers = 16;
        tp.Props.MaximumBuffers = 64;
        tp.Props.LogFileMode = Etw.EVENT_TRACE_REAL_TIME_MODE;
        tp.Props.FlushTimer = 1;
        tp.Props.LoggerNameOffset = (uint)sizeof(EVENT_TRACE_PROPERTIES);
        return Etw.StartTraceW(out handle, SessionName, &tp.Props);
    }

    private static uint StopSession()
    {
        var tp = new TraceProperties();
        tp.Props.Wnode.BufferSize = (uint)sizeof(TraceProperties);
        tp.Props.LoggerNameOffset = (uint)sizeof(EVENT_TRACE_PROPERTIES);
        return Etw.ControlTraceW(0, SessionName, &tp.Props, Etw.EVENT_TRACE_CONTROL_STOP);
    }

    private void ConsumeLoop()
    {
        ulong h = _traceHandle;
        ProcessTraceStatus = Etw.ProcessTrace(&h, 1, IntPtr.Zero, IntPtr.Zero);
        _consumerExited = true;
    }

    private void OnEvent(EVENT_RECORD* r)
    {
        try
        {
            if (r->EventHeader.ProviderId != ProviderGuid) return;
            int id = r->EventHeader.EventDescriptor.Id;
            if (id < _eventCounts.Length) Interlocked.Increment(ref _eventCounts[id]);

            bool send, v6;
            byte proto;
            switch (id)
            {
                case 10: send = true; proto = 6; v6 = false; break;
                case 11: send = false; proto = 6; v6 = false; break;
                case 26: send = true; proto = 6; v6 = true; break;
                case 27: send = false; proto = 6; v6 = true; break;
                case 42: send = true; proto = 17; v6 = false; break;
                case 43: send = false; proto = 17; v6 = false; break;
                case 58: send = true; proto = 17; v6 = true; break;
                case 59: send = false; proto = 17; v6 = true; break;
                default: return;
            }

            // Payload: PID u32, size u32, daddr, saddr, dport u16, sport u16, ...
            byte* d = (byte*)r->UserData;
            int portOffset = v6 ? 40 : 16;
            if (d == null || r->UserDataLength < portOffset + 4) return;

            uint pid = *(uint*)d;
            uint size = *(uint*)(d + 4);
            ulong da0, da1 = 0, sa0, sa1 = 0;
            if (v6)
            {
                da0 = *(ulong*)(d + 8); da1 = *(ulong*)(d + 16);
                sa0 = *(ulong*)(d + 24); sa1 = *(ulong*)(d + 32);
            }
            else
            {
                da0 = *(uint*)(d + 8);
                sa0 = *(uint*)(d + 12);
            }
            ushort dport = *(ushort*)(d + portOffset);
            ushort sport = *(ushort*)(d + portOffset + 2);

            // Decide which side is local by checking this machine's own addresses.
            var local = _localAddresses;
            bool sLocal = local.Contains((v6, sa0, sa1));
            bool dLocal = local.Contains((v6, da0, da1));
            bool saddrIsLocal = sLocal != dLocal ? sLocal : send;

            var key = saddrIsLocal
                ? new ConnKey((int)pid, proto, v6, sa0, sa1, sport, da0, da1, dport)
                : new ConnKey((int)pid, proto, v6, da0, da1, dport, sa0, sa1, sport);

            if (_portMode < 0 && proto == 6) SamplePort(key.LPortRaw);

            long now = Environment.TickCount64;
            lock (_lock)
            {
                if (!_conns.TryGetValue(key, out var c))
                {
                    c = new Counters();
                    _conns[key] = c;
                }
                if (send) c.Sent += size; else c.Recv += size;
                c.LastSeen = now;
            }
        }
        catch
        {
            // Never let an exception escape into native ETW code.
        }
    }

    private void SamplePort(ushort raw)
    {
        lock (_sampleLock)
        {
            if (_portSamples.Count < 400) _portSamples.Add(raw);
        }
    }

    public static ushort Swap(ushort p) => (ushort)((p >> 8) | (p << 8));

    /// <summary>Converts a logged port to a real port number.</summary>
    public int Port(ushort raw) => _portMode == 0 ? raw : Swap(raw);

    /// <summary>Works out the port byte order by comparing logged local TCP ports with the machine's TCP table.</summary>
    public void DetectPortOrder()
    {
        if (_portMode >= 0) return;
        ushort[] samples;
        lock (_sampleLock)
        {
            if (_portSamples.Count < 30) return;
            samples = _portSamples.ToArray();
        }

        var props = IPGlobalProperties.GetIPGlobalProperties();
        var ports = new HashSet<int>(props.GetActiveTcpConnections().Select(c => c.LocalEndPoint.Port)
            .Concat(props.GetActiveTcpListeners().Select(e => e.Port)));
        int raw = samples.Count(p => ports.Contains(p));
        int swapped = samples.Count(p => ports.Contains(Swap(p)));
        int best = Math.Max(raw, swapped);
        if (best >= 10 && best >= 2 * Math.Min(raw, swapped))
        {
            _portMode = swapped >= raw ? 1 : 0;
            PortOrderDescription = $"{(_portMode == 1 ? "network" : "host")} byte order (matched {best} of {samples.Length} samples; other order matched {Math.Min(raw, swapped)})";
        }
        else
        {
            lock (_sampleLock) { _portSamples.Clear(); }
            PortOrderDescription = $"inconclusive (raw {raw}, swapped {swapped} of {samples.Length}); assuming network byte order";
        }
    }

    public void RefreshLocalAddresses()
    {
        var set = new HashSet<(bool, ulong, ulong)>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                    AddAddress(set, ua.Address);
        }
        catch
        {
            // keep whatever we collected
        }
        AddAddress(set, IPAddress.Loopback);
        AddAddress(set, IPAddress.IPv6Loopback);
        _localAddresses = set;
        _localRefreshedAt = Environment.TickCount64;
    }

    private static void AddAddress(HashSet<(bool, ulong, ulong)> set, IPAddress a)
    {
        var b = a.GetAddressBytes();
        if (b.Length == 4) set.Add((false, BitConverter.ToUInt32(b, 0), 0UL));
        else if (b.Length == 16) set.Add((true, BitConverter.ToUInt64(b, 0), BitConverter.ToUInt64(b, 8)));
    }

    public List<ConnSnapshot> Snapshot()
    {
        if (Environment.TickCount64 - _localRefreshedAt > 30_000) RefreshLocalAddresses();
        lock (_lock)
        {
            var list = new List<ConnSnapshot>(_conns.Count);
            foreach (var kv in _conns)
                list.Add(new ConnSnapshot(kv.Key, kv.Value.Sent, kv.Value.Recv, kv.Value.LastSeen));
            return list;
        }
    }

    /// <summary>Forgets connections that have been quiet for longer than idleMs.</summary>
    public void Prune(long idleMs)
    {
        long now = Environment.TickCount64;
        lock (_lock)
        {
            List<ConnKey>? dead = null;
            foreach (var kv in _conns)
                if (now - kv.Value.LastSeen > idleMs) (dead ??= new()).Add(kv.Key);
            if (dead != null) foreach (var k in dead) _conns.Remove(k);
        }
    }

    public string EventCountsDescription()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < _eventCounts.Length; i++)
        {
            long n = Interlocked.Read(ref _eventCounts[i]);
            if (n > 0) sb.Append($"{i}:{n} ");
        }
        return sb.Length == 0 ? "(none)" : sb.ToString().Trim();
    }

    public void Stop()
    {
        if (_started) StopSession();
        _started = false;

        if (_traceHandle != Etw.INVALID_PROCESSTRACE_HANDLE)
        {
            Etw.CloseTrace(_traceHandle);
            _traceHandle = Etw.INVALID_PROCESSTRACE_HANDLE;
        }

        bool exited = _thread == null || _thread.Join(3000);
        if (exited)
        {
            if (_logfile != null) { NativeMemory.Free(_logfile); _logfile = null; }
            if (_namePtr != IntPtr.Zero) { Marshal.FreeHGlobal(_namePtr); _namePtr = IntPtr.Zero; }
        }
        // If the consumer thread is stuck, leak the small native buffers rather than free memory ETW may still use.
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        Stop();
    }
}
