using System.Runtime.InteropServices;

namespace NetQosManager;

// Hand-written ETW interop (x64 layouts). Sizes are asserted in EtwLayout.Verify().

[StructLayout(LayoutKind.Sequential)]
internal struct WNODE_HEADER
{
    public uint BufferSize;
    public uint ProviderId;
    public ulong HistoricalContext;
    public long TimeStamp;
    public Guid Guid;
    public uint ClientContext;
    public uint Flags;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_TRACE_PROPERTIES
{
    public WNODE_HEADER Wnode;
    public uint BufferSize;
    public uint MinimumBuffers;
    public uint MaximumBuffers;
    public uint MaximumFileSize;
    public uint LogFileMode;
    public uint FlushTimer;
    public uint EnableFlags;
    public int AgeLimit;
    public uint NumberOfBuffers;
    public uint FreeBuffers;
    public uint EventsLost;
    public uint BuffersWritten;
    public uint LogBuffersLost;
    public uint RealTimeBuffersLost;
    public IntPtr LoggerThreadId;
    public uint LogFileNameOffset;
    public uint LoggerNameOffset;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct TraceProperties
{
    public EVENT_TRACE_PROPERTIES Props;
    public fixed char LoggerName[1024];
}

[StructLayout(LayoutKind.Sequential)]
internal struct SYSTEMTIME
{
    public ushort Year, Month, DayOfWeek, Day, Hour, Minute, Second, Milliseconds;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct TIME_ZONE_INFORMATION
{
    public int Bias;
    public fixed char StandardName[32];
    public SYSTEMTIME StandardDate;
    public int StandardBias;
    public fixed char DaylightName[32];
    public SYSTEMTIME DaylightDate;
    public int DaylightBias;
}

[StructLayout(LayoutKind.Sequential)]
internal struct TRACE_LOGFILE_HEADER
{
    public uint BufferSize;
    public uint Version;
    public uint ProviderVersion;
    public uint NumberOfProcessors;
    public long EndTime;
    public uint TimerResolution;
    public uint MaximumFileSize;
    public uint LogFileMode;
    public uint BuffersWritten;
    public Guid LogInstanceGuid;
    public IntPtr LoggerName;
    public IntPtr LogFileName;
    public TIME_ZONE_INFORMATION TimeZone;
    public long BootTime;
    public long PerfFreq;
    public long StartTime;
    public uint ReservedFlags;
    public uint BuffersLost;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_TRACE_HEADER
{
    public ushort Size;
    public byte HeaderType;
    public byte MarkerFlags;
    public uint Version;
    public uint ThreadId;
    public uint ProcessId;
    public long TimeStamp;
    public Guid Guid;
    public uint KernelTime;
    public uint UserTime;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_TRACE
{
    public EVENT_TRACE_HEADER Header;
    public uint InstanceId;
    public uint ParentInstanceId;
    public Guid ParentGuid;
    public IntPtr MofData;
    public uint MofLength;
    public uint ClientContext;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_TRACE_LOGFILEW
{
    public IntPtr LogFileName;
    public IntPtr LoggerName;
    public long CurrentTime;
    public uint BuffersRead;
    public uint ProcessTraceMode;
    public EVENT_TRACE CurrentEvent;
    public TRACE_LOGFILE_HEADER LogfileHeader;
    public IntPtr BufferCallback;
    public uint BufferSize;
    public uint Filled;
    public uint EventsLost;
    public IntPtr EventRecordCallback;
    public uint IsKernelTrace;
    public IntPtr Context;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_DESCRIPTOR
{
    public ushort Id;
    public byte Version;
    public byte Channel;
    public byte Level;
    public byte Opcode;
    public ushort Task;
    public ulong Keyword;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_HEADER
{
    public ushort Size;
    public ushort HeaderType;
    public ushort Flags;
    public ushort EventProperty;
    public uint ThreadId;
    public uint ProcessId;
    public long TimeStamp;
    public Guid ProviderId;
    public EVENT_DESCRIPTOR EventDescriptor;
    public ulong ProcessorTime;
    public Guid ActivityId;
}

[StructLayout(LayoutKind.Sequential)]
internal struct EVENT_RECORD
{
    public EVENT_HEADER EventHeader;
    public uint BufferContext;
    public ushort ExtendedDataCount;
    public ushort UserDataLength;
    public IntPtr ExtendedData;
    public IntPtr UserData;
    public IntPtr UserContext;
}

[UnmanagedFunctionPointer(CallingConvention.StdCall)]
internal unsafe delegate void EventRecordCallback(EVENT_RECORD* record);

internal static unsafe class Etw
{
    public const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
    public const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
    public const uint EVENT_TRACE_CONTROL_STOP = 1;
    public const uint EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1;
    public const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    public const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
    public const uint ERROR_ALREADY_EXISTS = 183;
    public const ulong INVALID_PROCESSTRACE_HANDLE = ulong.MaxValue;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint StartTraceW(out ulong sessionHandle, string sessionName, EVENT_TRACE_PROPERTIES* properties);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern uint ControlTraceW(ulong sessionHandle, string? sessionName, EVENT_TRACE_PROPERTIES* properties, uint controlCode);

    [DllImport("advapi32.dll")]
    public static extern uint EnableTraceEx2(ulong sessionHandle, ref Guid providerId, uint controlCode, byte level,
        ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern ulong OpenTraceW(EVENT_TRACE_LOGFILEW* logfile);

    [DllImport("advapi32.dll")]
    public static extern uint ProcessTrace(ulong* handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

    [DllImport("advapi32.dll")]
    public static extern uint CloseTrace(ulong traceHandle);
}

internal static unsafe class EtwLayout
{
    public static string Describe()
    {
        EVENT_TRACE_LOGFILEW lf = default;
        long cbOffset = (byte*)&lf.EventRecordCallback - (byte*)&lf;
        return $"EVENT_TRACE_PROPERTIES={sizeof(EVENT_TRACE_PROPERTIES)} (want 120), " +
               $"TRACE_LOGFILE_HEADER={sizeof(TRACE_LOGFILE_HEADER)} (want 280), " +
               $"EVENT_TRACE_LOGFILEW={sizeof(EVENT_TRACE_LOGFILEW)} (want 448), " +
               $"EventRecordCallback offset={cbOffset} (want 424), " +
               $"EVENT_RECORD={sizeof(EVENT_RECORD)} (want 112)";
    }

    public static void Verify()
    {
        EVENT_TRACE_LOGFILEW lf = default;
        long cbOffset = (byte*)&lf.EventRecordCallback - (byte*)&lf;
        if (sizeof(EVENT_TRACE_PROPERTIES) != 120 || sizeof(TRACE_LOGFILE_HEADER) != 280 ||
            sizeof(EVENT_TRACE_LOGFILEW) != 448 || cbOffset != 424 || sizeof(EVENT_RECORD) != 112)
        {
            throw new InvalidOperationException("ETW struct layout mismatch: " + Describe());
        }
    }
}
