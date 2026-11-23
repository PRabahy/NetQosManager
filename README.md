# Network QoS Manager

A small Windows app that shows how much network traffic each process and connection is using, and lets you
throttle uploads with Windows Policy-based QoS, without typing `New-NetQosPolicy` commands.

## Features

- **Live traffic per connection**: process, PID, protocol, local and remote endpoints, upload and download
  rates and totals, refreshed every second. Covers TCP and UDP over IPv4 and IPv6, including kernel traffic
  such as SMB file sharing (shown as `System`).
- **Group by process**: a tree view with one row per process and its connections nested underneath.
- **Sortable columns**: click a header to sort, click again to reverse.
- **Throttle uploads**: create a QoS throttle policy from a selected row, by application and/or remote port.
- **Policy list**: shows every QoS policy with its conditions, its limit and the upload currently flowing
  through it. Right-click to change a limit, delete, or copy as a PowerShell command.
- **Safety checks**: refuses rules that would throttle all upload traffic, and highlights any existing catch-all rule in red.

## Requirements

- Windows 10/11, 64-bit
- [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0) (the .NET 8 SDK to build)
- Administrator rights for measuring traffic and changing policies. The app starts unelevated and offers
  **Restart as administrator**.

## Build and run

```powershell
dotnet build -c Release
.\bin\Release\net8.0-windows\NetQosManager.exe
```

### Self-test

A read-only, headless check that measures traffic for about 6 seconds and lists QoS policies. Run it from an
elevated prompt:

```powershell
.\bin\Release\net8.0-windows\NetQosManager.exe --selftest .\selftest-report.txt
```

## How it works

- **Traffic:** a real-time ETW session on the `Microsoft-Windows-Kernel-Network` provider (TCP/UDP send and
  receive events, IPv4 and IPv6). Bytes are counted per process and connection. Which side is local is
  decided by comparing against the machine's own addresses, and port byte order is detected automatically
  against the TCP table.
- **Policies:** the app runs the built-in NetQos PowerShell cmdlets (`Get-`, `New-`, `Set-` and
  `Remove-NetQosPolicy`). User input is passed as base64-encoded JSON, never spliced into script text.

## Windows QoS limitations (observed on Windows 11 Home)

These were measured, not taken from documentation, and they shape what the app offers:

| Behavior | Result |
|---|---|
| `-PolicyStore ActiveStore` with `-IPDstPrefixMatchCondition` | The address condition is **silently dropped**. An address-only rule becomes a rule with no conditions and throttles **all** upload traffic. |
| Persistent store (no `-PolicyStore`) | Keeps the address, but the policy was **not enforced**. |
| ActiveStore by application, protocol or remote port | Works. A 100 Mbps cap held upload at 94–100 Mbps with no retransmits. |
| Policy names in ActiveStore | Lower-cased by Windows. |

So the app creates **temporary (until reboot) rules matched by application and/or remote port only**. A port
rule applies to that port on every remote host. Traffic sent by the `System` process (SMB) can only be
matched by port. QoS throttling affects **outbound** traffic only.

Some backup tools report a speed of 0 B/s while throttled even though data keeps flowing. Check the
amount backed up instead.
