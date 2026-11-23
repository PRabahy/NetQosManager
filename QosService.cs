using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;

namespace NetQosManager;

internal sealed record PolicyRequest(string Name, string? App, string? RemotePrefix, int RemotePort,
    string Protocol, ulong BitsPerSecond, bool Temporary);

internal sealed class QosPolicy
{
    public string Name { get; init; } = "";
    public string Owner { get; init; } = "";
    public string Lifetime { get; init; } = "";
    public bool Removable { get; init; }
    public string App { get; init; } = "";
    public string Protocol { get; init; } = "";
    public string DstPrefix { get; init; } = "";
    public int DstPortStart { get; init; }
    public int DstPortEnd { get; init; }
    public string SrcPrefix { get; init; } = "";
    public int SrcPortStart { get; init; }
    public int SrcPortEnd { get; init; }
    public string Uri { get; init; } = "";
    public string Template { get; init; } = "";
    public ulong ThrottleBps { get; init; }
    public int Dscp { get; init; } = -1;

    /// <summary>True when every condition is one this app can check against live traffic.</summary>
    public bool Evaluable =>
        SrcPrefix.Length == 0 && SrcPortStart == 0 && Uri.Length == 0 && Template.Length == 0;

    /// <summary>No app, port or address condition: Windows applies it to all (TCP/UDP) upload traffic.</summary>
    public bool IsCatchAll =>
        App.Length == 0 && DstPortStart == 0 && DstPrefix.Length == 0 && SrcPrefix.Length == 0 &&
        SrcPortStart == 0 && Uri.Length == 0 && Template.Length == 0;

    public string Match
    {
        get
        {
            var parts = new List<string>();
            if (App.Length > 0) parts.Add("App " + App);
            if (Template.Length > 0) parts.Add("Template " + Template);
            if (Protocol.Length > 0) parts.Add(Protocol);
            if (DstPrefix.Length > 0) parts.Add("to " + DstPrefix);
            if (DstPortStart > 0) parts.Add("port " + PortRange(DstPortStart, DstPortEnd));
            if (SrcPrefix.Length > 0) parts.Add("from " + SrcPrefix);
            if (SrcPortStart > 0) parts.Add("local port " + PortRange(SrcPortStart, SrcPortEnd));
            if (Uri.Length > 0) parts.Add("URI " + Uri);
            if (IsCatchAll)
                return Protocol is "TCP" or "UDP" ? $"ALL {Protocol} upload traffic" : "ALL upload traffic";
            return string.Join(", ", parts);
        }
    }

    private static string PortRange(int start, int end) => end > start ? $"{start}-{end}" : start.ToString();

    public string LimitText => ThrottleBps > 0
        ? Fmt.Bits(ThrottleBps)
        : Dscp >= 0 ? $"DSCP {Dscp} only" : "none";

    public bool Matches(TrafficRow r)
    {
        if (!Evaluable) return false;
        if (App.Length > 0)
        {
            string exe = Path.GetFileName(App);
            if (!exe.Equals(r.Process + ".exe", StringComparison.OrdinalIgnoreCase) &&
                !exe.Equals(r.Process, StringComparison.OrdinalIgnoreCase)) return false;
        }
        if (DstPrefix.Length > 0)
        {
            if (r.RemoteIp == null || !PrefixContains(DstPrefix, r.RemoteIp)) return false;
        }
        if (DstPortStart > 0)
        {
            int end = DstPortEnd > 0 ? DstPortEnd : DstPortStart;
            if (r.RemotePort < DstPortStart || r.RemotePort > end) return false;
        }
        if ((Protocol == "TCP" || Protocol == "UDP") && r.Proto != Protocol) return false;
        return true;
    }

    private static bool PrefixContains(string prefix, IPAddress ip)
    {
        if (IPNetwork.TryParse(prefix, out var net))
            return ip.AddressFamily == net.BaseAddress.AddressFamily && net.Contains(ip);
        return IPAddress.TryParse(prefix, out var single) && single.Equals(ip);
    }
}

internal sealed record PolicyListResult(List<QosPolicy> Policies, List<string> Errors, string Raw, string Stderr, bool ActiveStoreReadable = true);

/// <summary>Talks to the NetQos PowerShell cmdlets. User input is always passed as base64 JSON, never spliced into script text.</summary>
internal static class QosService
{
    private const string Prelude =
        "$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n" +
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n";

    private sealed record PsResult(int ExitCode, string Stdout, string Stderr);

    private static async Task<PsResult> RunAsync(string script)
    {
        var psi = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand" })
            psi.ArgumentList.Add(a);
        psi.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(Prelude + script)));

        using var p = Process.Start(psi) ?? throw new InvalidOperationException("Could not start powershell.exe");
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync().ConfigureAwait(false);
        return new PsResult(p.ExitCode, await stdout.ConfigureAwait(false), await stderr.ConfigureAwait(false));
    }

    private static string B64Json(object value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)));

    private static JsonDocument? LastJson(string stdout)
    {
        var line = stdout.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith('{'));
        if (line == null) return null;
        try { return JsonDocument.Parse(line); } catch (JsonException) { return null; }
    }

    private static IEnumerable<JsonElement> AsArray(JsonElement e) =>
        e.ValueKind == JsonValueKind.Array ? e.EnumerateArray()
        : e.ValueKind == JsonValueKind.Null || e.ValueKind == JsonValueKind.Undefined ? Enumerable.Empty<JsonElement>()
        : new[] { e };

    private static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";

    private static long Num(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var n) ? n : 0;

    private const string ListScript = @"
$errors = @()
function Get-Proto($v) { switch (""$v"") { '1' {'TCP'} 'TCP' {'TCP'} '2' {'UDP'} 'UDP' {'UDP'} '3' {'Both'} 'Both' {'Both'} default {''} } }
function Convert-Policy($p, $store) {
  $tpl = ""$($p.Template)""; if ($tpl -eq 'None' -or $tpl -eq '0') { $tpl = '' }
  [pscustomobject]@{
    Name = ""$($p.Name)""; Store = $store; Owner = ""$($p.Owner)""
    App = ""$($p.AppPathNameMatchCondition)""
    Protocol = Get-Proto $p.IPProtocolMatchCondition
    DstPrefix = ""$($p.IPDstPrefixMatchCondition)""
    DstPortStart = [int]$p.IPDstPortStartMatchCondition
    DstPortEnd = [int]$p.IPDstPortEndMatchCondition
    SrcPrefix = ""$($p.IPSrcPrefixMatchCondition)""
    SrcPortStart = [int]$p.IPSrcPortStartMatchCondition
    SrcPortEnd = [int]$p.IPSrcPortEndMatchCondition
    Uri = ""$($p.URIMatchCondition)""
    Template = $tpl
    Throttle = [int64]$p.ThrottleRateAction
    Dscp = [int]$p.DSCPAction
  }
}
$all = @()
try { $all += @(Get-NetQosPolicy -PolicyStore ActiveStore | ForEach-Object { Convert-Policy $_ 'Active' }) } catch { $errors += ""ActiveStore: $($_.Exception.Message)"" }
try { $all += @(Get-NetQosPolicy | ForEach-Object { Convert-Policy $_ 'Persistent' }) } catch { $errors += ""Persistent store: $($_.Exception.Message)"" }
[pscustomobject]@{ Policies = @($all); Errors = @($errors) } | ConvertTo-Json -Depth 4 -Compress
";

    public static async Task<PolicyListResult> ListAsync()
    {
        var r = await RunAsync(ListScript).ConfigureAwait(false);
        var errors = new List<string>();
        var raw = new List<(string Store, QosPolicy P)>();

        using (var doc = LastJson(r.Stdout))
        {
            if (doc == null)
            {
                errors.Add("PowerShell returned no data. " + r.Stderr.Trim());
            }
            else
            {
                if (doc.RootElement.TryGetProperty("Errors", out var errs))
                    errors.AddRange(AsArray(errs).Select(e => e.ToString()).Where(s => s.Length > 0));
                if (doc.RootElement.TryGetProperty("Policies", out var pols))
                {
                    foreach (var e in AsArray(pols))
                    {
                        raw.Add((Str(e, "Store"), new QosPolicy
                        {
                            Name = Str(e, "Name"),
                            Owner = Str(e, "Owner"),
                            App = Str(e, "App"),
                            Protocol = Str(e, "Protocol"),
                            DstPrefix = Str(e, "DstPrefix"),
                            DstPortStart = (int)Num(e, "DstPortStart"),
                            DstPortEnd = (int)Num(e, "DstPortEnd"),
                            SrcPrefix = Str(e, "SrcPrefix"),
                            SrcPortStart = (int)Num(e, "SrcPortStart"),
                            SrcPortEnd = (int)Num(e, "SrcPortEnd"),
                            Uri = Str(e, "Uri"),
                            Template = Str(e, "Template"),
                            ThrottleBps = (ulong)Math.Max(0, Num(e, "Throttle")),
                            Dscp = (int)Num(e, "Dscp"),
                        }));
                    }
                }
            }
        }

        // Without admin the temporary store can't be read; that's expected, not an error worth showing.
        bool activeReadable = !errors.Any(e => e.StartsWith("ActiveStore", StringComparison.Ordinal));
        if (!activeReadable) errors.RemoveAll(e => e.StartsWith("ActiveStore", StringComparison.Ordinal));

        var merged = new List<QosPolicy>();
        foreach (var g in raw.GroupBy(x => (x.P.Name, x.P.Owner)))
        {
            bool active = g.Any(x => x.Store == "Active");
            bool persistent = g.Any(x => x.Store == "Persistent");
            var src = g.FirstOrDefault(x => x.Store == "Active").P ?? g.First().P;
            bool gpo = src.Owner.StartsWith("Group Policy", StringComparison.OrdinalIgnoreCase);
            string lifetime = gpo ? "Group Policy"
                : persistent ? (active || !activeReadable ? "Permanent" : "Permanent (not active)")
                : "Until reboot";
            merged.Add(new QosPolicy
            {
                Name = src.Name, Owner = src.Owner, Lifetime = lifetime, Removable = !gpo,
                App = src.App, Protocol = src.Protocol, DstPrefix = src.DstPrefix,
                DstPortStart = src.DstPortStart, DstPortEnd = src.DstPortEnd,
                SrcPrefix = src.SrcPrefix, SrcPortStart = src.SrcPortStart, SrcPortEnd = src.SrcPortEnd,
                Uri = src.Uri, Template = src.Template, ThrottleBps = src.ThrottleBps, Dscp = src.Dscp,
            });
        }

        return new PolicyListResult(merged.OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase).ToList(),
            errors, r.Stdout.Trim(), r.Stderr.Trim(), activeReadable);
    }

    public static async Task<(bool Ok, string Error)> CreateAsync(PolicyRequest req)
    {
        // Windows ignores address conditions in the temporary store, so a rule needs an app or a port,
        // otherwise it would throttle every upload on the PC.
        if (string.IsNullOrWhiteSpace(req.App) && req.RemotePort <= 0)
            return (false, "Refused: without an application or port, Windows would throttle all upload traffic.");
        req = req with { RemotePrefix = null };

        string script = $@"
try {{
  $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{B64Json(req)}')) | ConvertFrom-Json
  $a = @{{ Name = [string]$p.Name; ThrottleRateActionBitsPerSecond = [uint64]$p.BitsPerSecond }}
  if ($p.App) {{ $a.AppPathNameMatchCondition = [string]$p.App }}
  if ($p.RemotePrefix) {{ $a.IPDstPrefixMatchCondition = [string]$p.RemotePrefix }}
  $proto = [string]$p.Protocol
  if ([int]$p.RemotePort -gt 0) {{
    $a.IPDstPortMatchCondition = [uint16]$p.RemotePort
    if ($proto -eq 'Any') {{ $proto = 'Both' }}
  }}
  if ($proto -ne 'Any') {{ $a.IPProtocolMatchCondition = $proto }}
  if ($p.Temporary) {{ $a.PolicyStore = 'ActiveStore' }}
  New-NetQosPolicy @a | Out-Null
  [pscustomobject]@{{ Ok = $true; Error = '' }} | ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{ Ok = $false; Error = $_.Exception.Message }} | ConvertTo-Json -Compress
}}";
        var r = await RunAsync(script).ConfigureAwait(false);
        using var doc = LastJson(r.Stdout);
        if (doc == null) return (false, "No response from PowerShell. " + r.Stderr.Trim());
        bool ok = doc.RootElement.TryGetProperty("Ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
        return (ok, Str(doc.RootElement, "Error"));
    }

    public static async Task<(bool Ok, string Error)> SetLimitAsync(QosPolicy policy, ulong bitsPerSecond)
    {
        var args = new { policy.Name, Persistent = policy.Lifetime.StartsWith("Permanent"), Bps = bitsPerSecond };
        string script = $@"
try {{
  $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{B64Json(args)}')) | ConvertFrom-Json
  if ($p.Persistent) {{ Set-NetQosPolicy -Name $p.Name -ThrottleRateActionBitsPerSecond ([uint64]$p.Bps) -Confirm:$false }}
  else {{ Set-NetQosPolicy -Name $p.Name -PolicyStore ActiveStore -ThrottleRateActionBitsPerSecond ([uint64]$p.Bps) -Confirm:$false }}
  [pscustomobject]@{{ Ok = $true; Error = '' }} | ConvertTo-Json -Compress
}} catch {{
  [pscustomobject]@{{ Ok = $false; Error = $_.Exception.Message }} | ConvertTo-Json -Compress
}}";
        var r = await RunAsync(script).ConfigureAwait(false);
        using var doc = LastJson(r.Stdout);
        if (doc == null) return (false, "No response from PowerShell. " + r.Stderr.Trim());
        bool ok = doc.RootElement.TryGetProperty("Ok", out var okEl) && okEl.ValueKind == JsonValueKind.True;
        return (ok, Str(doc.RootElement, "Error"));
    }

    /// <summary>A New-NetQosPolicy command that recreates the policy (for copying to the clipboard).</summary>
    public static string ToPowerShell(QosPolicy p)
    {
        static string Q(string s) => "'" + s.Replace("'", "''") + "'";
        var sb = new StringBuilder("New-NetQosPolicy -Name " + Q(p.Name));
        if (p.App.Length > 0) sb.Append(" -AppPathNameMatchCondition " + Q(p.App));
        if (p.Protocol.Length > 0) sb.Append(" -IPProtocolMatchCondition " + p.Protocol);
        if (p.DstPrefix.Length > 0) sb.Append(" -IPDstPrefixMatchCondition " + Q(p.DstPrefix));
        if (p.DstPortStart > 0)
        {
            if (p.DstPortEnd > p.DstPortStart)
                sb.Append($" -IPDstPortStartMatchCondition {p.DstPortStart} -IPDstPortEndMatchCondition {p.DstPortEnd}");
            else
                sb.Append($" -IPDstPortMatchCondition {p.DstPortStart}");
        }
        if (p.SrcPrefix.Length > 0) sb.Append(" -IPSrcPrefixMatchCondition " + Q(p.SrcPrefix));
        if (p.SrcPortStart > 0)
        {
            if (p.SrcPortEnd > p.SrcPortStart)
                sb.Append($" -IPSrcPortStartMatchCondition {p.SrcPortStart} -IPSrcPortEndMatchCondition {p.SrcPortEnd}");
            else
                sb.Append($" -IPSrcPortMatchCondition {p.SrcPortStart}");
        }
        if (p.ThrottleBps > 0) sb.Append($" -ThrottleRateActionBitsPerSecond {p.ThrottleBps}");
        if (p.Dscp >= 0) sb.Append($" -DSCPAction {p.Dscp}");
        if (!p.Lifetime.StartsWith("Permanent") && p.Lifetime != "Group Policy") sb.Append(" -PolicyStore ActiveStore");
        return sb.ToString();
    }

    public static async Task<List<string>> DeleteAsync(IEnumerable<string> names)
    {
        string script = $@"
$names = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{B64Json(names.ToArray())}')) | ConvertFrom-Json
$msgs = @()
foreach ($n in @($names)) {{
  $removed = $false
  foreach ($store in 'Persistent', 'ActiveStore') {{
    try {{
      if ($store -eq 'ActiveStore') {{ $found = @(Get-NetQosPolicy -PolicyStore ActiveStore | Where-Object {{ $_.Name -ceq $n }}) }}
      else {{ $found = @(Get-NetQosPolicy | Where-Object {{ $_.Name -ceq $n }}) }}
      foreach ($f in $found) {{
        if (""$($f.Owner)"" -like 'Group Policy*') {{ $msgs += ""Skipped '$n' (owned by Group Policy)""; continue }}
        if ($store -eq 'ActiveStore') {{ Remove-NetQosPolicy -Name $n -PolicyStore ActiveStore -Confirm:$false }}
        else {{ Remove-NetQosPolicy -Name $n -Confirm:$false }}
        $removed = $true
      }}
    }} catch {{ $msgs += ""Error removing '$n' from ${{store}}: $($_.Exception.Message)"" }}
  }}
  if ($removed) {{ $msgs += ""Removed '$n'"" }}
}}
[pscustomobject]@{{ Messages = @($msgs) }} | ConvertTo-Json -Compress
";
        var r = await RunAsync(script).ConfigureAwait(false);
        using var doc = LastJson(r.Stdout);
        if (doc == null) return new List<string> { "No response from PowerShell. " + r.Stderr.Trim() };
        return doc.RootElement.TryGetProperty("Messages", out var m)
            ? AsArray(m).Select(e => e.ToString()).ToList()
            : new List<string>();
    }
}
