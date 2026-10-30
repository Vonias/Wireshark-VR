using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;

namespace WiresharkVR.Core;

/// <summary>Runs tshark (Wireshark's command-line engine) and returns dissected packets.</summary>
public sealed class TsharkRunner : ICaptureEngine
{
    public string Name => "tshark (full Wireshark engine)";

    public string ExecutablePath { get; }

    public TsharkRunner(string? executablePath = null)
    {
        ExecutablePath = executablePath ?? Locate()
            ?? throw new FileNotFoundException(
                "tshark.exe not found. Install Wireshark or set the WIRESHARK_TSHARK environment variable.");
    }

    public static string? Locate()
    {
        var env = Environment.GetEnvironmentVariable("WIRESHARK_TSHARK");
        if (!string.IsNullOrEmpty(env) && File.Exists(env)) return env;

        string[] candidates =
        {
            @"C:\Program Files\Wireshark\tshark.exe",
            @"C:\Program Files (x86)\Wireshark\tshark.exe",
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
        };
        return candidates.FirstOrDefault(File.Exists);
    }

    // ---- Packet List pane -------------------------------------------------

    /// <summary>Lists packets like Wireshark's Packet List. A bad display filter throws InvalidOperationException.</summary>
    public async Task<List<PacketRow>> ListPacketsAsync(string pcapPath, string? displayFilter = null, CancellationToken ct = default)
    {
        var args = new List<string> { "-r", pcapPath };
        if (!string.IsNullOrWhiteSpace(displayFilter)) { args.Add("-Y"); args.Add(displayFilter); }
        args.AddRange(new[]
        {
            "-T", "fields", "-E", "separator=/t",
            "-e", "frame.number", "-e", "frame.time_relative",
            "-e", "_ws.col.Source", "-e", "_ws.col.Destination",
            "-e", "_ws.col.Protocol", "-e", "frame.len", "-e", "_ws.col.Info",
        });

        var text = await RunAsync(args, ct);
        var rows = new List<PacketRow>();
        foreach (var line in text.Split('\n'))
        {
            var f = line.TrimEnd('\r').Split('\t');
            if (f.Length < 7 || !int.TryParse(f[0], out var number)) continue;
            double.TryParse(f[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var rel);
            int.TryParse(f[5], out var len);
            rows.Add(new PacketRow(number, rel, f[2], f[3], f[4], len, f[6]));
        }
        return rows;
    }

    // ---- Packet Details and Packet Bytes panes ----------------------------

    public async Task<PacketDetail> GetDetailAsync(string pcapPath, int packetNumber, CancellationToken ct = default)
    {
        string filter = $"frame.number == {packetNumber}";
        var pdml = RunAsync(new[] { "-r", pcapPath, "-Y", filter, "-T", "pdml" }, ct);
        var hex  = RunAsync(new[] { "-r", pcapPath, "-Y", filter, "-x" }, ct);
        await Task.WhenAll(pdml, hex);
        return new PacketDetail { Tree = PdmlParser.Parse(pdml.Result), Bytes = HexDump.Parse(hex.Result) };
    }

    // ---- Statistics menu and Follow Stream --------------------------------

    /// <summary>Runs a tshark statistic such as "io,phs" or "conv,tcp" and returns its text report.</summary>
    public Task<string> StatisticAsync(string pcapPath, string statistic, string? displayFilter = null, CancellationToken ct = default)
    {
        var args = new List<string> { "-r", pcapPath, "-q", "-z", statistic };
        if (!string.IsNullOrWhiteSpace(displayFilter)) { args.Add("-Y"); args.Add(displayFilter); }
        return RunAsync(args, ct);
    }

    /// <summary>Follow TCP/UDP Stream: the conversation reassembled as readable text.</summary>
    public Task<string> FollowStreamAsync(string pcapPath, string protocol, int streamIndex, CancellationToken ct = default) =>
        RunAsync(new[] { "-r", pcapPath, "-q", "-z", $"follow,{protocol},ascii,{streamIndex}" }, ct);

    // ---- Flow view (JSON model used by the 3D ladder diagram) -------------

    /// <summary>Dissects a capture file. maxPackets limits how many packets are read (0 = all).</summary>
    public async Task<List<Packet>> ReadFileAsync(string pcapPath, int maxPackets = 0, CancellationToken ct = default)
    {
        var args = new List<string> { "-r", pcapPath, "-T", "json" };
        if (maxPackets > 0) { args.Add("-c"); args.Add(maxPackets.ToString()); }
        return CaptureParser.Parse(await RunAsync(args, ct));
    }

    // ---- Live capture -------------------------------------------------------

    /// <summary>Returns interface labels like "1. Wi-Fi" parsed from tshark -D output.</summary>
    public async Task<List<string>> ListInterfacesAsync(CancellationToken ct = default)
    {
        var text = await RunAsync(new[] { "-D" }, ct);
        var result = new List<string>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r').Trim();
            if (line.Length == 0) continue;
            // "1. \Device\NPF_{GUID} (Wi-Fi)"  →  "1. Wi-Fi"
            var m = Regex.Match(line, @"^(\d+)\.\s+.*\((.+)\)\s*$");
            result.Add(m.Success ? $"{m.Groups[1].Value}. {m.Groups[2].Value}" : line);
        }
        return result;
    }

    /// <summary>
    /// Streams a live capture from <paramref name="iface"/> (the number string from <see cref="ListInterfacesAsync"/>).
    /// Writes raw packets to <paramref name="tempFile"/> simultaneously so details can be fetched while running.
    /// </summary>
    public async IAsyncEnumerable<PacketRow> CaptureAsync(
        string iface, string tempFile, [EnumeratorCancellation] CancellationToken ct = default)
    {
        var psi = new ProcessStartInfo(ExecutablePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        psi.ArgumentList.Add("-i");  psi.ArgumentList.Add(iface);
        psi.ArgumentList.Add("-w");  psi.ArgumentList.Add(tempFile);  // write pcapng for details/hex
        psi.ArgumentList.Add("-l");  // line-buffered stdout
        psi.ArgumentList.Add("-T");  psi.ArgumentList.Add("fields");
        psi.ArgumentList.Add("-E");  psi.ArgumentList.Add("separator=/t");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("frame.number");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("frame.time_relative");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("_ws.col.Source");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("_ws.col.Destination");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("_ws.col.Protocol");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("frame.len");
        psi.ArgumentList.Add("-e");  psi.ArgumentList.Add("_ws.col.Info");

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start tshark.");
        try
        {
            string? line;
            while ((line = await proc.StandardOutput.ReadLineAsync(ct).ConfigureAwait(false)) != null)
            {
                var f = line.TrimEnd('\r').Split('\t');
                if (f.Length < 7 || !int.TryParse(f[0], out var number)) continue;
                double.TryParse(f[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var rel);
                int.TryParse(f[5], out var len);
                yield return new PacketRow(number, rel, f[2], f[3], f[4], len, f[6]);
            }
        }
        finally
        {
            if (!proc.HasExited)
            {
                proc.Kill();
                await proc.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false);
            }
        }
    }

    // ---- process plumbing -------------------------------------------------

    async Task<string> RunAsync(IEnumerable<string> args, CancellationToken ct)
    {
        var psi = new ProcessStartInfo(ExecutablePath)
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var proc = Process.Start(psi) ?? throw new InvalidOperationException("Could not start tshark.");
        var stdout = proc.StandardOutput.ReadToEndAsync(ct);
        var stderr = proc.StandardError.ReadToEndAsync(ct);
        await proc.WaitForExitAsync(ct);

        if (proc.ExitCode != 0)
        {
            var err = (await stderr).Trim();
            int nl = err.IndexOf('\n');
            throw new InvalidOperationException(nl > 0 ? err[..nl].Trim() : err);
        }
        return await stdout;
    }
}
