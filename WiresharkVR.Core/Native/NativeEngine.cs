using System.Globalization;
using System.Text;

namespace WiresharkVR.Core.Native;

/// <summary>
/// Capture engine written entirely in C#, so it runs on a standalone headset where tshark cannot.
/// It understands a focused set of protocols (see <see cref="CaptureDissector"/>); everything else
/// is still listed, with its raw bytes, just without a decoded tree.
/// </summary>
public sealed class NativeEngine : ICaptureEngine
{
    public string Name => "built-in dissector";

    readonly object _gate = new();
    string? _cachedPath;
    DateTime _cachedStamp;
    List<DissectedPacket>? _cached;

    // ---- ICaptureEngine ---------------------------------------------------

    public Task<List<PacketRow>> ListPacketsAsync(string pcapPath, string? displayFilter = null, CancellationToken ct = default) =>
        Task.Run(() => Filter(Load(pcapPath), displayFilter).Select(p => p.ToRow()).ToList(), ct);

    public Task<PacketDetail> GetDetailAsync(string pcapPath, int packetNumber, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            var dp = Load(pcapPath).FirstOrDefault(p => p.Raw.Number == packetNumber)
                     ?? throw new InvalidOperationException($"Packet {packetNumber} not found.");
            return new PacketDetail { Tree = dp.Tree, Bytes = dp.Raw.Data };
        }, ct);

    public Task<string> StatisticAsync(string pcapPath, string statistic, string? displayFilter = null, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            var packets = Filter(Load(pcapPath), displayFilter).ToList();
            string filterLine = $"Filter: {displayFilter}";
            return statistic switch
            {
                "io,phs"       => ProtocolHierarchy(packets, filterLine),
                "conv,tcp"     => Conversations("TCP", packets.Where(p => p.Transport == "tcp"), filterLine),
                "conv,udp"     => Conversations("UDP", packets.Where(p => p.Transport == "udp"), filterLine),
                "conv,ip"      => IpConversations(packets, filterLine),
                "endpoints,ip" => IpEndpoints(packets, filterLine),
                _ => throw new NotSupportedException($"The built-in engine does not provide the statistic \"{statistic}\"."),
            };
        }, ct);

    public Task<string> FollowStreamAsync(string pcapPath, string protocol, int streamIndex, CancellationToken ct = default) =>
        Task.Run(() => Follow(Load(pcapPath), protocol, streamIndex), ct);

    public Task<List<Packet>> ReadFileAsync(string pcapPath, int maxPackets = 0, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            IEnumerable<DissectedPacket> all = Load(pcapPath);
            if (maxPackets > 0) all = all.Take(maxPackets);
            return all.Select(ToPacket).ToList();
        }, ct);

    // ---- loading and filtering --------------------------------------------

    List<DissectedPacket> Load(string path)
    {
        lock (_gate)
        {
            var stamp = File.GetLastWriteTimeUtc(path);
            if (_cached != null && _cachedPath == path && _cachedStamp == stamp) return _cached;

            var raws = CaptureFileReader.Read(path);
            _cached = new CaptureDissector().DissectAll(raws);
            _cachedPath = path;
            _cachedStamp = stamp;
            return _cached;
        }
    }

    static IEnumerable<DissectedPacket> Filter(List<DissectedPacket> all, string? filter)
    {
        if (string.IsNullOrWhiteSpace(filter)) return all;
        Func<DissectedPacket, bool> test;
        try { test = DisplayFilter.Compile(filter); }
        catch (FormatException e) { throw new InvalidOperationException(e.Message); }
        return all.Where(test);
    }

    static Packet ToPacket(DissectedPacket dp)
    {
        var p = new Packet
        {
            Number = dp.Raw.Number,
            Length = dp.Raw.OriginalLength,
            Time = DateTimeOffset.FromUnixTimeMilliseconds((long)(dp.Raw.Time * 1000)),
            Source = dp.SrcAddr, Destination = dp.DstAddr,
            SourcePort = dp.SrcPort, DestinationPort = dp.DstPort,
            Info = dp.Info,
            StreamKey = dp.Transport != null ? $"{dp.Transport}:{dp.StreamIndex}" : null,
        };
        foreach (var proto in dp.Chain)
        {
            var layer = new Layer { Name = proto };
            foreach (var (name, values) in dp.Fields)
                if (name.StartsWith(proto + ".", StringComparison.Ordinal))
                    layer.Fields.Add(new Field(name, values[0], 0));
            p.Layers.Add(layer);
        }
        return p;
    }

    // ---- statistics -------------------------------------------------------

    const string Rule = "===================================================================";

    static string ProtocolHierarchy(List<DissectedPacket> packets, string filterLine)
    {
        // Count frames and bytes at every prefix of each packet's protocol chain.
        var counts = new Dictionary<string, (int frames, long bytes)>();
        var order = new List<string>();
        foreach (var p in packets)
        {
            for (int depth = 1; depth <= p.Chain.Count; depth++)
            {
                string key = string.Join("/", p.Chain.Take(depth));
                if (!counts.TryGetValue(key, out var c)) order.Add(key);
                counts[key] = (c.frames + 1, c.bytes + p.Raw.OriginalLength);
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine(Rule).AppendLine("Protocol Hierarchy Statistics").AppendLine(filterLine).AppendLine();
        foreach (var key in order.OrderBy(k => k.Split('/').Length).ThenBy(k => order.IndexOf(k)).OrderBy(k => HierarchySortKey(k, order)))
        {
            var parts = key.Split('/');
            string label = new string(' ', (parts.Length - 1) * 2) + parts[^1];
            sb.AppendLine($"{label,-40} frames:{counts[key].frames} bytes:{counts[key].bytes}");
        }
        sb.AppendLine(Rule);
        return sb.ToString();
    }

    /// <summary>Sorts a hierarchy so every child sits directly under its parent, in first-seen order.</summary>
    static string HierarchySortKey(string key, List<string> order)
    {
        var parts = key.Split('/');
        var sb = new StringBuilder();
        for (int d = 1; d <= parts.Length; d++)
            sb.Append(order.IndexOf(string.Join("/", parts.Take(d))).ToString("D6"));
        return sb.ToString();
    }

    static string Conversations(string title, IEnumerable<DissectedPacket> packets, string filterLine)
    {
        var groups = packets.GroupBy(p => p.StreamIndex).OrderBy(g => g.Key).ToList();
        var sb = new StringBuilder();
        sb.AppendLine(Rule).AppendLine($"{title} Conversations").AppendLine(filterLine);
        sb.AppendLine($"{"Stream",-7}{"Address A",-26}{"Address B",-26}{"Frames",8}{"Bytes",9}{"A->B",7}{"B->A",7}{"Start",12}{"Duration",11}");
        foreach (var g in groups)
        {
            var first = g.First();
            string a = $"{first.SrcAddr}:{first.SrcPort}", b = $"{first.DstAddr}:{first.DstPort}";
            int ab = g.Count(p => p.Direction == 0), ba = g.Count() - ab;
            double start = g.Min(p => p.RelativeTime), dur = g.Max(p => p.RelativeTime) - start;
            sb.AppendLine($"{g.Key,-7}{a,-26}{b,-26}{g.Count(),8}{g.Sum(p => (long)p.Raw.OriginalLength),9}{ab,7}{ba,7}" +
                          $"{start.ToString("0.000000", CultureInfo.InvariantCulture),12}{dur.ToString("0.0000", CultureInfo.InvariantCulture),11}");
        }
        if (groups.Count == 0) sb.AppendLine("(no conversations)");
        sb.AppendLine(Rule);
        return sb.ToString();
    }

    static string IpConversations(List<DissectedPacket> packets, string filterLine)
    {
        var groups = packets.Where(p => p.SrcAddr != null && p.DstAddr != null)
            .GroupBy(p => string.CompareOrdinal(p.SrcAddr, p.DstAddr) <= 0 ? (p.SrcAddr!, p.DstAddr!) : (p.DstAddr!, p.SrcAddr!));
        var sb = new StringBuilder();
        sb.AppendLine(Rule).AppendLine("IPv4/IPv6 Conversations").AppendLine(filterLine);
        sb.AppendLine($"{"Address A",-30}{"Address B",-30}{"Frames",8}{"Bytes",9}{"Start",12}");
        foreach (var g in groups.OrderBy(g => g.Min(p => p.RelativeTime)))
            sb.AppendLine($"{g.Key.Item1,-30}{g.Key.Item2,-30}{g.Count(),8}{g.Sum(p => (long)p.Raw.OriginalLength),9}" +
                          $"{g.Min(p => p.RelativeTime).ToString("0.000000", CultureInfo.InvariantCulture),12}");
        sb.AppendLine(Rule);
        return sb.ToString();
    }

    static string IpEndpoints(List<DissectedPacket> packets, string filterLine)
    {
        var stats = new Dictionary<string, (int tx, long txBytes, int rx, long rxBytes)>();
        foreach (var p in packets)
        {
            if (p.SrcAddr == null || p.DstAddr == null) continue;
            stats.TryGetValue(p.SrcAddr, out var s); stats[p.SrcAddr] = (s.tx + 1, s.txBytes + p.Raw.OriginalLength, s.rx, s.rxBytes);
            stats.TryGetValue(p.DstAddr, out var r); stats[p.DstAddr] = (r.tx, r.txBytes, r.rx + 1, r.rxBytes + p.Raw.OriginalLength);
        }
        var sb = new StringBuilder();
        sb.AppendLine(Rule).AppendLine("IPv4/IPv6 Endpoints").AppendLine(filterLine);
        sb.AppendLine($"{"Address",-34}{"Packets",9}{"Bytes",10}{"Tx Pkts",9}{"Tx Bytes",10}{"Rx Pkts",9}{"Rx Bytes",10}");
        foreach (var (addr, s) in stats.OrderByDescending(kv => kv.Value.tx + kv.Value.rx))
            sb.AppendLine($"{addr,-34}{s.tx + s.rx,9}{s.txBytes + s.rxBytes,10}{s.tx,9}{s.txBytes,10}{s.rx,9}{s.rxBytes,10}");
        sb.AppendLine(Rule);
        return sb.ToString();
    }

    // ---- Follow Stream ----------------------------------------------------

    static string Follow(List<DissectedPacket> all, string protocol, int stream)
    {
        var packets = all.Where(p => p.Transport == protocol && p.StreamIndex == stream).ToList();
        if (packets.Count == 0) throw new InvalidOperationException($"No {protocol.ToUpper()} stream {stream} in this capture.");

        var first = packets[0];
        var sb = new StringBuilder();
        sb.AppendLine(Rule).AppendLine($"Follow: {protocol},ascii").AppendLine($"Filter: {protocol}.stream eq {stream}");
        sb.AppendLine($"Node 0: {first.SrcAddr}:{first.SrcPort}");
        sb.AppendLine($"Node 1: {first.DstAddr}:{first.DstPort}");

        // Reassemble each direction in sequence order, skipping retransmitted bytes.
        var next = new long[] { -1, -1 };
        int currentDir = -1;
        var chunk = new StringBuilder();
        void Flush()
        {
            if (currentDir < 0 || chunk.Length == 0) return;
            string text = chunk.ToString();
            sb.AppendLine(text.Length.ToString());
            sb.AppendLine(currentDir == 1 ? "\t" + text.Replace("\n", "\n\t") : text);
            chunk.Clear();
        }

        foreach (var p in packets)
        {
            if (p.Payload == null) continue;
            byte[] data = p.Payload;
            int skip = 0;
            if (protocol == "tcp")
            {
                if (next[p.Direction] >= 0 && p.RelativeSeq < next[p.Direction])
                    skip = (int)Math.Min(data.Length, next[p.Direction] - p.RelativeSeq);
                next[p.Direction] = Math.Max(next[p.Direction], p.RelativeSeq + data.Length);
            }
            if (skip >= data.Length) continue;

            if (p.Direction != currentDir) { Flush(); currentDir = p.Direction; }
            foreach (byte b in data.AsSpan(skip))
                chunk.Append(b == '\n' || b == '\r' || (b >= 32 && b < 127) ? (char)b : '.');
        }
        Flush();
        sb.AppendLine(Rule);
        return sb.ToString();
    }
}
