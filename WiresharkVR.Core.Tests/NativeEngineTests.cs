using System.Buffers.Binary;
using WiresharkVR.Core;
using WiresharkVR.Core.Native;
using Xunit;
using Xunit.Abstractions;

namespace WiresharkVR.Core.Tests;

/// <summary>Checks the built-in dissector against real Wireshark (tshark) output.</summary>
public class NativeEngineTests
{
    readonly ITestOutputHelper _out;
    public NativeEngineTests(ITestOutputHelper output) => _out = output;

    static string Sample()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "samples", "loopback-http.pcapng")))
            dir = dir.Parent;
        return Path.Combine(dir!.FullName, "samples", "loopback-http.pcapng");
    }

    // ---- crafted capture: ARP, ICMP echo, UDP, DNS query and compressed response ----

    static readonly byte[] MacA = { 0x02, 0, 0, 0, 0, 0x0A }, MacB = { 0x02, 0, 0, 0, 0, 0x0B };
    static readonly byte[] IpA = { 192, 168, 1, 50 }, IpB = { 192, 168, 1, 1 };

    static byte[] Eth(byte[] dst, byte[] src, ushort type, byte[] payload) =>
        dst.Concat(src).Concat(new[] { (byte)(type >> 8), (byte)type }).Concat(payload).ToArray();

    static byte[] Ip4(byte[] src, byte[] dst, byte proto, byte[] payload, byte ttl = 64)
    {
        var h = new byte[20];
        h[0] = 0x45; h[8] = ttl; h[9] = proto;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), (ushort)(20 + payload.Length));
        src.CopyTo(h, 12); dst.CopyTo(h, 16);
        return h.Concat(payload).ToArray();
    }

    static byte[] Udp(ushort sp, ushort dp, byte[] payload)
    {
        var h = new byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(h, sp); BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), dp);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), (ushort)(8 + payload.Length));
        return h.Concat(payload).ToArray();
    }

    static byte[] DnsName(string name) =>
        name.Split('.').SelectMany(l => new[] { (byte)l.Length }.Concat(System.Text.Encoding.ASCII.GetBytes(l))).Append((byte)0).ToArray();

    static List<byte[]> CraftedFrames()
    {
        var frames = new List<byte[]>();

        // 1. ARP request: who has 192.168.1.1? tell 192.168.1.50
        var arp = new byte[28];
        arp[1] = 1; arp[2] = 0x08; arp[4] = 6; arp[5] = 4; arp[7] = 1;
        MacA.CopyTo(arp, 8); IpA.CopyTo(arp, 14); IpB.CopyTo(arp, 24);
        frames.Add(Eth(new byte[] { 255, 255, 255, 255, 255, 255 }, MacA, 0x0806, arp));

        // 2. ICMP echo request, id 1, seq 1
        var icmp = new byte[] { 8, 0, 0, 0, 0, 1, 0, 1, 0xAA, 0xBB };
        frames.Add(Eth(MacB, MacA, 0x0800, Ip4(IpA, IpB, 1, icmp)));

        // 3. DNS query for example.com (A)
        var query = new byte[] { 0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0 }
            .Concat(DnsName("example.com")).Concat(new byte[] { 0, 1, 0, 1 }).ToArray();
        frames.Add(Eth(MacB, MacA, 0x0800, Ip4(IpA, IpB, 17, Udp(54321, 53, query))));

        // 4. DNS response with one A answer using a compression pointer back to the question name
        var response = new byte[] { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 }
            .Concat(DnsName("example.com")).Concat(new byte[] { 0, 1, 0, 1 })
            .Concat(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 93, 184, 216, 34 }).ToArray();
        frames.Add(Eth(MacA, MacB, 0x0800, Ip4(IpB, IpA, 17, Udp(53, 54321, response))));

        // 5. Plain UDP datagram with an unknown payload
        frames.Add(Eth(MacB, MacA, 0x0800, Ip4(IpA, IpB, 17, Udp(40000, 9999, new byte[] { 1, 2, 3, 4, 5 }))));
        return frames;
    }

    static string WritePcap(IEnumerable<byte[]> frames)
    {
        string path = Path.Combine(Path.GetTempPath(), $"wsvr-{Guid.NewGuid():N}.pcap");
        using var fs = File.Create(path);
        var gh = new byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(gh, 0xA1B2C3D4);
        BinaryPrimitives.WriteUInt16LittleEndian(gh.AsSpan(4), 2); BinaryPrimitives.WriteUInt16LittleEndian(gh.AsSpan(6), 4);
        BinaryPrimitives.WriteUInt32LittleEndian(gh.AsSpan(16), 65535); BinaryPrimitives.WriteUInt32LittleEndian(gh.AsSpan(20), 1);
        fs.Write(gh);
        uint sec = 1_700_000_000;
        foreach (var f in frames)
        {
            var rh = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(rh, sec++);
            BinaryPrimitives.WriteUInt32LittleEndian(rh.AsSpan(8), (uint)f.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(rh.AsSpan(12), (uint)f.Length);
            fs.Write(rh); fs.Write(f);
        }
        return path;
    }

    // ---- tests ----

    [Fact]
    public async Task SampleListMatchesTshark()
    {
        var native = await new NativeEngine().ListPacketsAsync(Sample());
        var tshark = await new TsharkRunner().ListPacketsAsync(Sample());
        Assert.Equal(tshark.Count, native.Count);

        // Packets 6 and 8 are an HTTP response that tshark reassembles across two segments,
        // which the built-in engine deliberately does not attempt.
        var problems = new List<string>();
        for (int i = 0; i < tshark.Count; i++)
        {
            if (tshark[i].Number is 6 or 8) continue;
            var t = tshark[i]; var n = native[i];
            if (t.Source != n.Source) problems.Add($"#{t.Number} source: {t.Source} vs {n.Source}");
            if (t.Destination != n.Destination) problems.Add($"#{t.Number} dest: {t.Destination} vs {n.Destination}");
            if (t.Protocol != n.Protocol) problems.Add($"#{t.Number} protocol: {t.Protocol} vs {n.Protocol}");
            if (t.Length != n.Length) problems.Add($"#{t.Number} length: {t.Length} vs {n.Length}");
            if (t.Info != n.Info) problems.Add($"#{t.Number} info: [{t.Info}] vs [{n.Info}]");
            if (Math.Abs(t.RelativeTime - n.RelativeTime) > 1e-5) problems.Add($"#{t.Number} time: {t.RelativeTime} vs {n.RelativeTime}");
        }
        foreach (var p in problems) _out.WriteLine(p);
        Assert.Empty(problems);
    }

    [Fact]
    public async Task CraftedPacketsMatchTshark()
    {
        string path = WritePcap(CraftedFrames());
        try
        {
            var native = await new NativeEngine().ListPacketsAsync(path);
            var tshark = await new TsharkRunner().ListPacketsAsync(path);
            Assert.Equal(tshark.Count, native.Count);

            var problems = new List<string>();
            for (int i = 0; i < tshark.Count; i++)
            {
                var t = tshark[i]; var n = native[i];
                _out.WriteLine($"tshark: {t.Source} -> {t.Destination} {t.Protocol} {t.Length} [{t.Info}]");
                _out.WriteLine($"native: {n.Source} -> {n.Destination} {n.Protocol} {n.Length} [{n.Info}]");
                if (t.Source != n.Source) problems.Add($"#{t.Number} source: {t.Source} vs {n.Source}");
                if (t.Destination != n.Destination) problems.Add($"#{t.Number} dest: {t.Destination} vs {n.Destination}");
                if (t.Protocol != n.Protocol) problems.Add($"#{t.Number} protocol: {t.Protocol} vs {n.Protocol}");
                if (t.Info != n.Info) problems.Add($"#{t.Number} info: [{t.Info}] vs [{n.Info}]");
            }
            Assert.Empty(problems);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task ClassicPcapIsReadSameAsPcapng()
    {
        var raws = CaptureFileReader.Read(Sample());
        string path = WritePcap(raws.Select(r => r.Data));
        try
        {
            Assert.Equal(10, raws.Count);
            Assert.Equal(10, CaptureFileReader.Read(path).Count);
            Assert.Equal(raws[3].Data, CaptureFileReader.Read(path)[3].Data);
        }
        finally { File.Delete(path); }
        await Task.CompletedTask;
    }

    [Fact]
    public async Task DetailLabelsMatchTshark()
    {
        var native = await new NativeEngine().GetDetailAsync(Sample(), 4);
        var tshark = await new TsharkRunner().GetDetailAsync(Sample(), 4);

        string Label(PacketDetail d, string prefix) => d.Tree.First(n => n.Label.StartsWith(prefix)).Label;
        Assert.Equal(Label(tshark, "Transmission Control Protocol"), Label(native, "Transmission Control Protocol"));
        Assert.Equal(Label(tshark, "Internet Protocol Version 6"), Label(native, "Internet Protocol Version 6"));
        Assert.Equal(tshark.Bytes, native.Bytes);

        var src = native.Find("tcp.srcport");
        Assert.NotNull(src);
        Assert.Equal("49931", src!.Show);
        Assert.Equal(2, src.Size);
    }

    [Fact]
    public async Task DisplayFiltersWork()
    {
        var engine = new NativeEngine();
        string path = WritePcap(CraftedFrames());
        try
        {
            async Task<int> Count(string f) => (await engine.ListPacketsAsync(path, f)).Count;
            Assert.Equal(5, await Count(""));
            Assert.Equal(1, await Count("arp"));
            Assert.Equal(2, await Count("dns"));
            Assert.Equal(3, await Count("udp"));
            Assert.Equal(4, await Count("ip.addr == 192.168.1.50"));
            Assert.Equal(1, await Count("ip.addr == 192.168.1.50 && udp.port == 9999"));
            Assert.Equal(1, await Count("dns && !(udp.dstport == 53)")); // only the response
            Assert.Equal(1, await Count("dns.qry.name contains \"example\" and ip.src == 192.168.1.1"));
            Assert.Equal(4, await Count("ip.addr == 192.168.1.0/24"));
            Assert.Equal(1, await Count("icmp"));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task BadFilterExplainsItself()
    {
        var engine = new NativeEngine();
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => engine.ListPacketsAsync(Sample(), "tcp.nonsense == 1"));
        Assert.Contains("not a valid protocol or protocol field", ex.Message);
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.ListPacketsAsync(Sample(), "tcp.port == "));
        await Assert.ThrowsAsync<InvalidOperationException>(() => engine.ListPacketsAsync(Sample(), "(tcp"));
    }

    [Fact]
    public async Task StatsAndFollowStreamWork()
    {
        var engine = new NativeEngine();
        var phs = await engine.StatisticAsync(Sample(), "io,phs");
        Assert.Contains("frames:10", phs);
        Assert.Contains("http", phs);

        var follow = await engine.FollowStreamAsync(Sample(), "tcp", 0);
        Assert.Contains("GET /hello HTTP/1.1", follow);

        var conv = await engine.StatisticAsync(Sample(), "conv,tcp");
        Assert.Contains("49931", conv);
    }

    [Fact]
    public void EveryEmittedFieldIsInTheFilterCatalog()
    {
        var missing = new HashSet<string>();
        foreach (var dp in new CaptureDissector().DissectAll(CaptureFileReader.Read(Sample())))
            foreach (var name in dp.Fields.Keys.Where(k => k != "http"))
                if (!DisplayFilter.Fields.Contains(name)) missing.Add(name);
        Assert.Empty(missing);
    }
}
