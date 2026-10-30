using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Text;

namespace WiresharkVR.Core.Native;

/// <summary>One packet after dissection: the details tree, the list-row columns, and filterable fields.</summary>
public sealed class DissectedPacket
{
    public required RawPacket Raw { get; init; }
    public double RelativeTime { get; set; }

    public List<DetailNode> Tree { get; } = new();
    /// <summary>Protocols present, outermost first, using Wireshark's short names ("eth", "ip", "tcp", "http").</summary>
    public List<string> Chain { get; } = new() { "frame" };
    /// <summary>Field name to value(s), used by display filters.</summary>
    public Dictionary<string, List<string>> Fields { get; } = new();

    public string Source { get; set; } = "";
    public string Destination { get; set; } = "";
    public string? SrcAddr { get; set; }
    public string? DstAddr { get; set; }
    public string? SrcPort { get; set; }
    public string? DstPort { get; set; }
    public string Protocol { get; set; } = "";
    public string Info { get; set; } = "";

    /// <summary>"tcp" or "udp" when the packet belongs to a stream.</summary>
    public string? Transport { get; set; }
    public int StreamIndex { get; set; } = -1;
    public int Direction { get; set; }
    public uint RelativeSeq { get; set; }
    public byte[]? Payload { get; set; }

    public void Add(string name, string value)
    {
        if (!Fields.TryGetValue(name, out var list)) Fields[name] = list = new List<string>();
        list.Add(value);
    }

    public PacketRow ToRow() =>
        new(Raw.Number, RelativeTime, Source, Destination, Protocol, Raw.OriginalLength, Info);
}

/// <summary>
/// Pure C# protocol dissector: Null/Loopback, Ethernet (+VLAN), ARP, IPv4, IPv6, ICMP, ICMPv6, TCP, UDP, DNS, HTTP.
/// It is stateful because TCP sequence numbers are shown relative to each stream's start, as Wireshark does.
/// </summary>
public sealed class CaptureDissector
{
    sealed class StreamState
    {
        public int Index;
        public string EndpointA = "";
        public uint[] Base = new uint[2];
        public bool[] HaveBase = new bool[2];
        public int[] WindowShift = { -1, -1 };
    }

    readonly Dictionary<string, StreamState> _tcp = new();
    readonly Dictionary<string, StreamState> _udp = new();

    public List<DissectedPacket> DissectAll(IReadOnlyList<RawPacket> raws)
    {
        var result = new List<DissectedPacket>(raws.Count);
        double first = raws.Count > 0 ? raws[0].Time : 0;
        foreach (var raw in raws)
        {
            result.Add(Dissect(raw, raw.Time - first));

        }
        return result;
    }

    /// <summary>Dissects the next packet of a capture; packets must arrive in capture order.</summary>
    public DissectedPacket Dissect(RawPacket raw, double relativeTime)
    {
        var dp = new DissectedPacket { Raw = raw, RelativeTime = relativeTime };
        try
        {
            switch (raw.LinkType)
            {
                case 0:   Null(dp); break;
                case 1:   Ethernet(dp, 0); break;
                case 12: case 14: case 101: RawIp(dp, 0); break;
                case 113: LinuxCooked(dp); break;
                default:  dp.Protocol = $"LINKTYPE {raw.LinkType}"; break;
            }
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            dp.Tree.Add(N("[Malformed Packet: truncated]", 0, raw.Data.Length));
            dp.Info = "[Malformed Packet]";
        }
        FinishFrame(dp);
        return dp;
    }

    // ======================================================================
    // Frame
    // ======================================================================

    static void FinishFrame(DissectedPacket dp)
    {
        var r = dp.Raw;
        var when = DateTimeOffset.FromUnixTimeMilliseconds((long)(r.Time * 1000)).ToLocalTime();
        var frame = N($"Frame {r.Number}: Packet, {r.OriginalLength} bytes on wire ({r.OriginalLength * 8} bits), " +
                      $"{r.Data.Length} bytes captured ({r.Data.Length * 8} bits)", 0, r.Data.Length);
        frame.Children.Add(N($"Arrival Time: {when:MMM d, yyyy HH:mm:ss.ffffff}", 0, 0, "frame.time"));
        frame.Children.Add(N($"[Time since first frame in this capture: {dp.RelativeTime:0.000000000} seconds]", 0, 0, "frame.time_relative", dp.RelativeTime.ToString("0.000000000", CultureInfo.InvariantCulture)));
        frame.Children.Add(N($"Frame Number: {r.Number}", 0, 0, "frame.number", r.Number.ToString()));
        frame.Children.Add(N($"Frame Length: {r.OriginalLength} bytes ({r.OriginalLength * 8} bits)", 0, 0, "frame.len", r.OriginalLength.ToString()));
        frame.Children.Add(N($"Capture Length: {r.Data.Length} bytes ({r.Data.Length * 8} bits)", 0, 0, "frame.cap_len", r.Data.Length.ToString()));
        frame.Children.Add(N($"[Protocols in frame: {string.Join(":", dp.Chain.Skip(1))}]", 0, 0, "frame.protocols", string.Join(":", dp.Chain.Skip(1))));
        dp.Tree.Insert(0, frame);

        dp.Add("frame.number", r.Number.ToString());
        dp.Add("frame.len", r.OriginalLength.ToString());
        dp.Add("frame.cap_len", r.Data.Length.ToString());
        dp.Add("frame.time_relative", dp.RelativeTime.ToString("0.000000000", CultureInfo.InvariantCulture));
        if (dp.Info.Length == 0) dp.Info = dp.Protocol;
    }

    // ======================================================================
    // Link layers
    // ======================================================================

    void Null(DissectedPacket dp)
    {
        var d = dp.Raw.Data;
        uint family = BinaryPrimitives.ReadUInt32LittleEndian(d);
        if (family > 255) family = BinaryPrimitives.ReadUInt32BigEndian(d);
        bool v6 = family is 24 or 28 or 30 or 10 or 23;
        string name = family == 2 ? "IPv4" : v6 ? "IPv6" : "Unknown";

        dp.Chain.Add("null");
        var node = N("Null/Loopback", 0, 4);
        node.Children.Add(N($"Family: {name} ({family})", 0, 4, "null.family", family.ToString()));
        dp.Tree.Add(node);

        if (family == 2) Ip4(dp, 4);
        else if (v6) Ip6(dp, 4);
        else dp.Protocol = "Loopback";
    }

    void LinuxCooked(DissectedPacket dp)
    {
        var d = dp.Raw.Data;
        int type = U16(d, 14);
        dp.Chain.Add("sll");
        dp.Tree.Add(N("Linux cooked capture v1", 0, 16));
        DispatchEtherType(dp, type, 16);
    }

    void RawIp(DissectedPacket dp, int off)
    {
        int version = dp.Raw.Data[off] >> 4;
        if (version == 4) Ip4(dp, off);
        else if (version == 6) Ip6(dp, off);
        else dp.Protocol = "Raw IP";
    }

    void Ethernet(DissectedPacket dp, int off)
    {
        var d = dp.Raw.Data;
        string dst = Mac(d, off), src = Mac(d, off + 6);
        int type = U16(d, off + 12);
        int payload = off + 14;

        dp.Chain.Add("eth");
        dp.Source = src; dp.Destination = Friendly(dst);
        var node = N($"Ethernet II, Src: {src}, Dst: {dst}", off, 14);
        node.Children.Add(N($"Destination: {dst}", off, 6, "eth.dst", dst));
        node.Children.Add(N($"Source: {src}", off + 6, 6, "eth.src", src));
        dp.Add("eth.dst", dst); dp.Add("eth.src", src); dp.Add("eth.addr", dst); dp.Add("eth.addr", src);

        if (type == 0x8100 && d.Length >= off + 18) // 802.1Q VLAN tag
        {
            int tci = U16(d, off + 14);
            node.Children.Add(N($"Type: 802.1Q Virtual LAN (0x8100)", off + 12, 2));
            dp.Tree.Add(node);
            dp.Chain.Add("vlan");
            dp.Tree.Add(N($"802.1Q Virtual LAN, PRI: {tci >> 13}, DEI: {(tci >> 12) & 1}, ID: {tci & 0xFFF}", off + 14, 4));
            dp.Add("vlan.id", (tci & 0xFFF).ToString());
            type = U16(d, off + 16);
            payload = off + 18;
        }
        else
        {
            node.Children.Add(N($"Type: {EtherTypeName(type)} (0x{type:x4})", off + 12, 2, "eth.type", $"0x{type:x4}"));
            dp.Tree.Add(node);
        }
        DispatchEtherType(dp, type, payload);
    }

    void DispatchEtherType(DissectedPacket dp, int type, int off)
    {
        switch (type)
        {
            case 0x0800: Ip4(dp, off); break;
            case 0x86DD: Ip6(dp, off); break;
            case 0x0806: Arp(dp, off); break;
            default: dp.Protocol = type == 0x88CC ? "LLDP" : $"0x{type:x4}"; break;
        }
    }

    // ======================================================================
    // ARP
    // ======================================================================

    void Arp(DissectedPacket dp, int off)
    {
        var d = dp.Raw.Data;
        int op = U16(d, off + 6);
        string sha = Mac(d, off + 8), spa = Ip4Text(d, off + 14), tha = Mac(d, off + 18), tpa = Ip4Text(d, off + 24);

        dp.Chain.Add("arp");
        dp.Protocol = "ARP";
        dp.Info = op == 1 ? $"Who has {tpa}? Tell {spa}" : op == 2 ? $"{spa} is at {sha}" : $"ARP opcode {op}";

        var node = N($"Address Resolution Protocol ({(op == 1 ? "request" : op == 2 ? "reply" : "opcode " + op)})", off, 28);
        node.Children.Add(N($"Hardware type: Ethernet ({U16(d, off)})", off, 2, "arp.hw.type", U16(d, off).ToString()));
        node.Children.Add(N($"Protocol type: {EtherTypeName(U16(d, off + 2))} (0x{U16(d, off + 2):x4})", off + 2, 2));
        node.Children.Add(N($"Opcode: {(op == 1 ? "request" : op == 2 ? "reply" : "other")} ({op})", off + 6, 2, "arp.opcode", op.ToString()));
        node.Children.Add(N($"Sender MAC address: {sha}", off + 8, 6, "arp.src.hw_mac", sha));
        node.Children.Add(N($"Sender IP address: {spa}", off + 14, 4, "arp.src.proto_ipv4", spa));
        node.Children.Add(N($"Target MAC address: {tha}", off + 18, 6, "arp.dst.hw_mac", tha));
        node.Children.Add(N($"Target IP address: {tpa}", off + 24, 4, "arp.dst.proto_ipv4", tpa));
        dp.Tree.Add(node);
        dp.Add("arp.opcode", op.ToString());
        dp.Add("arp.src.proto_ipv4", spa);
        dp.Add("arp.dst.proto_ipv4", tpa);
    }

    // ======================================================================
    // IP
    // ======================================================================

    void Ip4(DissectedPacket dp, int off)
    {
        var d = dp.Raw.Data;
        int ihl = (d[off] & 0xF) * 4;
        int total = U16(d, off + 2);
        int end = Math.Min(d.Length, total >= ihl && total > 0 ? off + total : d.Length);
        int ttl = d[off + 8], proto = d[off + 9];
        string src = Ip4Text(d, off + 12), dst = Ip4Text(d, off + 16);

        dp.Chain.Add("ip");
        dp.SrcAddr = src; dp.DstAddr = dst; dp.Source = src; dp.Destination = dst; dp.Protocol = "IPv4";
        dp.Add("ip.src", src); dp.Add("ip.dst", dst); dp.Add("ip.addr", src); dp.Add("ip.addr", dst);
        dp.Add("ip.proto", proto.ToString()); dp.Add("ip.ttl", ttl.ToString()); dp.Add("ip.len", total.ToString());
        dp.Add("ip.version", "4");

        int flags = d[off + 6] >> 5;
        var node = N($"Internet Protocol Version 4, Src: {src}, Dst: {dst}", off, ihl);
        node.Children.Add(N($"0100 .... = Version: 4", off, 1, "ip.version", "4"));
        node.Children.Add(N($".... {Convert.ToString(ihl / 4, 2).PadLeft(4, '0')} = Header Length: {ihl} bytes ({ihl / 4})", off, 1, "ip.hdr_len", ihl.ToString()));
        node.Children.Add(N($"Differentiated Services Field: 0x{d[off + 1]:x2}", off + 1, 1, "ip.dsfield", $"0x{d[off + 1]:x2}"));
        node.Children.Add(N($"Total Length: {total}", off + 2, 2, "ip.len", total.ToString()));
        node.Children.Add(N($"Identification: 0x{U16(d, off + 4):x4} ({U16(d, off + 4)})", off + 4, 2, "ip.id", $"0x{U16(d, off + 4):x4}"));
        node.Children.Add(N($"Flags: 0x{flags:x2}{((flags & 2) != 0 ? ", Don't fragment" : "")}{((flags & 1) != 0 ? ", More fragments" : "")}", off + 6, 1, "ip.flags", $"0x{flags:x2}"));
        node.Children.Add(N($"Fragment Offset: {U16(d, off + 6) & 0x1FFF}", off + 6, 2, "ip.frag_offset", (U16(d, off + 6) & 0x1FFF).ToString()));
        node.Children.Add(N($"Time to Live: {ttl}", off + 8, 1, "ip.ttl", ttl.ToString()));
        node.Children.Add(N($"Protocol: {IpProtoName(proto)} ({proto})", off + 9, 1, "ip.proto", proto.ToString()));
        node.Children.Add(N($"Header Checksum: 0x{U16(d, off + 10):x4}", off + 10, 2, "ip.checksum", $"0x{U16(d, off + 10):x4}"));
        node.Children.Add(N($"Source Address: {src}", off + 12, 4, "ip.src", src));
        node.Children.Add(N($"Destination Address: {dst}", off + 16, 4, "ip.dst", dst));
        dp.Tree.Add(node);

        // A fragment that is not the first has no transport header to read.
        if ((U16(d, off + 6) & 0x1FFF) != 0) { dp.Protocol = "IPv4"; dp.Info = "Fragmented IP protocol"; return; }
        Transport(dp, proto, off + ihl, end, v6: false, ttl);
    }

    void Ip6(DissectedPacket dp, int off)
    {
        var d = dp.Raw.Data;
        int payloadLen = U16(d, off + 4);
        int end = Math.Min(d.Length, payloadLen > 0 ? off + 40 + payloadLen : d.Length);
        int next = d[off + 6], hop = d[off + 7];
        string src = Ip6Text(d, off + 8), dst = Ip6Text(d, off + 24);
        uint vtf = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(off));

        dp.Chain.Add("ipv6");
        dp.SrcAddr = src; dp.DstAddr = dst; dp.Source = src; dp.Destination = dst; dp.Protocol = "IPv6";
        dp.Add("ipv6.src", src); dp.Add("ipv6.dst", dst); dp.Add("ipv6.addr", src); dp.Add("ipv6.addr", dst);
        dp.Add("ipv6.nxt", next.ToString()); dp.Add("ipv6.hlim", hop.ToString()); dp.Add("ipv6.plen", payloadLen.ToString());

        var node = N($"Internet Protocol Version 6, Src: {src}, Dst: {dst}", off, 40);
        node.Children.Add(N("0110 .... = Version: 6", off, 1, "ipv6.version", "6"));
        node.Children.Add(N($"Traffic Class: 0x{(vtf >> 20) & 0xFF:x2}", off, 2, "ipv6.tclass", $"0x{(vtf >> 20) & 0xFF:x2}"));
        node.Children.Add(N($"Flow Label: 0x{vtf & 0xFFFFF:x5}", off + 1, 3, "ipv6.flow", $"0x{vtf & 0xFFFFF:x5}"));
        node.Children.Add(N($"Payload Length: {payloadLen}", off + 4, 2, "ipv6.plen", payloadLen.ToString()));
        node.Children.Add(N($"Next Header: {IpProtoName(next)} ({next})", off + 6, 1, "ipv6.nxt", next.ToString()));
        node.Children.Add(N($"Hop Limit: {hop}", off + 7, 1, "ipv6.hlim", hop.ToString()));
        node.Children.Add(N($"Source Address: {src}", off + 8, 16, "ipv6.src", src));
        node.Children.Add(N($"Destination Address: {dst}", off + 24, 16, "ipv6.dst", dst));
        dp.Tree.Add(node);

        int p = off + 40;
        while (next is 0 or 43 or 60 && p + 8 <= end) // skip hop-by-hop, routing, destination-options headers
        {
            int len = (d[p + 1] + 1) * 8;
            next = d[p];
            p += len;
        }
        Transport(dp, next, p, end, v6: true, hop);
    }

    void Transport(DissectedPacket dp, int proto, int off, int end, bool v6, int ttl)
    {
        switch (proto)
        {
            case 6:  Tcp(dp, off, end); break;
            case 17: Udp(dp, off, end); break;
            case 1 when !v6:  Icmp(dp, off, end, ttl); break;
            case 58 when v6:  Icmp6(dp, off, end); break;
            default: dp.Protocol = IpProtoName(proto) is var n && n != "Unknown" ? n : dp.Protocol; break;
        }
    }

    // ======================================================================
    // ICMP / ICMPv6
    // ======================================================================

    void Icmp(DissectedPacket dp, int off, int end, int ttl)
    {
        var d = dp.Raw.Data;
        int type = d[off], code = d[off + 1];
        dp.Chain.Add("icmp"); dp.Protocol = "ICMP";
        dp.Add("icmp.type", type.ToString()); dp.Add("icmp.code", code.ToString());

        string text;
        if (type is 0 or 8)
        {
            int id = U16(d, off + 4), seq = U16(d, off + 6);
            int swapped = ((seq & 0xFF) << 8) | (seq >> 8);
            text = $"Echo (ping) {(type == 8 ? "request" : "reply")}  id=0x{id:x4}, seq={seq}/{swapped}, ttl={ttl}";
        }
        else if (type == 3)
        {
            string[] names = { "Network unreachable", "Host unreachable", "Protocol unreachable", "Port unreachable" };
            text = $"Destination unreachable ({(code < names.Length ? names[code] : "code " + code)})";
        }
        else if (type == 11) text = "Time-to-live exceeded";
        else text = $"Type: {type}, Code: {code}";

        dp.Info = text;
        var node = N("Internet Control Message Protocol", off, end - off);
        node.Children.Add(N($"Type: {type}", off, 1, "icmp.type", type.ToString()));
        node.Children.Add(N($"Code: {code}", off + 1, 1, "icmp.code", code.ToString()));
        node.Children.Add(N($"Checksum: 0x{U16(d, off + 2):x4}", off + 2, 2, "icmp.checksum", $"0x{U16(d, off + 2):x4}"));
        dp.Tree.Add(node);
    }

    void Icmp6(DissectedPacket dp, int off, int end)
    {
        var d = dp.Raw.Data;
        int type = d[off], code = d[off + 1];
        dp.Chain.Add("icmpv6"); dp.Protocol = "ICMPv6";
        dp.Add("icmpv6.type", type.ToString()); dp.Add("icmpv6.code", code.ToString());
        dp.Info = type switch
        {
            128 => "Echo (ping) request",
            129 => "Echo (ping) reply",
            133 => "Router Solicitation",
            134 => "Router Advertisement",
            135 => $"Neighbor Solicitation for {Ip6Text(d, off + 8)}",
            136 => $"Neighbor Advertisement {Ip6Text(d, off + 8)}",
            1 => "Destination unreachable",
            3 => "Time exceeded",
            _ => $"Type: {type}, Code: {code}",
        };
        var node = N("Internet Control Message Protocol v6", off, end - off);
        node.Children.Add(N($"Type: {type}", off, 1, "icmpv6.type", type.ToString()));
        node.Children.Add(N($"Code: {code}", off + 1, 1, "icmpv6.code", code.ToString()));
        node.Children.Add(N($"Checksum: 0x{U16(d, off + 2):x4}", off + 2, 2));
        dp.Tree.Add(node);
    }

    // ======================================================================
    // UDP and DNS
    // ======================================================================

    void Udp(DissectedPacket dp, int off, int end)
    {
        var d = dp.Raw.Data;
        int sp = U16(d, off), dpn = U16(d, off + 2), len = U16(d, off + 4);
        int payload = off + 8, payloadLen = Math.Max(0, Math.Min(end, off + len) - payload);

        string a = $"{dp.SrcAddr}:{sp}", b = $"{dp.DstAddr}:{dpn}";
        var st = Stream(_udp, a, b);
        dp.Transport = "udp"; dp.StreamIndex = st.Index; dp.Direction = a == st.EndpointA ? 0 : 1;
        dp.SrcPort = sp.ToString(); dp.DstPort = dpn.ToString();
        dp.Chain.Add("udp"); dp.Protocol = "UDP";
        dp.Info = $"{sp} → {dpn} Len={payloadLen}";
        dp.Add("udp.srcport", sp.ToString()); dp.Add("udp.dstport", dpn.ToString());
        dp.Add("udp.port", sp.ToString()); dp.Add("udp.port", dpn.ToString());
        dp.Add("udp.length", len.ToString()); dp.Add("udp.stream", st.Index.ToString());

        var node = N($"User Datagram Protocol, Src Port: {sp}, Dst Port: {dpn}", off, 8);
        node.Children.Add(N($"Source Port: {sp}", off, 2, "udp.srcport", sp.ToString()));
        node.Children.Add(N($"Destination Port: {dpn}", off + 2, 2, "udp.dstport", dpn.ToString()));
        node.Children.Add(N($"Length: {len}", off + 4, 2, "udp.length", len.ToString()));
        node.Children.Add(N($"Checksum: 0x{U16(d, off + 6):x4}", off + 6, 2, "udp.checksum", $"0x{U16(d, off + 6):x4}"));
        node.Children.Add(N($"[Stream index: {st.Index}]", 0, 0, "udp.stream", st.Index.ToString()));
        dp.Tree.Add(node);
        dp.Payload = payloadLen > 0 ? d.AsSpan(payload, payloadLen).ToArray() : null;

        if (payloadLen == 0) return;
        if ((sp == 53 || dpn == 53 || sp == 5353 || dpn == 5353) && payloadLen >= 12) Dns(dp, payload, payload + payloadLen, sp == 5353 || dpn == 5353);
        else DataNode(dp, payload, payloadLen);
    }

    static readonly Dictionary<int, string> DnsTypes = new()
    {
        [1] = "A", [2] = "NS", [5] = "CNAME", [6] = "SOA", [12] = "PTR", [15] = "MX",
        [16] = "TXT", [28] = "AAAA", [33] = "SRV", [65] = "HTTPS", [255] = "ANY",
    };

    void Dns(DissectedPacket dp, int off, int end, bool mdns)
    {
        var d = dp.Raw.Data;
        int id = U16(d, off), flags = U16(d, off + 2);
        int qd = U16(d, off + 4), an = U16(d, off + 6), ns = U16(d, off + 8), ar = U16(d, off + 10);
        bool response = (flags & 0x8000) != 0;
        int rcode = flags & 0xF;

        dp.Chain.Add("dns"); dp.Protocol = mdns ? "MDNS" : "DNS";
        var node = N($"Domain Name System ({(response ? "response" : "query")})", off, end - off);
        node.Children.Add(N($"Transaction ID: 0x{id:x4}", off, 2, "dns.id", $"0x{id:x4}"));
        node.Children.Add(N($"Flags: 0x{flags:x4} {(response ? "Standard query response" : "Standard query")}", off + 2, 2, "dns.flags", $"0x{flags:x4}"));
        node.Children.Add(N($"Questions: {qd}", off + 4, 2, "dns.count.queries", qd.ToString()));
        node.Children.Add(N($"Answer RRs: {an}", off + 6, 2, "dns.count.answers", an.ToString()));
        node.Children.Add(N($"Authority RRs: {ns}", off + 8, 2));
        node.Children.Add(N($"Additional RRs: {ar}", off + 10, 2));
        dp.Add("dns.id", $"0x{id:x4}"); dp.Add("dns.flags.response", response ? "1" : "0"); dp.Add("dns.flags.rcode", rcode.ToString());

        int pos = off + 12;
        string qname = "", qtypeName = "";
        var info = new StringBuilder();
        try
        {
            if (qd > 0)
            {
                var queries = N("Queries", pos, 0);
                for (int i = 0; i < qd; i++)
                {
                    int start = pos;
                    string name = ReadDnsName(d, off, ref pos);
                    int qtype = U16(d, pos); pos += 4; // type + class
                    string tn = DnsTypes.TryGetValue(qtype, out var t) ? t : $"TYPE{qtype}";
                    queries.Children.Add(N($"{name}: type {tn}", start, pos - start, "dns.qry.name", name));
                    dp.Add("dns.qry.name", name); dp.Add("dns.qry.type", qtype.ToString());
                    if (i == 0) { qname = name; qtypeName = tn; }
                }
                node.Children.Add(queries);
            }

            var answers = new List<string>();
            if (an > 0)
            {
                var ansNode = N("Answers", pos, 0);
                for (int i = 0; i < an && pos + 10 <= end; i++)
                {
                    int start = pos;
                    string name = ReadDnsName(d, off, ref pos);
                    int type = U16(d, pos), rdlen = U16(d, pos + 8);
                    uint ttl = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(pos + 4));
                    pos += 10;
                    string tn = DnsTypes.TryGetValue(type, out var t) ? t : $"TYPE{type}";
                    string data = type switch
                    {
                        1 when rdlen == 4  => Ip4Text(d, pos),
                        28 when rdlen == 16 => Ip6Text(d, pos),
                        2 or 5 or 12 => ReadDnsNameAt(d, off, pos),
                        _ => $"{rdlen} bytes",
                    };
                    ansNode.Children.Add(N($"{name}: type {tn}, TTL {ttl}, {data}", start, pos + rdlen - start, type == 1 ? "dns.a" : type == 28 ? "dns.aaaa" : "dns.resp.name", data));
                    if (type == 1) dp.Add("dns.a", data);
                    if (type == 28) dp.Add("dns.aaaa", data);
                    answers.Add($"{tn} {data}");
                    pos += rdlen;
                }
                node.Children.Add(ansNode);
            }

            info.Append(response ? $"Standard query response 0x{id:x4}" : $"Standard query 0x{id:x4}");
            if (response && rcode == 3) info.Append(" No such name");
            else if (response && rcode != 0) info.Append($" Error {rcode}");
            if (qname.Length > 0) info.Append($" {qtypeName} {qname}");
            foreach (var a in answers) info.Append(' ').Append(a);
        }
        catch (Exception e) when (e is IndexOutOfRangeException or ArgumentOutOfRangeException)
        {
            info.Append("[Malformed DNS]");
        }
        dp.Info = info.ToString();
        dp.Tree.Add(node);
    }

    static string ReadDnsName(byte[] d, int msgStart, ref int pos)
    {
        var sb = new StringBuilder();
        int p = pos, jumps = 0;
        bool jumped = false;
        while (true)
        {
            int len = d[p];
            if (len == 0) { p++; break; }
            if ((len & 0xC0) == 0xC0) // compression pointer
            {
                if (!jumped) pos = p + 2;
                jumped = true;
                p = msgStart + (((len & 0x3F) << 8) | d[p + 1]);
                if (++jumps > 20) break;
                continue;
            }
            if (sb.Length > 0) sb.Append('.');
            sb.Append(Encoding.ASCII.GetString(d, p + 1, len));
            p += 1 + len;
        }
        if (!jumped) pos = p;
        return sb.Length == 0 ? "<Root>" : sb.ToString();
    }

    static string ReadDnsNameAt(byte[] d, int msgStart, int at) { int p = at; return ReadDnsName(d, msgStart, ref p); }

    // ======================================================================
    // TCP
    // ======================================================================

    static readonly string[] FlagNames = { "FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR" };
    static readonly string[] FlagFields = { "fin", "syn", "reset", "push", "ack", "urg", "ece", "cwr" };

    void Tcp(DissectedPacket dp, int off, int end)
    {
        var d = dp.Raw.Data;
        int sp = U16(d, off), dpn = U16(d, off + 2);
        uint seqRaw = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(off + 4));
        uint ackRaw = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(off + 8));
        int hdr = Math.Max(20, (d[off + 12] >> 4) * 4);
        int flags = ((d[off + 12] & 1) << 8) | d[off + 13];
        int win = U16(d, off + 14);
        int payloadOff = Math.Min(off + hdr, end), len = Math.Max(0, end - payloadOff);
        bool syn = (flags & 2) != 0, ack = (flags & 16) != 0, fin = (flags & 1) != 0;

        string a = $"{dp.SrcAddr}:{sp}", b = $"{dp.DstAddr}:{dpn}";
        var st = Stream(_tcp, a, b);
        int dir = a == st.EndpointA ? 0 : 1;
        if (!st.HaveBase[dir]) { st.Base[dir] = seqRaw; st.HaveBase[dir] = true; }
        uint relSeq = seqRaw - st.Base[dir];
        uint relAck = ack && st.HaveBase[1 - dir] ? ackRaw - st.Base[1 - dir] : ackRaw;

        // Options
        var optNodes = new List<DetailNode>();
        var infoTokens = new List<string>();
        for (int o = off + 20; o < off + hdr && o < end;)
        {
            byte kind = d[o];
            if (kind == 0) { optNodes.Add(N("TCP Option - End of Option List (EOL)", o, 1)); break; }
            if (kind == 1) { optNodes.Add(N("TCP Option - No-Operation (NOP)", o, 1)); o++; continue; }
            if (o + 1 >= end) break;
            int l = d[o + 1];
            if (l < 2 || o + l > off + hdr) break;
            switch (kind)
            {
                case 2 when l == 4:
                    int mss = U16(d, o + 2);
                    optNodes.Add(N($"TCP Option - Maximum segment size: {mss} bytes", o, 4, "tcp.options.mss_val", mss.ToString()));
                    infoTokens.Add($"MSS={mss}");
                    break;
                case 3 when l == 3:
                    int shift = d[o + 2];
                    optNodes.Add(N($"TCP Option - Window scale: {shift} (multiply by {1 << shift})", o, 3, "tcp.options.wscale.shift", shift.ToString()));
                    infoTokens.Add($"WS={1 << shift}");
                    if (syn) st.WindowShift[dir] = shift;
                    break;
                case 4:
                    optNodes.Add(N("TCP Option - SACK permitted", o, 2));
                    infoTokens.Add("SACK_PERM");
                    break;
                case 5:
                    for (int s = o + 2; s + 8 <= o + l; s += 8)
                    {
                        uint le = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(s)) - st.Base[1 - dir];
                        uint re = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(s + 4)) - st.Base[1 - dir];
                        infoTokens.Add($"SLE={le}"); infoTokens.Add($"SRE={re}");
                    }
                    optNodes.Add(N("TCP Option - SACK", o, l));
                    break;
                case 8 when l == 10:
                    uint tsv = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(o + 2)), tse = BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(o + 6));
                    optNodes.Add(N($"TCP Option - Timestamps: TSval {tsv}, TSecr {tse}", o, 10, "tcp.options.timestamp.tsval", tsv.ToString()));
                    infoTokens.Add($"TSval={tsv}"); infoTokens.Add($"TSecr={tse}");
                    break;
                default:
                    optNodes.Add(N($"TCP Option - Kind: {kind}", o, l));
                    break;
            }
            o += l;
        }

        bool scaling = st.WindowShift[0] >= 0 && st.WindowShift[1] >= 0;
        long calcWin = syn || !scaling ? win : (long)win << st.WindowShift[dir];

        var flagNames = new List<string>();
        for (int i = 0; i < FlagNames.Length; i++) if ((flags & (1 << i)) != 0) flagNames.Add(FlagNames[i]);
        string flagText = flagNames.Count == 0 ? "<None>" : string.Join(", ", flagNames);

        dp.Transport = "tcp"; dp.StreamIndex = st.Index; dp.Direction = dir; dp.RelativeSeq = relSeq;
        dp.SrcPort = sp.ToString(); dp.DstPort = dpn.ToString();
        dp.Chain.Add("tcp"); dp.Protocol = "TCP";
        dp.Info = $"{sp} → {dpn} [{flagText}] Seq={relSeq}" + (ack ? $" Ack={relAck}" : "") + $" Win={calcWin} Len={len}" +
                  (infoTokens.Count > 0 ? " " + string.Join(" ", infoTokens) : "");

        dp.Add("tcp.srcport", sp.ToString()); dp.Add("tcp.dstport", dpn.ToString());
        dp.Add("tcp.port", sp.ToString()); dp.Add("tcp.port", dpn.ToString());
        dp.Add("tcp.stream", st.Index.ToString()); dp.Add("tcp.len", len.ToString());
        dp.Add("tcp.seq", relSeq.ToString()); dp.Add("tcp.seq_raw", seqRaw.ToString());
        dp.Add("tcp.ack", relAck.ToString()); dp.Add("tcp.ack_raw", ackRaw.ToString());
        dp.Add("tcp.hdr_len", hdr.ToString()); dp.Add("tcp.window_size", calcWin.ToString());
        for (int i = 0; i < FlagFields.Length; i++) dp.Add($"tcp.flags.{FlagFields[i]}", (flags & (1 << i)) != 0 ? "1" : "0");

        var node = N($"Transmission Control Protocol, Src Port: {sp}, Dst Port: {dpn}, Seq: {relSeq}" +
                     (ack ? $", Ack: {relAck}" : "") + $", Len: {len}", off, hdr);
        node.Children.Add(N($"Source Port: {sp}", off, 2, "tcp.srcport", sp.ToString()));
        node.Children.Add(N($"Destination Port: {dpn}", off + 2, 2, "tcp.dstport", dpn.ToString()));
        node.Children.Add(N($"[Stream index: {st.Index}]", 0, 0, "tcp.stream", st.Index.ToString()));
        node.Children.Add(N($"[TCP Segment Len: {len}]", 0, 0, "tcp.len", len.ToString()));
        node.Children.Add(N($"Sequence Number: {relSeq}    (relative sequence number)", off + 4, 4, "tcp.seq", relSeq.ToString()));
        node.Children.Add(N($"Sequence Number (raw): {seqRaw}", off + 4, 4, "tcp.seq_raw", seqRaw.ToString()));
        node.Children.Add(N($"[Next Sequence Number: {relSeq + (uint)len + (syn || fin ? 1u : 0u)}    (relative sequence number)]", 0, 0));
        node.Children.Add(N($"Acknowledgment Number: {(ack ? relAck : 0)}    (relative ack number)", off + 8, 4, "tcp.ack", relAck.ToString()));
        node.Children.Add(N($"Acknowledgment number (raw): {ackRaw}", off + 8, 4, "tcp.ack_raw", ackRaw.ToString()));
        node.Children.Add(N($"{Convert.ToString(hdr / 4, 2).PadLeft(4, '0')} .... = Header Length: {hdr} bytes ({hdr / 4})", off + 12, 1, "tcp.hdr_len", hdr.ToString()));

        var flagsNode = N($"Flags: 0x{flags:x3} ({flagText})", off + 12, 2, "tcp.flags", $"0x{flags:x3}");
        for (int i = FlagNames.Length - 1; i >= 0; i--)
            flagsNode.Children.Add(N($"{CultureInfo.InvariantCulture.TextInfo.ToTitleCase(FlagNames[i].ToLowerInvariant())}: {((flags & (1 << i)) != 0 ? "Set" : "Not set")}",
                off + 12, 2, $"tcp.flags.{FlagFields[i]}", (flags & (1 << i)) != 0 ? "1" : "0"));
        node.Children.Add(flagsNode);

        node.Children.Add(N($"Window: {win}", off + 14, 2, "tcp.window_size_value", win.ToString()));
        if (scaling && !syn) node.Children.Add(N($"[Calculated window size: {calcWin}]", off + 14, 2, "tcp.window_size", calcWin.ToString()));
        node.Children.Add(N($"Checksum: 0x{U16(d, off + 16):x4}", off + 16, 2, "tcp.checksum", $"0x{U16(d, off + 16):x4}"));
        node.Children.Add(N($"Urgent Pointer: {U16(d, off + 18)}", off + 18, 2));
        if (hdr > 20)
        {
            var opts = N($"Options: ({hdr - 20} bytes)", off + 20, hdr - 20);
            opts.Children.AddRange(optNodes);
            node.Children.Add(opts);
        }
        dp.Tree.Add(node);

        if (len == 0) return;
        dp.Payload = d.AsSpan(payloadOff, len).ToArray();
        if (LooksLikeHttp(d, payloadOff, end)) Http(dp, payloadOff, end);
        else DataNode(dp, payloadOff, len);
    }

    StreamState Stream(Dictionary<string, StreamState> table, string a, string b)
    {
        string key = string.CompareOrdinal(a, b) <= 0 ? a + "|" + b : b + "|" + a;
        if (!table.TryGetValue(key, out var st))
            table[key] = st = new StreamState { Index = table.Count, EndpointA = a };
        return st;
    }

    // ======================================================================
    // HTTP
    // ======================================================================

    static readonly string[] HttpMethods = { "GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE " };

    static bool LooksLikeHttp(byte[] d, int off, int end)
    {
        if (end - off < 5) return false;
        var head = Encoding.ASCII.GetString(d, off, Math.Min(9, end - off));
        return head.StartsWith("HTTP/") || HttpMethods.Any(m => head.StartsWith(m, StringComparison.Ordinal));
    }

    void Http(DissectedPacket dp, int off, int end)
    {
        var d = dp.Raw.Data;
        string text = Encoding.ASCII.GetString(d, off, end - off);
        int headerEnd = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        string head = headerEnd >= 0 ? text[..headerEnd] : text;
        var lines = head.Split("\r\n");
        string first = lines[0];
        bool response = first.StartsWith("HTTP/");

        dp.Chain.Add("http"); dp.Protocol = "HTTP";
        var node = N("Hypertext Transfer Protocol", off, headerEnd >= 0 ? headerEnd + 4 : end - off);

        int cursor = off;
        string contentType = "";
        for (int i = 0; i < lines.Length; i++)
        {
            string line = lines[i];
            var child = N(line + "\\r\\n", cursor, line.Length + 2);
            if (i == 0)
            {
                var parts = first.Split(' ', 3);
                if (response && parts.Length >= 2)
                {
                    child.Children.Add(N($"Response Version: {parts[0]}", cursor, parts[0].Length, "http.response.version", parts[0]));
                    child.Children.Add(N($"Status Code: {parts[1]}", cursor + parts[0].Length + 1, parts[1].Length, "http.response.code", parts[1]));
                    dp.Add("http.response.code", parts[1]);
                    if (parts.Length > 2) { child.Children.Add(N($"Response Phrase: {parts[2]}", cursor, parts[2].Length, "http.response.phrase", parts[2])); dp.Add("http.response.phrase", parts[2]); }
                }
                else if (parts.Length >= 2)
                {
                    child.Children.Add(N($"Request Method: {parts[0]}", cursor, parts[0].Length, "http.request.method", parts[0]));
                    child.Children.Add(N($"Request URI: {parts[1]}", cursor + parts[0].Length + 1, parts[1].Length, "http.request.uri", parts[1]));
                    dp.Add("http.request.method", parts[0]); dp.Add("http.request.uri", parts[1]);
                    if (parts.Length > 2) { child.Children.Add(N($"Request Version: {parts[2]}", cursor, parts[2].Length, "http.request.version", parts[2])); dp.Add("http.request.version", parts[2]); }
                }
            }
            else
            {
                int colon = line.IndexOf(':');
                if (colon > 0)
                {
                    string name = line[..colon].Trim().ToLowerInvariant(), value = line[(colon + 1)..].Trim();
                    if (name == "host") { dp.Add("http.host", value); child.Children.Add(N($"Host: {value}", cursor, line.Length, "http.host", value)); }
                    else if (name == "user-agent") { dp.Add("http.user_agent", value); child.Children.Add(N($"User-Agent: {value}", cursor, line.Length, "http.user_agent", value)); }
                    else if (name == "content-type") { dp.Add("http.content_type", value); contentType = value; }
                }
            }
            node.Children.Add(child);
            cursor += line.Length + 2;
        }
        dp.Tree.Add(node);

        dp.Info = response && contentType.Length > 0 ? $"{first}  ({contentType.Split(';')[0]})" : first + (response ? "" : " ");
        dp.Add("http", "1");
    }

    // ======================================================================
    // helpers
    // ======================================================================

    static void DataNode(DissectedPacket dp, int off, int len)
    {
        if (len <= 0) return;
        dp.Chain.Add("data");
        var node = N($"Data ({len} bytes)", off, len, "data.len", len.ToString());
        node.Children.Add(N($"[Length: {len}]", off, len, "data.len", len.ToString()));
        dp.Tree.Add(node);
        dp.Add("data.len", len.ToString());
    }

    static DetailNode N(string label, int pos, int size, string name = "", string show = "") =>
        new() { Label = label, Pos = pos, Size = size, Name = name, Show = show };

    static int U16(byte[] d, int o) => BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(o));
    static string Mac(byte[] d, int o) => string.Join(":", d.Skip(o).Take(6).Select(b => b.ToString("x2")));
    static string Friendly(string mac) => mac == "ff:ff:ff:ff:ff:ff" ? "Broadcast" : mac;
    static string Ip4Text(byte[] d, int o) => $"{d[o]}.{d[o + 1]}.{d[o + 2]}.{d[o + 3]}";
    static string Ip6Text(byte[] d, int o) => new IPAddress(d.AsSpan(o, 16)).ToString();

    static string EtherTypeName(int t) => t switch
    {
        0x0800 => "IPv4", 0x86DD => "IPv6", 0x0806 => "ARP", 0x8100 => "802.1Q Virtual LAN", 0x88CC => "LLDP", _ => "Unknown",
    };

    static string IpProtoName(int p) => p switch
    {
        1 => "ICMP", 2 => "IGMP", 6 => "TCP", 17 => "UDP", 41 => "IPv6", 47 => "GRE", 50 => "ESP", 51 => "AH",
        58 => "ICMPv6", 89 => "OSPF", _ => "Unknown",
    };
}
