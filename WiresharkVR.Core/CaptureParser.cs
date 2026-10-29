using System.Globalization;
using System.Text.Json;

namespace WiresharkVR.Core;

/// <summary>Turns the output of "tshark -T json" into <see cref="Packet"/> objects.</summary>
public static class CaptureParser
{
    static readonly string[] TcpFlagNames = { "fin", "syn", "reset", "push", "ack", "urg" };
    static readonly string[] TcpFlagLabels = { "FIN", "SYN", "RST", "PSH", "ACK", "URG" };

    public static List<Packet> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var packets = new List<Packet>();
        foreach (var item in doc.RootElement.EnumerateArray())
        {
            if (!item.TryGetProperty("_source", out var source) ||
                !source.TryGetProperty("layers", out var layers))
                continue;
            packets.Add(ParsePacket(layers));
        }
        return packets;
    }

    static Packet ParsePacket(JsonElement layers)
    {
        var frame = layers.GetProperty("frame");
        var packet = new Packet
        {
            Number = (int)ReadNumber(frame, "frame.number"),
            Length = (int)ReadNumber(frame, "frame.len"),
            Time = ReadTime(frame),
        };

        // Duplicate keys can occur in tshark JSON; enumerating keeps them all.
        foreach (var prop in layers.EnumerateObject())
        {
            var layer = new Layer { Name = prop.Name };
            Flatten(prop.Value, layer.Fields, 0);
            packet.Layers.Add(layer);
        }

        Summarize(packet);
        return packet;
    }

    /// <summary>Walks a layer object; scalar values become fields, objects become deeper levels.</summary>
    static void Flatten(JsonElement element, List<Field> into, int depth)
    {
        if (element.ValueKind != JsonValueKind.Object) return;
        foreach (var prop in element.EnumerateObject())
        {
            switch (prop.Value.ValueKind)
            {
                case JsonValueKind.Object:
                    // Subtree labelled by a descriptive string or "*_tree" key.
                    Flatten(prop.Value, into, depth + 1);
                    break;
                case JsonValueKind.Array:
                    var parts = new List<string>();
                    foreach (var v in prop.Value.EnumerateArray())
                    {
                        if (v.ValueKind == JsonValueKind.Object) Flatten(v, into, depth + 1);
                        else parts.Add(v.ToString());
                    }
                    if (parts.Count > 0) into.Add(new Field(prop.Name, string.Join(", ", parts), depth));
                    break;
                default:
                    into.Add(new Field(prop.Name, prop.Value.ToString(), depth));
                    break;
            }
        }
    }

    static void Summarize(Packet p)
    {
        var ip = p.GetLayer("ip");
        var ipv6 = p.GetLayer("ipv6");
        p.Source = ip?.Get("ip.src") ?? ipv6?.Get("ipv6.src");
        p.Destination = ip?.Get("ip.dst") ?? ipv6?.Get("ipv6.dst");

        var tcp = p.GetLayer("tcp");
        var udp = p.GetLayer("udp");
        if (tcp != null)
        {
            p.SourcePort = tcp.Get("tcp.srcport");
            p.DestinationPort = tcp.Get("tcp.dstport");
            var stream = tcp.Get("tcp.stream");
            if (stream != null) p.StreamKey = $"tcp:{stream}";
            p.Info = TcpInfo(tcp);
        }
        else if (udp != null)
        {
            p.SourcePort = udp.Get("udp.srcport");
            p.DestinationPort = udp.Get("udp.dstport");
            var stream = udp.Get("udp.stream");
            if (stream != null) p.StreamKey = $"udp:{stream}";
            p.Info = $"{p.SourcePort} → {p.DestinationPort} Len={udp.Get("udp.length")}";
        }
        else
        {
            p.Info = p.Protocol;
        }
    }

    static string TcpInfo(Layer tcp)
    {
        var flags = new List<string>();
        for (int i = 0; i < TcpFlagNames.Length; i++)
            if (tcp.Get($"tcp.flags.{TcpFlagNames[i]}") == "1") flags.Add(TcpFlagLabels[i]);
        return $"{tcp.Get("tcp.srcport")} → {tcp.Get("tcp.dstport")} [{string.Join(", ", flags)}] " +
               $"Seq={tcp.Get("tcp.seq")} Ack={tcp.Get("tcp.ack")} Len={tcp.Get("tcp.len")}";
    }

    static double ReadNumber(JsonElement layer, string field) =>
        layer.TryGetProperty(field, out var v) &&
        double.TryParse(v.ToString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : 0;

    static DateTimeOffset ReadTime(JsonElement frame)
    {
        if (!frame.TryGetProperty("frame.time_epoch", out var v)) return default;
        var s = v.ToString();
        if (double.TryParse(s, NumberStyles.Float, CultureInfo.InvariantCulture, out var epoch))
            return DateTimeOffset.FromUnixTimeMilliseconds((long)(epoch * 1000));
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var t) ? t : default;
    }
}
