using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace WiresharkVR.Core;

/// <summary>One line of Wireshark's Packet List pane.</summary>
public sealed record PacketRow(
    int Number, double RelativeTime, string Source, string Destination,
    string Protocol, int Length, string Info);

/// <summary>One line of Wireshark's Packet Details pane (a protocol or a field inside it).</summary>
public sealed class DetailNode
{
    public required string Label { get; init; }
    /// <summary>Wireshark field name such as "tcp.srcport"; empty for protocol headers without one.</summary>
    public string Name { get; init; } = "";
    /// <summary>Display value of the field, e.g. "49931".</summary>
    public string Show { get; init; } = "";
    /// <summary>Byte offset of this item inside the packet, and how many bytes it covers.</summary>
    public int Pos { get; init; }
    public int Size { get; init; }
    public List<DetailNode> Children { get; } = new();
    public bool Expanded { get; set; }
}

/// <summary>Everything the Details and Bytes panes need for one packet.</summary>
public sealed class PacketDetail
{
    public required List<DetailNode> Tree { get; init; }
    public required byte[] Bytes { get; init; }

    public DetailNode? Find(string fieldName)
    {
        DetailNode? Walk(IEnumerable<DetailNode> nodes)
        {
            foreach (var n in nodes)
            {
                if (n.Name == fieldName) return n;
                var hit = Walk(n.Children);
                if (hit != null) return hit;
            }
            return null;
        }
        return Walk(Tree);
    }
}

/// <summary>Parses tshark's PDML output, which carries the same labels Wireshark shows in its details pane.</summary>
public static class PdmlParser
{
    public static List<DetailNode> Parse(string xml)
    {
        var result = new List<DetailNode>();
        var packet = XDocument.Parse(xml).Descendants("packet").FirstOrDefault();
        if (packet == null) return result;

        foreach (var proto in packet.Elements("proto"))
        {
            if ((string?)proto.Attribute("name") == "geninfo") continue; // Wireshark hides this one
            result.Add(ToNode(proto));
        }
        return result;
    }

    static DetailNode ToNode(XElement e)
    {
        string name = (string?)e.Attribute("name") ?? "";
        string show = (string?)e.Attribute("show") ?? "";
        string label = (string?)e.Attribute("showname") ?? "";
        if (label.Length == 0) label = show.Length > 0 ? show : name;

        var node = new DetailNode
        {
            Label = label,
            Name  = name,
            Show  = show,
            Pos   = ParseInt((string?)e.Attribute("pos")),
            Size  = ParseInt((string?)e.Attribute("size")),
        };
        foreach (var child in e.Elements("field"))
            if ((string?)child.Attribute("hidden") != "yes")
                node.Children.Add(ToNode(child));
        return node;
    }

    static int ParseInt(string? s) =>
        int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
}

/// <summary>Reads the text produced by "tshark -x" back into raw bytes.</summary>
public static class HexDump
{
    static readonly Regex Line = new(@"^[0-9a-fA-F]{4}\s\s", RegexOptions.Compiled);

    public static byte[] Parse(string text)
    {
        var bytes = new List<byte>();
        foreach (var raw in text.Split('\n'))
        {
            var line = raw.TrimEnd('\r');
            if (!Line.IsMatch(line)) continue;
            // Hex columns: 8 bytes, an extra space, 8 bytes = 49 characters starting at column 6.
            var hex = line.Substring(6, Math.Min(49, line.Length - 6));
            foreach (var token in hex.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                if (token.Length == 2 && byte.TryParse(token, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var b))
                    bytes.Add(b);
        }
        return bytes.ToArray();
    }
}
