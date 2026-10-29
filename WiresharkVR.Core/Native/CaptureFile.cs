using System.Buffers.Binary;

namespace WiresharkVR.Core.Native;

/// <summary>One captured frame exactly as it came off the wire.</summary>
public sealed class RawPacket
{
    public int Number { get; init; }
    /// <summary>Seconds since 1970-01-01 UTC.</summary>
    public double Time { get; init; }
    public required byte[] Data { get; init; }
    /// <summary>Length on the wire (can exceed Data.Length when the capture was truncated).</summary>
    public int OriginalLength { get; init; }
    public int LinkType { get; init; }
}

/// <summary>Reads classic .pcap and modern .pcapng capture files.</summary>
public static class CaptureFileReader
{
    public static List<RawPacket> Read(string path) => Read(File.ReadAllBytes(path));

    public static List<RawPacket> Read(byte[] data)
    {
        if (data.Length < 12) throw new InvalidDataException("File is too small to be a capture.");
        uint magic = BinaryPrimitives.ReadUInt32LittleEndian(data);
        return magic == 0x0A0D0D0A ? ReadPcapNg(data) : ReadPcap(data, magic);
    }

    // ---- classic pcap -----------------------------------------------------

    static List<RawPacket> ReadPcap(byte[] d, uint magic)
    {
        bool le, nano;
        switch (magic)
        {
            case 0xA1B2C3D4: le = true;  nano = false; break;
            case 0xA1B23C4D: le = true;  nano = true;  break;
            case 0xD4C3B2A1: le = false; nano = false; break;
            case 0x4D3CB2A1: le = false; nano = true;  break;
            default: throw new InvalidDataException("Not a pcap or pcapng capture file.");
        }
        if (d.Length < 24) throw new InvalidDataException("Truncated pcap header.");

        int linkType = (int)U32(d, 20, le);
        var packets = new List<RawPacket>();
        int pos = 24;
        while (pos + 16 <= d.Length)
        {
            uint sec = U32(d, pos, le), frac = U32(d, pos + 4, le);
            int incl = (int)U32(d, pos + 8, le), orig = (int)U32(d, pos + 12, le);
            pos += 16;
            if (incl < 0 || pos + incl > d.Length) break; // truncated file: keep what we have

            packets.Add(new RawPacket
            {
                Number = packets.Count + 1,
                Time = sec + frac / (nano ? 1e9 : 1e6),
                Data = d.AsSpan(pos, incl).ToArray(),
                OriginalLength = orig,
                LinkType = linkType,
            });
            pos += incl;
        }
        return packets;
    }

    // ---- pcapng -----------------------------------------------------------

    static List<RawPacket> ReadPcapNg(byte[] d)
    {
        var packets = new List<RawPacket>();
        var interfaces = new List<(int link, double unitsPerSecond)>();
        bool le = true;
        int pos = 0;

        while (pos + 12 <= d.Length)
        {
            uint type = U32(d, pos, le);
            if (type == 0x0A0D0D0A) // Section Header: byte order of the section lives in its body
            {
                le = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(pos + 8)) == 0x1A2B3C4D;
                interfaces.Clear();
            }
            int total = (int)U32(d, pos + 4, le);
            if (total < 12 || pos + total > d.Length) break;
            int body = pos + 8, bodyEnd = pos + total - 4;

            switch (type)
            {
                case 1: // Interface Description
                {
                    int link = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(body)) is var l && !le
                        ? BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(body)) : l;
                    double units = 1e6; // default timestamp resolution: microseconds
                    for (int o = body + 8; o + 4 <= bodyEnd;)
                    {
                        int code = U16(d, o, le), len = U16(d, o + 2, le);
                        if (code == 0) break;
                        if (code == 9 && len >= 1 && o + 4 < bodyEnd) // if_tsresol
                        {
                            byte b = d[o + 4];
                            units = (b & 0x80) == 0 ? Math.Pow(10, b) : Math.Pow(2, b & 0x7F);
                        }
                        o += 4 + ((len + 3) & ~3);
                    }
                    interfaces.Add((link, units));
                    break;
                }
                case 6: // Enhanced Packet
                {
                    int ifId = (int)U32(d, body, le);
                    ulong ts = ((ulong)U32(d, body + 4, le) << 32) | U32(d, body + 8, le);
                    int cap = (int)U32(d, body + 12, le), orig = (int)U32(d, body + 16, le);
                    if (ifId >= interfaces.Count || cap < 0 || body + 20 + cap > bodyEnd) break;
                    var (link, units) = interfaces[ifId];
                    packets.Add(new RawPacket
                    {
                        Number = packets.Count + 1,
                        Time = ts / units,
                        Data = d.AsSpan(body + 20, cap).ToArray(),
                        OriginalLength = orig,
                        LinkType = link,
                    });
                    break;
                }
                case 3: // Simple Packet (no timestamp, always interface 0)
                {
                    if (interfaces.Count == 0) break;
                    int orig = (int)U32(d, body, le);
                    int cap = Math.Min(orig, bodyEnd - body - 4);
                    packets.Add(new RawPacket
                    {
                        Number = packets.Count + 1,
                        Time = 0,
                        Data = d.AsSpan(body + 4, cap).ToArray(),
                        OriginalLength = orig,
                        LinkType = interfaces[0].link,
                    });
                    break;
                }
            }
            pos += total;
        }
        return packets;
    }

    static uint   U32(byte[] d, int o, bool le) => le ? BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(o)) : BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(o));
    static ushort U16(byte[] d, int o, bool le) => le ? BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(o)) : BinaryPrimitives.ReadUInt16BigEndian(d.AsSpan(o));
}
