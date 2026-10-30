using System.Buffers.Binary;
using System.Net;

namespace WiresharkVR.Core.Vpn;

/// <summary>An IPv4 or IPv6 address held as a plain value, so it can be part of a flow key.</summary>
public readonly record struct IpAddr(UInt128 Value, bool IsV6)
{
    public static implicit operator IpAddr(uint ipv4) => new(ipv4, false);

    public static IpAddr ReadV6(ReadOnlySpan<byte> bytes) => new(BinaryPrimitives.ReadUInt128BigEndian(bytes), true);

    public void Write(Span<byte> target)
    {
        if (IsV6) BinaryPrimitives.WriteUInt128BigEndian(target, Value);
        else BinaryPrimitives.WriteUInt32BigEndian(target, (uint)Value);
    }

    public IPAddress ToIPAddress()
    {
        Span<byte> bytes = stackalloc byte[IsV6 ? 16 : 4];
        Write(bytes);
        return new IPAddress(bytes);
    }

    /// <summary>Multicast and link-local IPv6 stay on the local network, so they can't be forwarded.</summary>
    public bool IsLocalOnlyV6
    {
        get
        {
            byte top = (byte)(Value >> 120);
            byte next = (byte)(Value >> 112);
            return IsV6 && (top == 0xFF || (top == 0xFE && (next & 0xC0) == 0x80));
        }
    }
}

/// <summary>Reads and builds the IP, TCP and UDP headers the VPN forwarder needs.</summary>
public static class IpPacket
{
    public const byte Fin = 1, Syn = 2, Rst = 4, Psh = 8, Ack = 16;
    public const byte ProtocolTcp = 6, ProtocolUdp = 17;

    const int V4Header = 20, V6Header = 40;

    static int _identification;

    public static ushort Checksum(ReadOnlySpan<byte> data, uint sum = 0)
    {
        int i = 0;
        for (; i + 1 < data.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(data[i..]);
        if (i < data.Length) sum += (uint)data[i] << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return (ushort)~sum;
    }

    public static uint PseudoHeader(IpAddr src, IpAddr dst, byte protocol, int length)
    {
        uint sum = protocol + (uint)length;
        for (int shift = 0; shift < (src.IsV6 ? 128 : 32); shift += 16)
            sum += (ushort)(src.Value >> shift) + (uint)(ushort)(dst.Value >> shift);
        return sum;
    }

    static int HeaderLength(IpAddr address) => address.IsV6 ? V6Header : V4Header;

    static void WriteIpHeader(Span<byte> p, byte protocol, IpAddr src, IpAddr dst)
    {
        if (src.IsV6)
        {
            p[0] = 0x60;
            BinaryPrimitives.WriteUInt16BigEndian(p[4..], (ushort)(p.Length - V6Header));
            p[6] = protocol;
            p[7] = 64;
            src.Write(p[8..]);
            dst.Write(p[24..]);
            return;
        }

        p[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(p[2..], (ushort)p.Length);
        BinaryPrimitives.WriteUInt16BigEndian(p[4..], (ushort)Interlocked.Increment(ref _identification));
        p[6] = 0x40; // don't fragment
        p[8] = 64;
        p[9] = protocol;
        src.Write(p[12..]);
        dst.Write(p[16..]);
        BinaryPrimitives.WriteUInt16BigEndian(p[10..], Checksum(p[..V4Header]));
    }

    public static byte[] Tcp(IpAddr src, ushort srcPort, IpAddr dst, ushort dstPort,
        uint seq, uint ack, byte flags, ushort window, ReadOnlySpan<byte> payload, ushort mss = 0)
    {
        int ip = HeaderLength(src);
        int options = mss != 0 ? 4 : 0;
        int headerLength = 20 + options;
        var p = new byte[ip + headerLength + payload.Length];
        var t = p.AsSpan(ip);

        BinaryPrimitives.WriteUInt16BigEndian(t, srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(t[2..], dstPort);
        BinaryPrimitives.WriteUInt32BigEndian(t[4..], seq);
        BinaryPrimitives.WriteUInt32BigEndian(t[8..], ack);
        t[12] = (byte)(headerLength / 4 << 4);
        t[13] = flags;
        BinaryPrimitives.WriteUInt16BigEndian(t[14..], window);
        if (mss != 0)
        {
            t[20] = 2;
            t[21] = 4;
            BinaryPrimitives.WriteUInt16BigEndian(t[22..], mss);
        }
        payload.CopyTo(t[headerLength..]);

        BinaryPrimitives.WriteUInt16BigEndian(t[16..], Checksum(t, PseudoHeader(src, dst, ProtocolTcp, t.Length)));
        WriteIpHeader(p, ProtocolTcp, src, dst);
        return p;
    }

    public static byte[] Udp(IpAddr src, ushort srcPort, IpAddr dst, ushort dstPort, ReadOnlySpan<byte> payload)
    {
        int ip = HeaderLength(src);
        var p = new byte[ip + 8 + payload.Length];
        var u = p.AsSpan(ip);

        BinaryPrimitives.WriteUInt16BigEndian(u, srcPort);
        BinaryPrimitives.WriteUInt16BigEndian(u[2..], dstPort);
        BinaryPrimitives.WriteUInt16BigEndian(u[4..], (ushort)u.Length);
        payload.CopyTo(u[8..]);

        ushort checksum = Checksum(u, PseudoHeader(src, dst, ProtocolUdp, u.Length));
        BinaryPrimitives.WriteUInt16BigEndian(u[6..], checksum == 0 ? (ushort)0xFFFF : checksum);
        WriteIpHeader(p, ProtocolUdp, src, dst);
        return p;
    }
}
