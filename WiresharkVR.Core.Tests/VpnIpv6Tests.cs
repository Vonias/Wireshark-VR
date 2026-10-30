using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using WiresharkVR.Core.Native;
using WiresharkVR.Core.Vpn;
using Xunit;

namespace WiresharkVR.Core.Tests;

public class VpnIpv6Tests
{
    const int IpHeader = 40;
    const ushort ClientPort = 40000;
    static readonly IpAddr Client = new(((UInt128)0xFD00006F00000000UL << 64) | 2, true);
    static readonly IpAddr Server = new(1, true); // ::1
    static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    static byte[] Take(BlockingCollection<byte[]> packets)
    {
        Assert.True(packets.TryTake(out var p, Timeout), "No packet came back through the tunnel.");
        Assert.Equal(6, p![0] >> 4);
        return p;
    }

    static void AssertTransportChecksum(byte[] p, byte protocol)
    {
        var segment = p.AsSpan(IpHeader);
        Assert.Equal(0, IpPacket.Checksum(segment, IpPacket.PseudoHeader(Server, Client, protocol, segment.Length)));
    }

    [Fact]
    public async Task Tcp_echo_over_ipv6()
    {
        using var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        var port = (ushort)((IPEndPoint)listener.LocalEndpoint).Port;
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            var s = c.GetStream();
            var buffer = new byte[64];
            int n = await s.ReadAsync(buffer);
            await s.WriteAsync(buffer.AsMemory(0, n));
        });

        var packets = new BlockingCollection<byte[]>();
        using var forwarder = new UserspaceForwarder(packets.Add);
        void Send(byte[] p) => forwarder.HandleOutbound(p, p.Length);

        Send(IpPacket.Tcp(Client, ClientPort, Server, port, 100, 0, IpPacket.Syn, 65535, default));
        var synAck = Take(packets);
        AssertTransportChecksum(synAck, IpPacket.ProtocolTcp);
        Assert.Equal(IpPacket.Syn | IpPacket.Ack, synAck[IpHeader + 13]);
        Assert.Equal(1440, BinaryPrimitives.ReadUInt16BigEndian(synAck.AsSpan(IpHeader + 22)));

        uint serverSeq = BinaryPrimitives.ReadUInt32BigEndian(synAck.AsSpan(IpHeader + 4)) + 1;
        Send(IpPacket.Tcp(Client, ClientPort, Server, port, 101, serverSeq, IpPacket.Ack, 65535, default));
        Send(IpPacket.Tcp(Client, ClientPort, Server, port, 101, serverSeq, IpPacket.Psh | IpPacket.Ack, 65535, Encoding.ASCII.GetBytes("hello")));

        string? echoed = null;
        while (echoed == null)
        {
            var p = Take(packets);
            AssertTransportChecksum(p, IpPacket.ProtocolTcp);
            int offset = IpHeader + (p[IpHeader + 12] >> 4) * 4;
            if (p.Length > offset) echoed = Encoding.ASCII.GetString(p, offset, p.Length - offset);
        }
        await server;
        Assert.Equal("hello", echoed);
    }

    [Fact]
    public async Task Udp_over_ipv6()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.IPv6Loopback, 0));
        var port = (ushort)((IPEndPoint)server.Client.LocalEndPoint!).Port;

        var packets = new BlockingCollection<byte[]>();
        using var forwarder = new UserspaceForwarder(packets.Add);
        var request = IpPacket.Udp(Client, ClientPort, Server, port, Encoding.ASCII.GetBytes("ping"));
        forwarder.HandleOutbound(request, request.Length);

        var got = await server.ReceiveAsync();
        Assert.Equal("ping", Encoding.ASCII.GetString(got.Buffer));
        await server.SendAsync(Encoding.ASCII.GetBytes("pong"), got.RemoteEndPoint);

        var reply = Take(packets);
        AssertTransportChecksum(reply, IpPacket.ProtocolUdp);
        Assert.Equal("pong", Encoding.ASCII.GetString(reply, IpHeader + 8, reply.Length - IpHeader - 8));
    }

    [Fact]
    public void Multicast_and_link_local_are_not_forwarded()
    {
        var packets = new BlockingCollection<byte[]>();
        using var forwarder = new UserspaceForwarder(packets.Add);
        var multicast = new IpAddr((UInt128)0xFF02000000000000UL << 64 | 0xFB, true);
        var linkLocal = new IpAddr((UInt128)0xFE80000000000000UL << 64 | 1, true);

        foreach (var target in new[] { multicast, linkLocal })
        {
            var p = IpPacket.Udp(Client, 5353, target, 5353, Encoding.ASCII.GetBytes("x"));
            forwarder.HandleOutbound(p, p.Length);
        }
        Assert.Equal(0, forwarder.OpenFlows);
    }

    [Fact]
    public void Unreachable_udp_destination_does_not_throw()
    {
        var packets = new BlockingCollection<byte[]>();
        using var forwarder = new UserspaceForwarder(packets.Add);
        var p = IpPacket.Udp(0x0A6F0002, ClientPort, 0x7F000001, 0, Encoding.ASCII.GetBytes("x"));
        forwarder.HandleOutbound(p, p.Length);
    }

    [Fact]
    public void Dissector_reads_a_raw_ipv6_packet()
    {
        var packet = IpPacket.Tcp(Client, ClientPort, Server, 443, 7, 0, IpPacket.Syn, 65535, default, 1440);
        var raw = new RawPacket { Number = 1, Data = packet, OriginalLength = packet.Length, LinkType = 101 };
        var row = new CaptureDissector().Dissect(raw, 0).ToRow();
        Assert.Equal("TCP", row.Protocol);
        Assert.Equal("::1", row.Destination);
    }
}
