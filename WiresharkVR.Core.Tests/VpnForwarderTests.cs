using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using WiresharkVR.Core.Native;
using WiresharkVR.Core.Vpn;
using Xunit;

namespace WiresharkVR.Core.Tests;

/// <summary>Plays the part of the device behind the tunnel, against real local servers.</summary>
public class VpnForwarderTests
{
    const uint Client = 0x0A6F0002, Server = 0x7F000001;
    const ushort ClientPort = 40000;
    static readonly TimeSpan Timeout = TimeSpan.FromSeconds(15);

    sealed class Seg
    {
        public required byte[] Raw;
        public uint Seq, Ack;
        public byte Flags;
        public byte[] Data = Array.Empty<byte>();
    }

    sealed class FakeDevice : IDisposable
    {
        public readonly BlockingCollection<byte[]> FromTunnel = new();
        public readonly UserspaceForwarder Forwarder;
        public readonly ushort ServerPort;
        public uint Seq = 1000, Ack;

        public FakeDevice(ushort serverPort)
        {
            ServerPort = serverPort;
            Forwarder = new UserspaceForwarder(FromTunnel.Add);
        }

        public void Send(byte flags, byte[]? data = null)
        {
            data ??= Array.Empty<byte>();
            var p = IpPacket.Tcp(Client, ClientPort, Server, ServerPort, Seq, Ack, flags, 65535, data);
            Forwarder.HandleOutbound(p, p.Length);
            Seq += (uint)data.Length + ((flags & (IpPacket.Syn | IpPacket.Fin)) != 0 ? 1u : 0u);
        }

        public Seg Next()
        {
            Assert.True(FromTunnel.TryTake(out var p, Timeout), "No packet came back through the tunnel.");
            return Parse(p!);
        }

        public void Handshake()
        {
            Send(IpPacket.Syn);
            var synAck = Next();
            Assert.Equal(IpPacket.Syn | IpPacket.Ack, synAck.Flags);
            Assert.Equal(Seq, synAck.Ack);
            Ack = synAck.Seq + 1;
            Send(IpPacket.Ack);
        }

        public void Dispose() => Forwarder.Dispose();
    }

    static Seg Parse(byte[] p)
    {
        Assert.Equal(0, IpChecksum(p.AsSpan(0, 20)));
        int headerLength = (p[32] >> 4) * 4;
        return new Seg
        {
            Raw = p,
            Seq = BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(24)),
            Ack = BinaryPrimitives.ReadUInt32BigEndian(p.AsSpan(28)),
            Flags = p[33],
            Data = p.AsSpan(20 + headerLength).ToArray(),
        };
    }

    static int IpChecksum(ReadOnlySpan<byte> header) => IpPacket.Checksum(header);

    [Fact]
    public async Task Tcp_echo_round_trip_and_close()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            var s = c.GetStream();
            var buffer = new byte[64];
            int n = await s.ReadAsync(buffer);
            await s.WriteAsync(Encoding.ASCII.GetBytes("echo:" + Encoding.ASCII.GetString(buffer, 0, n)));
        });

        using var device = new FakeDevice((ushort)((IPEndPoint)listener.LocalEndpoint).Port);
        device.Handshake();
        device.Send(IpPacket.Psh | IpPacket.Ack, Encoding.ASCII.GetBytes("hello"));

        var text = new StringBuilder();
        bool serverFinished = false;
        while (!serverFinished)
        {
            var s = device.Next();
            if (s.Data.Length > 0) text.Append(Encoding.ASCII.GetString(s.Data));
            if (s.Data.Length > 0 || (s.Flags & IpPacket.Fin) != 0)
            {
                device.Ack = s.Seq + (uint)s.Data.Length + ((s.Flags & IpPacket.Fin) != 0 ? 1u : 0u);
                device.Send(IpPacket.Ack);
            }
            serverFinished = (s.Flags & IpPacket.Fin) != 0;
        }
        await server;
        Assert.Equal("echo:hello", text.ToString());

        device.Send(IpPacket.Fin | IpPacket.Ack);
        var deadline = DateTime.UtcNow + Timeout;
        while (device.Forwarder.OpenFlows > 0 && DateTime.UtcNow < deadline) await Task.Delay(20);
        Assert.Equal(0, device.Forwarder.OpenFlows);
    }

    [Fact]
    public async Task Large_download_arrives_intact_despite_lost_packets()
    {
        var payload = RandomNumberGenerator.GetBytes(2 * 1024 * 1024);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            await c.GetStream().WriteAsync(payload);
        });

        using var device = new FakeDevice((ushort)((IPEndPoint)listener.LocalEndpoint).Port);
        device.Handshake();

        using var received = new MemoryStream();
        int count = 0;
        while (true)
        {
            var s = device.Next();
            if (++count % 97 == 0) continue; // the lost packet is never acknowledged, so it must be sent again

            if (s.Seq == device.Ack)
            {
                received.Write(s.Data);
                device.Ack += (uint)s.Data.Length;
                if ((s.Flags & IpPacket.Fin) != 0) { device.Ack++; device.Send(IpPacket.Ack); break; }
            }
            device.Send(IpPacket.Ack);
        }
        await server;
        Assert.Equal(SHA256.HashData(payload), SHA256.HashData(received.ToArray()));
    }

    [Fact]
    public async Task Large_upload_arrives_intact()
    {
        var payload = RandomNumberGenerator.GetBytes(512 * 1024);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var server = Task.Run(async () =>
        {
            using var c = await listener.AcceptTcpClientAsync();
            using var all = new MemoryStream();
            await c.GetStream().CopyToAsync(all);
            return all.ToArray();
        });

        using var device = new FakeDevice((ushort)((IPEndPoint)listener.LocalEndpoint).Port);
        device.Handshake();
        for (int offset = 0; offset < payload.Length; offset += UserspaceForwarder.Mss)
        {
            device.Send(IpPacket.Ack, payload.AsSpan(offset, Math.Min(UserspaceForwarder.Mss, payload.Length - offset)).ToArray());
            device.Next();
        }
        device.Send(IpPacket.Fin | IpPacket.Ack);
        Assert.Equal(SHA256.HashData(payload), SHA256.HashData(await server));
    }

    [Fact]
    public void Refused_connection_resets_the_client()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = (ushort)((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();

        using var device = new FakeDevice(port);
        device.Send(IpPacket.Syn);
        Assert.True((device.Next().Flags & IpPacket.Rst) != 0);
    }

    [Fact]
    public void Segment_for_unknown_flow_gets_a_reset()
    {
        using var device = new FakeDevice(1);
        device.Send(IpPacket.Ack);
        Assert.True((device.Next().Flags & IpPacket.Rst) != 0);
    }

    [Fact]
    public async Task Udp_round_trip()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = (ushort)((IPEndPoint)server.Client.LocalEndPoint!).Port;
        using var device = new FakeDevice(port);

        var request = IpPacket.Udp(Client, ClientPort, Server, port, Encoding.ASCII.GetBytes("ping"));
        device.Forwarder.HandleOutbound(request, request.Length);

        var got = await server.ReceiveAsync();
        Assert.Equal("ping", Encoding.ASCII.GetString(got.Buffer));
        await server.SendAsync(Encoding.ASCII.GetBytes("pong"), got.RemoteEndPoint);

        Assert.True(device.FromTunnel.TryTake(out var reply, Timeout));
        Assert.Equal(IpPacket.ProtocolUdp, reply![9]);
        Assert.Equal(port, BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(20)));
        Assert.Equal("pong", Encoding.ASCII.GetString(reply, 28, reply.Length - 28));
    }

    [Fact]
    public async Task Live_capture_saves_a_readable_file_and_dissects_rows()
    {
        string path = Path.GetTempFileName();
        try
        {
            var packet = IpPacket.Tcp(Client, ClientPort, Server, 443, 7, 0, IpPacket.Syn, 65535, default, 1460);
            using (var capture = new LiveCapture(path))
            {
                capture.Add(packet);
                using var cts = new CancellationTokenSource(Timeout);
                await foreach (var row in capture.RowsAsync(cts.Token))
                {
                    Assert.Equal(1, row.Number);
                    Assert.Equal("TCP", row.Protocol);
                    Assert.Equal("10.111.0.2", row.Source);
                    Assert.NotNull(capture.Detail(1));
                    break;
                }
            }

            var saved = CaptureFileReader.Read(path);
            Assert.Single(saved);
            Assert.Equal(packet, saved[0].Data);
            Assert.Equal(101, saved[0].LinkType);
        }
        finally { File.Delete(path); }
    }
}
