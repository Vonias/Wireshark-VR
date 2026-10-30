using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace WiresharkVR.Core.Vpn;

/// <summary>
/// Carries the device's traffic while a VPN tunnel captures it. Packets leaving the tunnel are ended here
/// and repeated over ordinary sockets; replies are rebuilt as packets and written back. Only TCP and UDP
/// over IPv4 and IPv6 are forwarded; anything else is left for the capture to record and goes no further.
/// </summary>
public sealed class UserspaceForwarder : IDisposable
{
    public const ushort Mss = 1460, MssV6 = 1440;
    const int V6HeaderLength = 40;

    readonly Action<byte[]> _toTunnel;
    readonly ConcurrentDictionary<(IpAddr, ushort, IpAddr, ushort), TcpFlow> _tcp = new();
    readonly ConcurrentDictionary<(IpAddr, ushort, IpAddr, ushort), UdpFlow> _udp = new();
    readonly CancellationTokenSource _stop = new();

    public UserspaceForwarder(Action<byte[]> toTunnel) => _toTunnel = toTunnel;

    public int OpenFlows => _tcp.Count + _udp.Count;

    public void HandleOutbound(byte[] buffer, int length)
    {
        if (length < 20) return;
        if (buffer[0] >> 4 == 6) { HandleOutboundV6(buffer, length); return; }
        if (buffer[0] >> 4 != 4) return;
        int headerLength = (buffer[0] & 0x0F) * 4;
        int total = Math.Min(BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(2)), length);
        bool fragment = (BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(6)) & 0x3FFF) != 0;
        if (headerLength < 20 || total < headerLength + 8 || fragment) return;

        uint src = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(12));
        uint dst = BinaryPrimitives.ReadUInt32BigEndian(buffer.AsSpan(16));
        var segment = buffer.AsSpan(headerLength, total - headerLength);

        Dispatch(buffer[9], src, dst, segment);
    }

    void HandleOutboundV6(byte[] buffer, int length)
    {
        if (length < V6HeaderLength) return;
        int total = Math.Min(V6HeaderLength + BinaryPrimitives.ReadUInt16BigEndian(buffer.AsSpan(4)), length);
        var src = IpAddr.ReadV6(buffer.AsSpan(8));
        var dst = IpAddr.ReadV6(buffer.AsSpan(24));
        if (dst.IsLocalOnlyV6 || total < V6HeaderLength + 8) return;
        Dispatch(buffer[6], src, dst, buffer.AsSpan(V6HeaderLength, total - V6HeaderLength));
    }

    void Dispatch(byte protocol, IpAddr src, IpAddr dst, ReadOnlySpan<byte> segment)
    {
        if (protocol == IpPacket.ProtocolTcp) HandleTcp(src, dst, segment);
        else if (protocol == IpPacket.ProtocolUdp) HandleUdp(src, dst, segment);
    }

    void HandleTcp(IpAddr src, IpAddr dst, ReadOnlySpan<byte> t)
    {
        if (t.Length < 20) return;
        ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(t);
        ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(t[2..]);
        uint seq = BinaryPrimitives.ReadUInt32BigEndian(t[4..]);
        uint ack = BinaryPrimitives.ReadUInt32BigEndian(t[8..]);
        int dataOffset = (t[12] >> 4) * 4;
        byte flags = t[13];
        ushort window = BinaryPrimitives.ReadUInt16BigEndian(t[14..]);
        if (dataOffset < 20 || dataOffset > t.Length) return;
        var key = (src, srcPort, dst, dstPort);

        if ((flags & IpPacket.Syn) != 0 && (flags & IpPacket.Ack) == 0)
        {
            if (_tcp.TryGetValue(key, out var existing))
            {
                if (existing.ClientIsn == seq) return; // retransmitted SYN while connecting
                existing.Abort(false);
            }
            var flow = new TcpFlow(this, key, seq, window);
            _tcp[key] = flow;
            flow.Start(_stop.Token);
            return;
        }

        if (_tcp.TryGetValue(key, out var open))
            open.OnClientSegment(seq, ack, flags, window, t[dataOffset..]);
        else if ((flags & IpPacket.Rst) == 0)
            _toTunnel(IpPacket.Tcp(dst, dstPort, src, srcPort, ack, seq + 1, (byte)(IpPacket.Rst | IpPacket.Ack), 0, default));
    }

    void HandleUdp(IpAddr src, IpAddr dst, ReadOnlySpan<byte> u)
    {
        if (u.Length < 8) return;
        ushort srcPort = BinaryPrimitives.ReadUInt16BigEndian(u);
        ushort dstPort = BinaryPrimitives.ReadUInt16BigEndian(u[2..]);
        int length = Math.Min(BinaryPrimitives.ReadUInt16BigEndian(u[4..]), u.Length);
        if (length < 8) return;

        var key = (src, srcPort, dst, dstPort);
        try
        {
            var flow = _udp.GetOrAdd(key, k => new UdpFlow(this, k, _stop.Token));
            flow.Send(u[8..length]);
        }
        catch (SocketException) { } // unreachable: drop it, as a real network would
    }

    public void Dispose()
    {
        _stop.Cancel();
        foreach (var flow in _tcp.Values) flow.Abort(true);
        foreach (var flow in _udp.Values) flow.Close();
    }

    static IPEndPoint Endpoint(IpAddr address, ushort port) => new(address.ToIPAddress(), port);

    static AddressFamily Family(IpAddr address) =>
        address.IsV6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork;

    // ---- UDP ---------------------------------------------------------------

    sealed class UdpFlow
    {
        static readonly TimeSpan Idle = TimeSpan.FromSeconds(60);

        readonly UserspaceForwarder _owner;
        readonly (IpAddr src, ushort srcPort, IpAddr dst, ushort dstPort) _key;
        readonly Socket _socket;
        readonly CancellationTokenSource _cts;
        int _closed;

        public UdpFlow(UserspaceForwarder owner, (IpAddr, ushort, IpAddr, ushort) key, CancellationToken stop)
        {
            _owner = owner;
            _key = key;
            _socket = new Socket(Family(_key.dst), SocketType.Dgram, ProtocolType.Udp);
            _cts = CancellationTokenSource.CreateLinkedTokenSource(stop);
            _cts.CancelAfter(Idle);
            _socket.Connect(Endpoint(_key.dst, _key.dstPort));
            _ = ReceiveLoop();
        }

        public void Send(ReadOnlySpan<byte> payload)
        {
            try
            {
                _cts.CancelAfter(Idle);
                _socket.Send(payload);
            }
            catch (Exception e) when (e is SocketException or ObjectDisposedException) { Close(); }
        }

        async Task ReceiveLoop()
        {
            var buffer = new byte[65535];
            try
            {
                while (true)
                {
                    int read = await _socket.ReceiveAsync(buffer, SocketFlags.None, _cts.Token).ConfigureAwait(false);
                    _cts.CancelAfter(Idle);
                    _owner._toTunnel(IpPacket.Udp(_key.dst, _key.dstPort, _key.src, _key.srcPort, buffer.AsSpan(0, read)));
                }
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException) { }
            Close();
        }

        public void Close()
        {
            if (Interlocked.Exchange(ref _closed, 1) != 0) return;
            _owner._udp.TryRemove(_key, out _);
            _socket.Dispose();
        }
    }

    // ---- TCP ---------------------------------------------------------------

    /// <summary>A small TCP endpoint facing the tunnel, joined to a real socket facing the server.</summary>
    sealed class TcpFlow
    {
        const int MaxToServerBytes = 1 << 20;
        const int MaxResends = 8;
        const ushort ReceiveWindow = 65535;
        static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(10);
        static readonly TimeSpan ResendAfter = TimeSpan.FromMilliseconds(250);
        const int DuplicateAcksBeforeResend = 3;

        readonly record struct Segment(uint Seq, byte[] Data, byte Flags, ushort Mss)
        {
            public uint Length => (uint)Data.Length + ((Flags & (IpPacket.Syn | IpPacket.Fin)) != 0 ? 1u : 0u);
        }

        readonly UserspaceForwarder _owner;
        readonly (IpAddr src, ushort srcPort, IpAddr dst, ushort dstPort) _key;
        readonly object _gate = new();
        readonly Queue<Segment> _unacked = new();
        readonly Channel<byte[]> _toServer = Channel.CreateUnbounded<byte[]>();
        readonly SemaphoreSlim _windowChanged = new(0);
        readonly Socket _socket;
        readonly ushort _mss;
        CancellationTokenSource? _cts;

        public uint ClientIsn { get; }
        uint _clientNext, _sendUnacked, _sendNext;
        ushort _clientWindow;
        int _queuedToServer, _resends, _duplicateAcks;
        long _lastSendTicks;
        bool _connected, _clientFin, _serverFin, _closed;

        public TcpFlow(UserspaceForwarder owner, (IpAddr, ushort, IpAddr, ushort) key, uint clientIsn, ushort window)
        {
            _owner = owner;
            _key = key;
            ClientIsn = clientIsn;
            _clientNext = clientIsn + 1;
            _clientWindow = window;
            _mss = _key.dst.IsV6 ? MssV6 : Mss;
            _socket = new Socket(Family(_key.dst), SocketType.Stream, ProtocolType.Tcp);
            _sendUnacked = _sendNext = (uint)Random.Shared.NextInt64(uint.MaxValue);
            _socket.NoDelay = true;
        }

        public void Start(CancellationToken stop)
        {
            _cts = CancellationTokenSource.CreateLinkedTokenSource(stop);
            _ = Run(_cts.Token);
        }

        async Task Run(CancellationToken ct)
        {
            try
            {
                using (var connect = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    connect.CancelAfter(ConnectTimeout);
                    await _socket.ConnectAsync(Endpoint(_key.dst, _key.dstPort), connect.Token).ConfigureAwait(false);
                }

                lock (_gate)
                {
                    _connected = true;
                    Transmit(Array.Empty<byte>(), (byte)(IpPacket.Syn | IpPacket.Ack), _mss);
                }
                await Task.WhenAll(PumpToClient(ct), PumpToServer(ct), ResendLoop(ct)).ConfigureAwait(false);
            }
            catch (Exception e) when (e is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                Abort(true);
            }
        }

        public void OnClientSegment(uint seq, uint ack, byte flags, ushort window, ReadOnlySpan<byte> payload)
        {
            lock (_gate)
            {
                if (_closed) return;
                if ((flags & IpPacket.Rst) != 0) { Abort(false); return; }

                _clientWindow = window;
                if ((flags & IpPacket.Ack) != 0) Acknowledged(ack);
                ReleaseWindowWaiter();

                bool fin = (flags & IpPacket.Fin) != 0;
                if (payload.IsEmpty && !fin) { CloseIfFinished(); return; }
                if (!_connected) return;

                int ahead = (int)(seq - _clientNext);
                if (ahead > 0) { SendAck(); return; } // out of order: the client will resend

                int skip = -ahead;
                if (skip > payload.Length || (skip == payload.Length && !fin)) { SendAck(); return; }

                var fresh = payload[skip..];
                if (!fresh.IsEmpty)
                {
                    if (_queuedToServer + fresh.Length > MaxToServerBytes) return; // no ACK, so the client backs off
                    _queuedToServer += fresh.Length;
                    _toServer.Writer.TryWrite(fresh.ToArray());
                    _clientNext += (uint)fresh.Length;
                }
                if (fin && !_clientFin)
                {
                    _clientNext++;
                    _clientFin = true;
                    _toServer.Writer.TryComplete();
                }
                SendAck();
                CloseIfFinished();
            }
        }

        void Acknowledged(uint ack)
        {
            if (ack == _sendUnacked && _unacked.Count > 0)
            {
                if (++_duplicateAcks == DuplicateAcksBeforeResend) ResendAll();
                return;
            }
            if ((int)(ack - _sendUnacked) <= 0 || (int)(ack - _sendNext) > 0) return;
            _sendUnacked = ack;
            _resends = 0;
            _duplicateAcks = 0;
            while (_unacked.TryPeek(out var front) && (int)(front.Seq + front.Length - ack) <= 0) _unacked.Dequeue();
        }

        async Task PumpToServer(CancellationToken ct)
        {
            await foreach (var chunk in _toServer.Reader.ReadAllAsync(ct).ConfigureAwait(false))
            {
                await _socket.SendAsync(chunk, SocketFlags.None, ct).ConfigureAwait(false);
                lock (_gate) _queuedToServer -= chunk.Length;
            }
            _socket.Shutdown(SocketShutdown.Send);
        }

        async Task PumpToClient(CancellationToken ct)
        {
            var buffer = new byte[_mss];
            while (true)
            {
                int room;
                lock (_gate) room = Math.Min(_mss, _clientWindow - (int)(_sendNext - _sendUnacked));
                if (room <= 0)
                {
                    await _windowChanged.WaitAsync(200, ct).ConfigureAwait(false);
                    continue;
                }

                int read = await _socket.ReceiveAsync(buffer.AsMemory(0, room), SocketFlags.None, ct).ConfigureAwait(false);
                lock (_gate)
                {
                    if (read == 0)
                    {
                        _serverFin = true;
                        Transmit(Array.Empty<byte>(), (byte)(IpPacket.Fin | IpPacket.Ack), 0);
                        return;
                    }
                    Transmit(buffer.AsSpan(0, read).ToArray(), (byte)(IpPacket.Psh | IpPacket.Ack), 0);
                }
            }
        }

        async Task ResendLoop(CancellationToken ct)
        {
            while (true)
            {
                await Task.Delay(100, ct).ConfigureAwait(false);
                lock (_gate)
                {
                    if (_closed) return;
                    if (!_unacked.TryPeek(out var front)) continue;
                    if (DateTime.UtcNow.Ticks - _lastSendTicks < ResendAfter.Ticks) continue;
                    if (++_resends > MaxResends) { Abort(true); return; }
                    ResendAll();
                }
            }
        }

        void ResendAll()
        {
            foreach (var segment in _unacked) Emit(segment);
        }

        void Transmit(byte[] data, byte flags, ushort mss)
        {
            var segment = new Segment(_sendNext, data, flags, mss);
            _sendNext += segment.Length;
            _unacked.Enqueue(segment);
            Emit(segment);
        }

        void Emit(Segment s)
        {
            _lastSendTicks = DateTime.UtcNow.Ticks;
            _owner._toTunnel(IpPacket.Tcp(_key.dst, _key.dstPort, _key.src, _key.srcPort,
                s.Seq, _clientNext, s.Flags, ReceiveWindow, s.Data, s.Mss));
        }

        void SendAck() =>
            _owner._toTunnel(IpPacket.Tcp(_key.dst, _key.dstPort, _key.src, _key.srcPort,
                _sendNext, _clientNext, IpPacket.Ack, ReceiveWindow, default));

        void ReleaseWindowWaiter()
        {
            if (_windowChanged.CurrentCount == 0) _windowChanged.Release();
        }

        void CloseIfFinished()
        {
            if (_clientFin && _serverFin && _unacked.Count == 0) Abort(false);
        }

        public void Abort(bool tellClient)
        {
            lock (_gate)
            {
                if (_closed) return;
                _closed = true;
                if (tellClient)
                    _owner._toTunnel(IpPacket.Tcp(_key.dst, _key.dstPort, _key.src, _key.srcPort,
                        _sendNext, _clientNext, (byte)(IpPacket.Rst | IpPacket.Ack), 0, default));
            }
            _owner._tcp.TryRemove(new KeyValuePair<(IpAddr, ushort, IpAddr, ushort), TcpFlow>(_key, this));
            _toServer.Writer.TryComplete();
            _cts?.Cancel();
            _socket.Dispose();
        }
    }
}
