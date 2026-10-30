using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Threading.Channels;
using WiresharkVR.Core.Native;

namespace WiresharkVR.Core.Vpn;

/// <summary>
/// Receives raw IP packets from the tunnel: saves them to a pcap file and dissects them into rows
/// for the packet list. Recent packets stay in memory so a paused stream can be inspected.
/// </summary>
public sealed class LiveCapture : IDisposable
{
    const int  RawIpLinkType = 101;
    const int  SnapLength = 65535;
    const int  MaxQueued = 20_000;
    const int  MaxKept = 20_000;
    const long MaxFileBytes = 256L * 1024 * 1024;

    readonly object _gate = new();
    readonly Channel<RawPacket> _incoming = Channel.CreateBounded<RawPacket>(
        new BoundedChannelOptions(MaxQueued) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });
    readonly CaptureDissector _dissector = new();
    readonly Dictionary<int, DissectedPacket> _recent = new();
    readonly Queue<int> _recentOrder = new();
    readonly FileStream _file;
    readonly double _start = Now();
    int _number;

    public string FilePath { get; }
    public bool FileFull { get; private set; }

    public LiveCapture(string pcapPath)
    {
        FilePath = pcapPath;
        _file = new FileStream(pcapPath, FileMode.Create, FileAccess.Write, FileShare.Read);

        Span<byte> header = stackalloc byte[24];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0xA1B2C3D4);
        BinaryPrimitives.WriteUInt16LittleEndian(header[4..], 2);
        BinaryPrimitives.WriteUInt16LittleEndian(header[6..], 4);
        BinaryPrimitives.WriteUInt32LittleEndian(header[16..], SnapLength);
        BinaryPrimitives.WriteUInt32LittleEndian(header[20..], RawIpLinkType);
        _file.Write(header);
    }

    static double Now() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    public void Add(ReadOnlySpan<byte> packet)
    {
        var data = packet.ToArray();
        double time = Now();
        lock (_gate)
        {
            WriteToFile(data, time);
            _incoming.Writer.TryWrite(new RawPacket
            {
                Number = ++_number, Time = time, Data = data, OriginalLength = data.Length, LinkType = RawIpLinkType,
            });
        }
    }

    void WriteToFile(byte[] data, double time)
    {
        if (FileFull) return;
        if (_file.Length >= MaxFileBytes) { FileFull = true; return; }

        Span<byte> record = stackalloc byte[16];
        long microseconds = (long)(time * 1_000_000);
        BinaryPrimitives.WriteUInt32LittleEndian(record, (uint)(microseconds / 1_000_000));
        BinaryPrimitives.WriteUInt32LittleEndian(record[4..], (uint)(microseconds % 1_000_000));
        BinaryPrimitives.WriteUInt32LittleEndian(record[8..], (uint)data.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(record[12..], (uint)data.Length);
        _file.Write(record);
        _file.Write(data);
    }

    public async IAsyncEnumerable<PacketRow> RowsAsync([EnumeratorCancellation] CancellationToken ct = default)
    {
        await foreach (var raw in _incoming.Reader.ReadAllAsync(ct).ConfigureAwait(false))
        {
            var dissected = _dissector.Dissect(raw, raw.Time - _start);
            lock (_gate)
            {
                _recent[raw.Number] = dissected;
                _recentOrder.Enqueue(raw.Number);
                if (_recentOrder.Count > MaxKept) _recent.Remove(_recentOrder.Dequeue());
            }
            yield return dissected.ToRow();
        }
    }

    /// <summary>Details of a recent packet, or null once it has aged out of memory.</summary>
    public PacketDetail? Detail(int number)
    {
        lock (_gate)
            return _recent.TryGetValue(number, out var dp) ? new PacketDetail { Tree = dp.Tree, Bytes = dp.Raw.Data } : null;
    }

    public void Dispose()
    {
        _incoming.Writer.TryComplete();
        lock (_gate) _file.Dispose();
    }
}
