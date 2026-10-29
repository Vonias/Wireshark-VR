namespace WiresharkVR.Core;

/// <summary>
/// Something that can turn a capture file into Wireshark-style panes. Two implementations exist:
/// <see cref="TsharkRunner"/> (full Wireshark fidelity, PC only) and Native.NativeEngine
/// (pure C#, runs anywhere including a standalone Quest).
/// </summary>
public interface ICaptureEngine
{
    string Name { get; }

    Task<List<PacketRow>> ListPacketsAsync(string pcapPath, string? displayFilter = null, CancellationToken ct = default);
    Task<PacketDetail> GetDetailAsync(string pcapPath, int packetNumber, CancellationToken ct = default);
    Task<string> StatisticAsync(string pcapPath, string statistic, string? displayFilter = null, CancellationToken ct = default);
    Task<string> FollowStreamAsync(string pcapPath, string protocol, int streamIndex, CancellationToken ct = default);
    Task<List<Packet>> ReadFileAsync(string pcapPath, int maxPackets = 0, CancellationToken ct = default);
}

public static class CaptureEngine
{
    /// <summary>Picks tshark when it is installed (PC), otherwise the built-in dissector (headset).</summary>
    public static ICaptureEngine Create(bool forceNative = false)
    {
        if (!forceNative && TsharkRunner.Locate() != null) return new TsharkRunner();
        return new Native.NativeEngine();
    }
}
