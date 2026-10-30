using WiresharkVR.Core;
using Xunit;

namespace WiresharkVR.Core.Tests;

public class CaptureReplayTests
{
    static PacketRow Row(int number, double time) => new(number, time, "a", "b", "TCP", 60, "info");

    [Fact]
    public async Task Loops_with_rising_numbers_and_time()
    {
        var source = new[] { Row(5, 1.0), Row(9, 1.5) };
        using var cts = new CancellationTokenSource();
        var got = new List<PacketRow>();

        try
        {
            await foreach (var row in CaptureReplay.StreamAsync(source, cts.Token))
            {
                got.Add(row);
                if (got.Count == 5) cts.Cancel();
            }
        }
        catch (OperationCanceledException) { }

        Assert.Equal(new[] { 1, 2, 3, 4, 5 }, got.Select(r => r.Number));
        for (int i = 1; i < got.Count; i++) Assert.True(got[i].RelativeTime > got[i - 1].RelativeTime);
    }

    [Fact]
    public async Task Empty_source_ends_immediately()
    {
        await foreach (var _ in CaptureReplay.StreamAsync(Array.Empty<PacketRow>()))
            Assert.Fail("No rows expected.");
    }

    [Fact]
    public void Delay_stays_within_steady_limits()
    {
        Assert.Equal(15, CaptureReplay.PacketDelay(new[] { Row(1, 0), Row(2, 0.0001) }).TotalMilliseconds);
        Assert.Equal(120, CaptureReplay.PacketDelay(new[] { Row(1, 0), Row(2, 60) }).TotalMilliseconds);
    }
}
