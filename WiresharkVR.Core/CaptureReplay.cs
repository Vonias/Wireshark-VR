using System.Runtime.CompilerServices;

namespace WiresharkVR.Core;

/// <summary>
/// Plays captured packets back as an endless stream at a steady pace. This is a replay of a recording,
/// not live traffic, so the interface must label it as such.
/// </summary>
public static class CaptureReplay
{
    const double MinDelayMs = 15, MaxDelayMs = 120;

    public static TimeSpan PacketDelay(IReadOnlyList<PacketRow> source)
    {
        if (source.Count < 2) return TimeSpan.FromMilliseconds(MaxDelayMs);
        double averageMs = (source[^1].RelativeTime - source[0].RelativeTime) * 1000 / (source.Count - 1);
        return TimeSpan.FromMilliseconds(Math.Clamp(averageMs, MinDelayMs, MaxDelayMs));
    }

    /// <summary>Repeats the source forever. Rows are renumbered from 1 so time and numbering keep rising across loops.</summary>
    public static async IAsyncEnumerable<PacketRow> StreamAsync(
        IReadOnlyList<PacketRow> source, [EnumeratorCancellation] CancellationToken ct = default)
    {
        if (source.Count == 0) yield break;

        var delay = PacketDelay(source);
        double start = source[0].RelativeTime;
        double loopLength = source[^1].RelativeTime - start + delay.TotalSeconds;
        for (long number = 1; ; number++)
        {
            await Task.Delay(delay, ct).ConfigureAwait(false);
            int index = (int)((number - 1) % source.Count);
            long loop = (number - 1) / source.Count;
            var row = source[index];
            yield return row with { Number = (int)number, RelativeTime = row.RelativeTime - start + loop * loopLength };
        }
    }
}
