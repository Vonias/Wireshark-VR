using WiresharkVR.Core;
using Xunit;

namespace WiresharkVR.Core.Tests;

public class WiresharkPaneTests
{
    static string Sample()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "samples", "loopback-http.pcapng")))
            dir = dir.Parent;
        return Path.Combine(dir!.FullName, "samples", "loopback-http.pcapng");
    }

    [Fact]
    public async Task PacketListMatchesWireshark()
    {
        var rows = await new TsharkRunner().ListPacketsAsync(Sample());
        Assert.Equal(10, rows.Count);
        Assert.Equal("TCP", rows[0].Protocol);
        Assert.Contains("[SYN]", rows[0].Info);
        Assert.Equal("HTTP", rows[3].Protocol);
    }

    [Fact]
    public async Task DisplayFilterNarrowsList()
    {
        var rows = await new TsharkRunner().ListPacketsAsync(Sample(), "http");
        Assert.Equal(2, rows.Count);
    }

    [Fact]
    public async Task BadDisplayFilterGivesReadableError()
    {
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => new TsharkRunner().ListPacketsAsync(Sample(), "tcp.nonsense =="));
        Assert.False(string.IsNullOrWhiteSpace(ex.Message));
    }

    [Fact]
    public async Task DetailHasTreeAndBytes()
    {
        var d = await new TsharkRunner().GetDetailAsync(Sample(), 4);
        Assert.Contains(d.Tree, n => n.Label.StartsWith("Transmission Control Protocol"));
        Assert.Equal(228, d.Bytes.Length);
        Assert.Equal(0x47, d.Bytes[0x40]); // 'G' of "GET"
        var src = d.Find("tcp.srcport");
        Assert.NotNull(src);
        Assert.Equal("49931", src!.Show);
        Assert.True(src.Size == 2);
    }

    [Fact]
    public async Task FollowStreamShowsHttpText()
    {
        var text = await new TsharkRunner().FollowStreamAsync(Sample(), "tcp", 0);
        Assert.Contains("GET /hello", text);
    }

    [Fact]
    public async Task ProtocolHierarchyReport()
    {
        var text = await new TsharkRunner().StatisticAsync(Sample(), "io,phs");
        Assert.Contains("http", text);
    }
}
