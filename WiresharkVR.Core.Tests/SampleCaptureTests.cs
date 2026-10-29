using WiresharkVR.Core;
using Xunit;

namespace WiresharkVR.Core.Tests;

public class SampleCaptureTests
{
    static string SamplePath()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "samples", "loopback-http.pcapng")))
            dir = dir.Parent;
        return Path.Combine(dir!.FullName, "samples", "loopback-http.pcapng");
    }

    [Fact]
    public async Task ReadsHandshakeAndHttp()
    {
        var packets = await new TsharkRunner().ReadFileAsync(SamplePath());

        Assert.Equal(10, packets.Count);
        Assert.Contains("SYN", packets[0].Info);
        Assert.Contains("SYN, ACK", packets[1].Info);
        Assert.Equal("::1", packets[0].Source);
        Assert.Equal("8089", packets[0].DestinationPort);
        Assert.Equal("http", packets[3].Protocol);
        Assert.NotNull(packets[0].GetLayer("tcp")?.Get("tcp.seq"));
    }

    [Fact]
    public async Task GroupsPacketsIntoOneConversation()
    {
        var packets = await new TsharkRunner().ReadFileAsync(SamplePath());
        var convs = ConversationBuilder.Build(packets);

        var conv = Assert.Single(convs);
        Assert.Equal(10, conv.Packets.Count);
        Assert.True(conv.Duration > TimeSpan.Zero);
    }
}
