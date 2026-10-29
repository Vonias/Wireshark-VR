namespace WiresharkVR.Core;

/// <summary>One dissected field, e.g. "tcp.srcport" = "49931". Depth is its nesting level inside the layer.</summary>
public sealed record Field(string Name, string Value, int Depth);

/// <summary>One protocol layer of a packet (frame, eth, ip, tcp, http...).</summary>
public sealed class Layer
{
    public required string Name { get; init; }
    public List<Field> Fields { get; } = new();

    public string? Get(string fieldName) =>
        Fields.FirstOrDefault(f => f.Name == fieldName)?.Value;
}

public sealed class Packet
{
    public int Number { get; init; }
    public DateTimeOffset Time { get; init; }
    public int Length { get; init; }
    public List<Layer> Layers { get; } = new();

    public string? Source { get; set; }
    public string? Destination { get; set; }
    public string? SourcePort { get; set; }
    public string? DestinationPort { get; set; }

    /// <summary>Highest recognized protocol, e.g. "http".</summary>
    public string Protocol => Layers.Count > 0 ? Layers[^1].Name : "";
    public string Info { get; set; } = "";

    /// <summary>Stream key such as "tcp:0", or null when the packet is not part of a tracked stream.</summary>
    public string? StreamKey { get; set; }

    public Layer? GetLayer(string name) => Layers.FirstOrDefault(l => l.Name == name);
}

/// <summary>A set of packets between two endpoints (one TCP/UDP stream).</summary>
public sealed class Conversation
{
    public required string Key { get; init; }
    public required string EndpointA { get; init; }
    public required string EndpointB { get; init; }
    public List<Packet> Packets { get; } = new();
    public DateTimeOffset Start => Packets[0].Time;
    public TimeSpan Duration => Packets[^1].Time - Packets[0].Time;
}
