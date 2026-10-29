namespace WiresharkVR.Core;

public static class ConversationBuilder
{
    /// <summary>Groups packets into conversations by stream key, falling back to the endpoint pair.</summary>
    public static List<Conversation> Build(IEnumerable<Packet> packets)
    {
        var map = new Dictionary<string, Conversation>();
        foreach (var p in packets)
        {
            if (p.Source == null || p.Destination == null) continue;

            var a = p.SourcePort != null ? $"{p.Source}:{p.SourcePort}" : p.Source;
            var b = p.DestinationPort != null ? $"{p.Destination}:{p.DestinationPort}" : p.Destination;
            // Order endpoints so both directions land in the same conversation.
            if (string.CompareOrdinal(a, b) > 0) (a, b) = (b, a);

            var key = p.StreamKey ?? $"{a}<->{b}";
            if (!map.TryGetValue(key, out var conv))
                map[key] = conv = new Conversation { Key = key, EndpointA = a, EndpointB = b };
            conv.Packets.Add(p);
        }
        return map.Values.OrderBy(c => c.Start).ToList();
    }
}
