namespace WiresharkVR.App;

/// <summary>Plain-English explanations shown when Guide mode is on.</summary>
static class Guide
{
	public const string Main =
		"Start here. Menus are along the top; the Filter box decides which packets you see.\n" +
		"Filters are just rules: 'tcp', 'http', 'ip.addr == 10.0.0.1', 'tcp.port == 443'.";

	public const string Filter =
		"Type a rule, then press Apply. Packets that don't match are hidden (not deleted).\n" +
		"Green message = rule understood. Red = typo. Or tap one of the shortcuts below.";

	public const string PacketList =
		"PACKET LIST - one row per packet that crossed the wire. Click a row to inspect it.\n" +
		"Colours: purple = TCP, blue = UDP, green = HTTP, grey = connection open/close, red = a problem or reset.";

	public const string Details =
		"PACKET DETAILS - the selected packet, unwrapped layer by layer (outer layer first).\n" +
		"Tap a line to open it. Tap a field to see exactly which bytes it lives in.";

	public const string Bytes =
		"PACKET BYTES - the raw data exactly as it travelled. Left: position, middle: hex, right: text.\n" +
		"CAPITAL hex letters are the bytes of the field you tapped in the details pane.";

	public const string CheatSheet =
@"WIRESHARK IN 60 SECONDS

1. A capture is a recording of network traffic. Each row is one packet.
2. Click a packet. The Details pane shows its layers, like envelopes inside envelopes:
     Frame  -> the capture's own wrapper
     Ethernet/Null -> the local network hop
     IP -> who sent it and who it's for
     TCP/UDP -> which program (port), plus reliability for TCP
     HTTP/DNS/... -> the actual message
3. The Bytes pane is the same packet as raw hex.
4. Filters hide everything except what you care about:
     tcp               only TCP
     http              only web traffic
     ip.addr == X      anything to or from X
     tcp.port == 443   a given port
     tcp.flags.syn==1  connection openers
     !(arp)            everything except ARP
5. Analyze > Follow Stream stitches a conversation back into readable text.
6. Statistics shows summaries: which protocols, which conversations.

TCP handshake: SYN -> SYN-ACK -> ACK. Data flows. FIN (polite) or RST (abrupt) ends it.";
}
