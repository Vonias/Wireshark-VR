using WiresharkVR.Core;

namespace WiresharkVR.App;

/// <summary>Plain-English captions that explain what a packet is doing.</summary>
static class Lesson
{
	public static string Explain(Packet p)
	{
		var tcp = p.GetLayer("tcp");
		if (tcp == null) return $"A {p.Protocol} packet.";

		bool syn = tcp.Get("tcp.flags.syn") == "1";
		bool ack = tcp.Get("tcp.flags.ack") == "1";
		bool fin = tcp.Get("tcp.flags.fin") == "1";
		bool rst = tcp.Get("tcp.flags.reset") == "1";
		bool hasData = (tcp.Get("tcp.len") ?? "0") != "0";

		if (rst) return "RST: one side slams the connection shut immediately (no polite goodbye).";
		if (syn && !ack) return "SYN: handshake step 1. The client asks to open a connection.";
		if (syn && ack) return "SYN-ACK: handshake step 2. The server agrees and sends its own sequence number.";
		if (fin) return "FIN: this side has finished sending and starts a polite close.";
		if (p.Protocol == "http" && hasData)
			return "HTTP rides inside TCP. This packet carries the request or response text itself.";
		if (ack && !hasData)
			return "ACK: 'I received everything up to this point.' With no data, it is pure bookkeeping "
			     + "(or handshake step 3 if it follows a SYN-ACK).";
		if (hasData) return "A TCP segment carrying application data.";
		return "A TCP packet.";
	}
}
