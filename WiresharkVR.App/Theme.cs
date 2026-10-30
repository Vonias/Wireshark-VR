using StereoKit;
using WiresharkVR.Core;

namespace WiresharkVR.App;

/// <summary>Wireshark's look: its accent blue on dark panels, and its default packet colouring rules.</summary>
static class Theme
{
	public static readonly Color Accent     = Color.Hex(0x1679A7FF);
	public static readonly Color Panel      = Color.Hex(0x20262CFF);
	public static readonly Color HeaderBg   = Color.Hex(0x39424BFF);
	public static readonly Color HeaderText = Color.Hex(0xE8EDF1FF);
	public static readonly Color DarkText   = Color.Hex(0x12272EFF);
	public static readonly Color SelectedBg = Color.Hex(0x3875D7FF);
	public static readonly Color Good       = Color.Hex(0xAFFFAFFF);
	public static readonly Color Bad        = Color.Hex(0xFFAFAFFF);
	public static readonly Color Warn       = Color.Hex(0xFFE08AFF);

	static readonly Color TcpBg     = Color.Hex(0xE7E6FFFF);
	static readonly Color UdpBg     = Color.Hex(0xDAEEFFFF);
	static readonly Color HttpBg    = Color.Hex(0xE4FFC7FF);
	static readonly Color IcmpBg    = Color.Hex(0xFCE0FFFF);
	static readonly Color ArpBg     = Color.Hex(0xFAF0D7FF);
	static readonly Color SynFinBg  = Color.Hex(0xA0A0A0FF);
	static readonly Color ResetBg   = Color.Hex(0xA40000FF);
	static readonly Color ResetText = Color.Hex(0xFFFC9CFF);
	static readonly Color BadTcpBg  = Color.Hex(0x121212FF);
	static readonly Color BadTcpTxt = Color.Hex(0xF78787FF);
	static readonly Color OtherBg   = Color.Hex(0xF2F2F2FF);

	public static void Apply()
	{
		UI.ColorScheme = Accent;
		UI.SetThemeColor(UIColor.Background, Panel);
		UI.SetThemeColor(UIColor.Common, HeaderBg);
		UI.SetThemeColor(UIColor.Text, HeaderText);

		UISettings settings = UI.Settings;
		settings.rounding = 0.5f * U.cm;
		UI.Settings = settings;

		Renderer.EnableSky  = false;
		Renderer.ClearColor = Color.Hex(0x0D1216FF).ToLinear();
	}

	/// <summary>Wireshark's default rules, most specific first.</summary>
	public static (Color bg, Color fg) RowColors(PacketRow r)
	{
		if (r.Info.Contains("Malformed") || r.Info.Contains("Retransmission") || r.Info.Contains("Out-Of-Order"))
			return (BadTcpBg, BadTcpTxt);
		if (r.Info.Contains("[RST"))                             return (ResetBg, ResetText);
		if (r.Info.Contains("[SYN") || r.Info.Contains("[FIN"))  return (SynFinBg, DarkText);
		return (ProtocolColor(r.Protocol), DarkText);
	}

	public static Color ProtocolColor(string protocol) => protocol.ToUpperInvariant() switch
	{
		"HTTP" or "HTTP2"                                 => HttpBg,
		"TCP" or "TLSV1" or "TLSV1.2" or "TLSV1.3" or "SSL" => TcpBg,
		"UDP" or "DNS" or "QUIC" or "MDNS" or "DHCP"      => UdpBg,
		"ICMP" or "ICMPV6"                                => IcmpBg,
		"ARP"                                             => ArpBg,
		_                                                 => OtherBg,
	};
}
