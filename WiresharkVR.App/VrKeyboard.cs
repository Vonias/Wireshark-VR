using System;
using System.Collections.Generic;
using System.Linq;
using StereoKit;

namespace WiresharkVR.App;

/// <summary>A floating keyboard for display filters, built to be used with the controller pointers.</summary>
class VrKeyboard
{
	const float KeySize = 5.6f * U.cm;
	const int   MaxSuggestions = 4;

	static readonly string[] Rows =
	{
		"1234567890",
		"qwertyuiop",
		"asdfghjkl.",
		"zxcvbnm:_-",
		"=!<>&|()\"/",
	};

	static readonly string[] Fields =
	{
		"ip.addr", "ip.src", "ip.dst", "ip.proto", "ip.ttl", "ipv6.addr", "ipv6.src", "ipv6.dst",
		"tcp.port", "tcp.srcport", "tcp.dstport", "tcp.stream", "tcp.len", "tcp.flags.syn", "tcp.flags.fin",
		"tcp.flags.reset", "tcp.flags.ack", "udp.port", "udp.srcport", "udp.dstport", "udp.stream",
		"dns.qry.name", "dns.a", "dns.aaaa", "http.host", "http.request.method", "http.request.uri",
		"http.response.code", "frame.len", "frame.number", "icmp.type", "arp.opcode",
		"tcp", "udp", "dns", "http", "icmp", "arp",
	};

	const float ViewDistance = 0.8f;
	const float ViewDrop     = 0.3f;
	const float MaxViewCos   = 0.72f; // about 45 degrees off centre before it moves back into view

	Pose _pose = Pose.Identity;
	bool _shift, _wasOpen, _returning;

	public bool IsOpen { get; set; }

	/// <summary>Draws the keyboard, editing text in place. Returns true when Apply is pressed.</summary>
	public bool Step(ref string text, IReadOnlyList<string> recent)
	{
		bool apply = false;
		StayInView();
		ControllerRays.BeginWindow("Keyboard", ref _pose, new Vec2(74, 0) * U.cm, UIWin.Normal);
		UI.Label(text.Length == 0 ? "Type a display filter" : text + "_");
		Suggestions(ref text, recent);
		UI.HSeparator();

		foreach (string row in Rows)
		{
			foreach (char c in row)
			{
				string label = (_shift ? char.ToUpperInvariant(c) : c).ToString();
				if (PointerUI.Button(label, new Vec2(KeySize, KeySize))) { text += label; _shift = false; }
				if (c != row[^1]) UI.SameLine();
			}
		}

		UI.PushTint(_shift ? Theme.Good : Color.White);
		if (PointerUI.Button("Shift")) _shift = !_shift;
		UI.PopTint();
		UI.SameLine();
		if (PointerUI.Button("Space", new Vec2(16, 0) * U.cm)) text += " ";
		UI.SameLine();
		if (PointerUI.Button("Back") && text.Length > 0) text = text[..^1];
		UI.SameLine();
		if (PointerUI.Button("Erase")) text = "";
		UI.SameLine();
		UI.PushTint(Theme.Good);
		if (PointerUI.Button("Apply")) apply = true;
		UI.PopTint();
		UI.SameLine();
		if (PointerUI.Button("Close")) { IsOpen = false; _wasOpen = false; }
		ControllerRays.EndWindow();
		return apply;
	}

	/// <summary>Opens below the centre of view, and drifts back whenever the user turns away from it.</summary>
	void StayInView()
	{
		Pose head = Input.Head;
		Vec3 ahead = new Vec3(head.Forward.x, 0, head.Forward.z).Normalized;
		Vec3 position = head.position + ahead * ViewDistance + new Vec3(0, -ViewDrop, 0);
		Pose target = new Pose(position, Quat.LookDir(head.position - position));

		if (!_wasOpen) { _pose = target; _wasOpen = true; return; }
		if (ControllerRays.IsGrabbed("Keyboard")) { _returning = false; return; }

		float facing = Vec3.Dot(head.Forward, (_pose.position - head.position).Normalized);
		if (facing < MaxViewCos) _returning = true;
		if (!_returning) return;

		float blend = Math.Min(1f, Time.Stepf * 4f);
		_pose = new Pose(Vec3.Lerp(_pose.position, target.position, blend), Quat.Slerp(_pose.orientation, target.orientation, blend));
		if (Vec3.Distance(_pose.position, target.position) < 2 * U.cm) _returning = false;
	}

	void Suggestions(ref string text, IReadOnlyList<string> recent)
	{
		string word = LastWord(text);
		var options = word.Length > 0
			? Fields.Where(f => f.StartsWith(word, StringComparison.Ordinal) && f != word).Take(MaxSuggestions)
			: text.Length == 0 ? recent.Take(MaxSuggestions) : Enumerable.Empty<string>();

		int shown = 0;
		foreach (string option in options)
		{
			if (shown++ > 0) UI.SameLine();
			if (!PointerUI.Button(option)) continue;
			text = word.Length > 0 ? text[..^word.Length] + option + " " : option;
			break;
		}
		if (shown == 0) UI.Label(" ");
	}

	static string LastWord(string text)
	{
		int start = text.Length;
		while (start > 0 && (char.IsLetterOrDigit(text[start - 1]) || text[start - 1] is '.' or '_')) start--;
		return text[start..];
	}
}
