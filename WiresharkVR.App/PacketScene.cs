using System;
using System.Collections.Generic;
using StereoKit;
using WiresharkVR.Core;

namespace WiresharkVR.App;

/// <summary>
/// Ladder diagram of one conversation: two endpoints, time running downward, one arrow per packet.
/// Pinch a packet to open its layers in the inspector window.
/// </summary>
class PacketScene
{
	const float Top        = 0.45f;
	const float HalfWidth  = 0.55f;
	const float MaxSpacing = 0.07f;
	const float TravelTime = 0.6f;
	const int   MaxFields  = 14;

	readonly Conversation _conv;
	readonly List<Packet> _packets;
	readonly string       _leftEndpoint;
	readonly string       _rightEndpoint;
	readonly float        _spacing;

	Pose _controlPose = new Pose(-0.55f, -0.15f, -0.75f, Quat.LookDir(0.5f, 0, 1));
	Pose _inspectPose = new Pose( 0.75f, -0.05f, -0.80f, Quat.LookDir(-0.6f, 0, 1));

	int   _shown      = 1;     // how many packets are revealed so far
	float _revealTime = 0;     // when the newest packet was revealed
	int   _selected   = -1;    // index into _packets
	int   _layerIndex = 0;

	readonly Mesh     _sphere = Mesh.GenerateSphere(0.12f);
	readonly Material _nodeMat = Material.Default;

	public PacketScene(Conversation conv)
	{
		_conv    = conv;
		_packets = conv.Packets;

		// The endpoint that sent the first packet goes on the left (usually the client).
		var first = _packets[0];
		_leftEndpoint  = Endpoint(first.Source, first.SourcePort);
		_rightEndpoint = Endpoint(first.Destination, first.DestinationPort);
		_spacing = Math.Min(MaxSpacing, 0.8f / Math.Max(1, _packets.Count));
		_revealTime = Time.Totalf;
	}

	public void Step()
	{
		DrawEndpoints();
		DrawPackets();
		ControlWindow();
		InspectorWindow();
	}

	// ---- 3D scene -------------------------------------------------------

	void DrawEndpoints()
	{
		float bottom = Top - _packets.Count * _spacing - 0.05f;
		DrawEndpoint(-HalfWidth, _leftEndpoint,  bottom);
		DrawEndpoint( HalfWidth, _rightEndpoint, bottom);
	}

	void DrawEndpoint(float x, string label, float bottom)
	{
		Vec3 top = new Vec3(x, Top + 0.1f, -1.2f);
		_sphere.Draw(_nodeMat, Matrix.T(top), new Color(0.3f, 0.6f, 1f));
		Lines.Add(top, new Vec3(x, bottom, -1.2f), new Color32(120, 140, 170, 255), 0.004f);
		Text.Add(label, Matrix.TR(top + new Vec3(0, 0.12f, 0), Quat.LookDir(0, 0, 1)));
	}

	Vec3 SideX(string endpoint, float y) =>
		new Vec3(endpoint == _leftEndpoint ? -HalfWidth : HalfWidth, y, -1.2f);

	void DrawPackets()
	{
		for (int i = 0; i < _shown && i < _packets.Count; i++)
		{
			var p    = _packets[i];
			float y  = Top - i * _spacing;
			Vec3 from = SideX(Endpoint(p.Source, p.SourcePort), y);
			Vec3 to   = SideX(Endpoint(p.Destination, p.DestinationPort), y);
			Vec3 mid  = (from + to) * 0.5f;

			Color color = PacketColor(p);
			bool selected = i == _selected;
			Lines.Add(from, to, ToColor32(color), selected ? 0.008f : 0.004f);

			// Number label beside the sending endpoint.
			Vec3 labelPos = from + new Vec3(from.x < 0 ? -0.08f : 0.08f, 0, 0);
			Text.Add($"#{p.Number}", Matrix.TRS(labelPos, Quat.LookDir(0, 0, 1), Vec3.One * 0.6f));

			// Grabbable marker in the middle of the arrow.
			Vec3 size = Vec3.One * (selected ? 0.05f : 0.035f);
			Mesh.Cube.Draw(Material.Default, Matrix.TS(mid, size), selected ? Color.White : color);

			BtnState state = UI.VolumeAt($"packet{i}", new Bounds(mid, Vec3.One * 0.06f), UIConfirm.Pinch, out _, out _);
			if ((state & BtnState.JustActive) != 0)
			{
				_selected   = i;
				_layerIndex = Math.Min(_layerIndex, p.Layers.Count - 1);
			}

			// Animate the newest packet travelling from sender to receiver.
			if (i == _shown - 1)
			{
				float t = Math.Min(1f, (Time.Totalf - _revealTime) / TravelTime);
				Mesh.Sphere.Draw(Material.Default, Matrix.TS(Vec3.Lerp(from, to, t), Vec3.One * 0.03f), Color.White);
			}
		}
	}

	// ---- UI windows -----------------------------------------------------

	void ControlWindow()
	{
		ControllerRays.BeginWindow("Conversation", ref _controlPose, new Vec2(30, 0) * U.cm, UIWin.Normal);
		UI.Label($"{_conv.Key}   {_leftEndpoint}  <->  {_rightEndpoint}");
		UI.Label($"Showing {Math.Min(_shown, _packets.Count)} of {_packets.Count} packets");
		UI.HSeparator();

		if (PointerUI.Button("Next") && _shown < _packets.Count)
		{
			_shown++;
			_revealTime = Time.Totalf;
			_selected   = _shown - 1;
		}
		UI.SameLine();
		if (PointerUI.Button("Back") && _shown > 1)
		{
			_shown--;
			_selected = Math.Min(_selected, _shown - 1);
		}
		UI.SameLine();
		if (PointerUI.Button("Show all")) { _shown = _packets.Count; }
		UI.SameLine();
		if (PointerUI.Button("Restart")) { _shown = 1; _selected = -1; _revealTime = Time.Totalf; }

		UI.HSeparator();
		UI.Label("Pinch a packet box in the diagram,\nor press Next to walk through it.");
		ControllerRays.EndWindow();
	}

	void InspectorWindow()
	{
		ControllerRays.BeginWindow("Packet inspector", ref _inspectPose, new Vec2(40, 0) * U.cm, UIWin.Normal);
		if (_selected < 0 || _selected >= _packets.Count)
		{
			UI.Label("No packet selected yet.");
			ControllerRays.EndWindow();
			return;
		}

		var p = _packets[_selected];
		UI.Label($"Packet #{p.Number}   {p.Length} bytes   {Pretty(p.Info)}");
		UI.Label(Lesson.Explain(p));
		UI.HSeparator();

		// One button per protocol layer, outermost first.
		UI.Label("Layers (outer to inner):");
		for (int i = 0; i < p.Layers.Count; i++)
		{
			if (i > 0) UI.SameLine();
			bool on = i == _layerIndex;
			UI.PushTint(on ? new Color(0.5f, 0.9f, 0.5f) : Color.White);
			if (PointerUI.Button(p.Layers[i].Name)) _layerIndex = i;
			UI.PopTint();
		}
		UI.HSeparator();

		var layer = p.Layers[Math.Min(_layerIndex, p.Layers.Count - 1)];
		int count = 0;
		foreach (var f in layer.Fields)
		{
			if (count++ >= MaxFields) break;
			UI.Label($"{new string(' ', f.Depth * 2)}{Trim(f.Name, 28)}: {Trim(f.Value, 40)}");
		}
		if (layer.Fields.Count > MaxFields)
			UI.Label($"... and {layer.Fields.Count - MaxFields} more fields");
		ControllerRays.EndWindow();
	}

	// ---- helpers --------------------------------------------------------

	static string Endpoint(string? host, string? port) =>
		port != null ? $"{host}:{port}" : host ?? "?";

	static string Pretty(string s) => s.Replace("→", "->");

	static string Trim(string s, int max) =>
		s.Length <= max ? s : s.Substring(0, max - 1) + "...";

	static Color32 ToColor32(Color c) =>
		new Color32((byte)(c.r * 255), (byte)(c.g * 255), (byte)(c.b * 255), 255);

	static Color PacketColor(Packet p)
	{
		var tcp = p.GetLayer("tcp");
		if (tcp?.Get("tcp.flags.reset") == "1") return new Color(1f, 0.35f, 0.3f);
		if (tcp?.Get("tcp.flags.syn") == "1")   return new Color(0.4f, 0.9f, 0.4f);
		if (tcp?.Get("tcp.flags.fin") == "1")   return new Color(1f, 0.7f, 0.3f);
		if (p.Protocol == "http")               return new Color(0.4f, 0.7f, 1f);
		return new Color(0.7f, 0.7f, 0.75f);
	}
}
