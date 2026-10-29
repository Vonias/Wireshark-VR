using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using StereoKit;
using WiresharkVR.Core;

namespace WiresharkVR.App;

/// <summary>
/// Wireshark's main window recreated in VR: each pane is its own movable window, so the user can
/// arrange them around themselves. Dissection is done by tshark; this class is only the interface.
/// </summary>
class WiresharkApp
{
	const int PageRows   = 14;
	const int DetailRows = 14;

	static readonly string[] FilterShortcuts =
		{ "tcp", "udp", "http", "dns", "icmp", "arp", "tcp.flags.syn == 1", "!(arp)" };

	readonly TsharkRunner _tshark;

	// ---- capture state ----
	string?          _path;
	int              _totalPackets;
	List<PacketRow>  _rows = new();
	string           _filterText = "";
	string           _appliedFilter = "";
	string           _message = "";
	bool             _messageIsError;

	// ---- selection ----
	int              _selectedIndex = -1;
	int              _listTop;
	PacketDetail?    _detail;
	int              _detailForNumber = -1;
	DetailNode?      _selectedNode;
	int              _detailTop;
	string           _hexText = "";
	Vec2             _hexScroll;

	// ---- background work (tshark runs off the render thread) ----
	Task<List<PacketRow>>? _listTask;
	string                 _listTaskFilter = "";
	Task<PacketDetail>?    _detailTask;
	int                    _detailTaskNumber;
	Task<string>?          _outputTask;
	string                 _outputTaskTitle = "";
	volatile string?       _pendingOpen;

	// ---- output window (statistics, follow stream, help) ----
	bool   _outputOpen;
	string _outputTitle = "";
	string _outputText = "";
	Vec2   _outputScroll;

	// ---- UI state ----
	string _menu = "";
	bool   _guide = true;
	bool   _showList = true, _showDetails = true, _showBytes = true;
	bool   _showFlow;
	TextStyle? _mono;

	// ---- window poses: main on top, list in the middle, details and bytes below ----
	// A window's pose is its top edge. Details and bytes sit beside the list, angled in toward the user.
	Pose _mainPose    = new Pose( 0.00f,  0.38f, -0.95f, Quat.LookDir(0, 0, 1));
	Pose _listPose    = new Pose( 0.00f, -0.10f, -0.95f, Quat.LookDir(0, 0, 1));
	Pose _detailPose  = new Pose(-0.83f,  0.15f, -0.90f, Quat.LookDir(0.35f, 0, 1));
	Pose _bytesPose   = new Pose( 0.88f,  0.15f, -0.90f, Quat.LookDir(-0.35f, 0, 1));
	Pose _outputPose  = new Pose( 0.00f,  0.15f, -0.70f, Quat.LookDir(0, 0, 1));

	// ---- 3D flow graph ----
	Task<List<Conversation>>? _flowTask;
	List<Conversation>?       _flowConversations;
	PacketScene?              _flowScene;
	string?                   _flowSceneKey;

	public WiresharkApp(string? initialPath, string? startupError)
	{
		_tshark = new TsharkRunner();
		if (startupError != null) SetMessage(startupError, true);
		else if (initialPath != null) LoadFile(initialPath);

		// Hex needs a fixed-width font to line up. Fall back to the default font where none is available.
		string consolas = @"C:\Windows\Fonts\consola.ttf";
		if (File.Exists(consolas))
			_mono = Text.MakeStyle(Font.FromFile(consolas), 0.012f, Color.White);
	}

	// =====================================================================
	// Frame loop
	// =====================================================================

	public void Step()
	{
		PollWork();
		HandleKeys();

		MainWindow();
		if (_showList)    ListWindow();
		if (_showDetails) DetailWindow();
		if (_showBytes)   BytesWindow();
		if (_outputOpen)  OutputWindow();
		if (_showFlow)    FlowStep();
	}

	void HandleKeys()
	{
		if (_rows.Count == 0) return;
		if (Pressed(Key.Down))     SelectRow(_selectedIndex + 1);
		if (Pressed(Key.Up))       SelectRow(_selectedIndex - 1);
		if (Pressed(Key.PageDown)) SelectRow(_selectedIndex + PageRows);
		if (Pressed(Key.PageUp))   SelectRow(_selectedIndex - PageRows);
	}

	static bool Pressed(Key k) => (Input.Key(k) & BtnState.JustActive) != 0;

	// =====================================================================
	// Loading and background work
	// =====================================================================

	void LoadFile(string path)
	{
		_path = path;
		_filterText = _appliedFilter = "";
		_selectedIndex = -1;
		_listTop = 0;
		_detail = null;
		_detailForNumber = -1;
		_selectedNode = null;
		_flowConversations = null; _flowTask = null; _flowScene = null; _flowSceneKey = null;
		SetMessage("Loading " + Path.GetFileName(path) + "...", false);
		StartList("");
	}

	void StartList(string filter)
	{
		if (_path == null) return;
		string path = _path;
		_listTaskFilter = filter;
		_listTask = Task.Run(() => _tshark.ListPacketsAsync(path, filter));
	}

	void PollWork()
	{
		if (_pendingOpen is string open) { _pendingOpen = null; LoadFile(open); }

		if (_listTask is { IsCompleted: true } list)
		{
			_listTask = null;
			if (list.IsFaulted)
			{
				SetMessage(list.Exception!.GetBaseException().Message, true);
			}
			else
			{
				int keep = _selectedIndex >= 0 && _selectedIndex < _rows.Count ? _rows[_selectedIndex].Number : -1;
				_rows = list.Result;
				_appliedFilter = _listTaskFilter;
				if (_appliedFilter.Length == 0) _totalPackets = _rows.Count;
				SetMessage(_appliedFilter.Length == 0
					? $"Loaded {_rows.Count} packets."
					: $"Filter '{_appliedFilter}' matches {_rows.Count} of {_totalPackets} packets.", false);

				int idx = keep >= 0 ? _rows.FindIndex(r => r.Number == keep) : -1;
				_listTop = 0;
				if (_rows.Count > 0) SelectRow(idx >= 0 ? idx : 0); else _selectedIndex = -1;
			}
		}

		if (_detailTask is { IsCompleted: true } det)
		{
			_detailTask = null;
			if (det.IsFaulted) SetMessage(det.Exception!.GetBaseException().Message, true);
			else if (_detailTaskNumber == CurrentNumber)
			{
				_detail = det.Result;
				_detailForNumber = _detailTaskNumber;
				_selectedNode = null;
				_detailTop = 0;
				if (_detail.Tree.Count > 0) _detail.Tree[^1].Expanded = true; // open the innermost protocol
				RebuildHex();
			}
		}

		if (_outputTask is { IsCompleted: true } outp)
		{
			_outputTask = null;
			_outputTitle = _outputTaskTitle;
			_outputText = outp.IsFaulted ? "Error: " + outp.Exception!.GetBaseException().Message : outp.Result.Trim();
			_outputScroll = Vec2.Zero;
			_outputOpen = true;
		}
	}

	int CurrentNumber => _selectedIndex >= 0 && _selectedIndex < _rows.Count ? _rows[_selectedIndex].Number : -1;

	void SelectRow(int index)
	{
		if (_rows.Count == 0) return;
		_selectedIndex = Math.Clamp(index, 0, _rows.Count - 1);
		if (_selectedIndex < _listTop) _listTop = _selectedIndex;
		if (_selectedIndex >= _listTop + PageRows) _listTop = _selectedIndex - PageRows + 1;

		int number = _rows[_selectedIndex].Number;
		if (number != _detailForNumber && _path != null)
		{
			string path = _path;
			_detailTaskNumber = number;
			_detailTask = Task.Run(() => _tshark.GetDetailAsync(path, number));
		}
	}

	void ApplyFilter(string filter)
	{
		_filterText = filter.Trim();
		SetMessage("Applying filter...", false);
		StartList(_filterText);
	}

	void RunOutput(string title, Func<string, Task<string>> job)
	{
		if (_path == null) { SetMessage("Open a capture file first.", true); return; }
		string path = _path;
		_outputTaskTitle = title;
		_outputTask = Task.Run(() => job(path));
		SetMessage("Working on " + title + "...", false);
	}

	void SetMessage(string text, bool error) { _message = text; _messageIsError = error; }

	// =====================================================================
	// Main window: menu bar, toolbar, filter bar, status bar
	// =====================================================================

	void MainWindow()
	{
		UI.WindowBegin("Wireshark VR", ref _mainPose, new Vec2(85, 0) * U.cm, UIWin.Normal);

		// Menu bar
		foreach (var m in new[] { "File", "Capture", "Analyze", "Statistics", "View", "Help" })
		{
			if (UI.Button(m)) _menu = _menu == m ? "" : m;
			UI.SameLine();
		}
		UI.Label(_menu.Length == 0 ? "" : "<- " + _menu);
		MenuItems();
		UI.HSeparator();

		// Toolbar
		if (UI.Button("First")) SelectRow(0);
		UI.SameLine();
		if (UI.Button("Prev"))  SelectRow(_selectedIndex - 1);
		UI.SameLine();
		if (UI.Button("Next"))  SelectRow(_selectedIndex + 1);
		UI.SameLine();
		if (UI.Button("Last"))  SelectRow(_rows.Count - 1);
		UI.SameLine();
		if (UI.Button("Reload") && _path != null) { string p = _path; LoadFile(p); }
		UI.SameLine();
		UI.Toggle("Guide mode", ref _guide);
		if (_guide) UI.Label(Guide.Main);
		UI.HSeparator();

		// Display filter bar
		UI.Label("Filter:");
		UI.SameLine();
		UI.Input("filterbox", ref _filterText, new Vec2(40, 0) * U.cm, TextContext.Text);
		UI.SameLine();
		if (UI.Button("Apply") || Pressed(Key.Return)) ApplyFilter(_filterText);
		UI.SameLine();
		if (UI.Button("Clear")) { _filterText = ""; ApplyFilter(""); }
		if (_guide) UI.Label(Guide.Filter);
		foreach (var s in FilterShortcuts)
		{
			if (UI.Button(s)) { _filterText = s; ApplyFilter(s); }
			UI.SameLine();
		}
		UI.Label("");
		UI.HSeparator();

		// Status bar
		UI.PushTint(_messageIsError ? new Color(1f, 0.5f, 0.5f) : new Color(0.7f, 1f, 0.7f));
		UI.Label(_message.Length == 0 ? "Ready" : _message);
		UI.PopTint();
		string file = _path == null ? "no file" : Path.GetFileName(_path);
		UI.Label($"File: {file}    Packets: {_totalPackets}    Displayed: {_rows.Count}    Selected: " +
		         (CurrentNumber > 0 ? "#" + CurrentNumber : "none"));
		UI.WindowEnd();
	}

	void MenuItems()
	{
		switch (_menu)
		{
			case "File":
				if (UI.Button("Open sample")) { var s = FindSample(); if (s != null) LoadFile(s); }
				UI.SameLine();
				if (UI.Button("Open file...")) Platform.FilePicker(PickerMode.Open, f => _pendingOpen = f, () => { }, ".pcap", ".pcapng", ".cap");
				UI.SameLine();
				if (UI.Button("Quit")) SK.Quit();
				break;

			case "Capture":
				UI.Label("Live capture is the next feature. For now, open a saved capture from File.");
				break;

			case "Analyze":
				if (UI.Button("Filter on selected field")) FilterOnSelectedField();
				UI.SameLine();
				if (UI.Button("Filter on this stream")) FilterOnStream();
				UI.SameLine();
				if (UI.Button("Follow stream")) FollowStream();
				break;

			case "Statistics":
				if (UI.Button("Protocol hierarchy")) RunOutput("Protocol Hierarchy", p => _tshark.StatisticAsync(p, "io,phs", _appliedFilter));
				UI.SameLine();
				if (UI.Button("TCP conversations")) RunOutput("TCP Conversations", p => _tshark.StatisticAsync(p, "conv,tcp", _appliedFilter));
				UI.SameLine();
				if (UI.Button("UDP conversations")) RunOutput("UDP Conversations", p => _tshark.StatisticAsync(p, "conv,udp", _appliedFilter));
				if (UI.Button("IP conversations")) RunOutput("IP Conversations", p => _tshark.StatisticAsync(p, "conv,ip", _appliedFilter));
				UI.SameLine();
				if (UI.Button("IP endpoints")) RunOutput("IP Endpoints", p => _tshark.StatisticAsync(p, "endpoints,ip", _appliedFilter));
				break;

			case "View":
				UI.Toggle("Packet list", ref _showList);
				UI.SameLine();
				UI.Toggle("Packet details", ref _showDetails);
				UI.SameLine();
				UI.Toggle("Packet bytes", ref _showBytes);
				UI.SameLine();
				UI.Toggle("3D flow graph", ref _showFlow);
				break;

			case "Help":
				if (UI.Button("Wireshark in 60 seconds")) { _outputTitle = "Wireshark in 60 seconds"; _outputText = Guide.CheatSheet; _outputScroll = Vec2.Zero; _outputOpen = true; }
				break;
		}
	}

	// =====================================================================
	// Analyze menu helpers
	// =====================================================================

	void FilterOnSelectedField()
	{
		if (_selectedNode == null || _selectedNode.Name.Length == 0)
		{
			SetMessage("Tap a field in the Packet Details pane first.", true);
			return;
		}
		string v = _selectedNode.Show;
		bool plain = Regex.IsMatch(v, @"^[0-9a-fA-F.:x]+$");
		ApplyFilter($"{_selectedNode.Name} == " + (plain ? v : "\"" + v.Replace("\"", "\\\"") + "\""));
	}

	/// <summary>Returns the stream protocol ("tcp" or "udp") and index of the selected packet, if it has one.</summary>
	(string proto, int index)? SelectedStream()
	{
		foreach (var proto in new[] { "tcp", "udp" })
		{
			var node = _detail?.Find(proto + ".stream");
			if (node != null && int.TryParse(node.Show, out var idx)) return (proto, idx);
		}
		return null;
	}

	void FilterOnStream()
	{
		var s = SelectedStream();
		if (s == null) { SetMessage("The selected packet is not part of a TCP/UDP stream.", true); return; }
		ApplyFilter($"{s.Value.proto}.stream eq {s.Value.index}");
	}

	void FollowStream()
	{
		var s = SelectedStream();
		if (s == null) { SetMessage("Select a TCP/UDP packet first.", true); return; }
		var (proto, index) = s.Value;
		RunOutput($"Follow {proto.ToUpper()} Stream {index}", p => _tshark.FollowStreamAsync(p, proto, index));
	}

	// =====================================================================
	// Packet List pane
	// =====================================================================

	static readonly (string name, float cm)[] Columns =
		{ ("No.", 3.5f), ("Time", 6), ("Source", 11), ("Destination", 11), ("Protocol", 6), ("Len", 4), ("Info", 33) };

	void ListWindow()
	{
		UI.WindowBegin("Packet List", ref _listPose, new Vec2(95, 0) * U.cm, UIWin.Normal);
		if (_guide) UI.Label(Guide.PacketList);

		foreach (var (name, cm) in Columns)
		{
			UI.Label(name, new Vec2(cm, 0) * U.cm);
			UI.SameLine();
		}
		UI.Label("");

		int end = Math.Min(_rows.Count, _listTop + PageRows);
		for (int i = _listTop; i < end; i++)
		{
			var r = _rows[i];
			var cells = new[]
			{
				r.Number.ToString(), r.RelativeTime.ToString("0.000000"), Clip(r.Source, 18), Clip(r.Destination, 18),
				r.Protocol, r.Length.ToString(), Clip(r.Info, 52),
			};

			UI.PushId(i);
			UI.PushTint(i == _selectedIndex ? new Color(1f, 1f, 0.45f) : RowColor(r));
			for (int c = 0; c < cells.Length; c++)
			{
				UI.PushId(c);
				if (UI.Button(cells[c].Length == 0 ? " " : cells[c], new Vec2(Columns[c].cm, 0) * U.cm)) SelectRow(i);
				UI.PopId();
				if (c < cells.Length - 1) UI.SameLine();
			}
			UI.PopTint();
			UI.PopId();
		}

		UI.HSeparator();
		if (UI.Button("Page up"))   SelectRow(_selectedIndex - PageRows);
		UI.SameLine();
		if (UI.Button("Page down")) SelectRow(_selectedIndex + PageRows);
		UI.SameLine();
		UI.Label(_rows.Count == 0 ? "No packets" : $"Rows {_listTop + 1}-{end} of {_rows.Count}    (arrow keys also work)");
		UI.WindowEnd();
	}

	/// <summary>Approximates Wireshark's default colouring rules.</summary>
	static Color RowColor(PacketRow r)
	{
		if (r.Info.Contains("[RST") || r.Info.Contains("Malformed") || r.Info.Contains("Retransmission")) return new Color(1f, 0.45f, 0.45f);
		if (r.Info.Contains("[SYN") || r.Info.Contains("[FIN"))                                         return new Color(0.7f, 0.7f, 0.7f);
		return r.Protocol.ToUpperInvariant() switch
		{
			"HTTP" or "HTTP2" or "TLSV1.3" or "TLSV1.2" => new Color(0.75f, 1f, 0.6f),
			"TCP"                                      => new Color(0.82f, 0.78f, 1f),
			"UDP" or "DNS" or "QUIC"                   => new Color(0.7f, 0.85f, 1f),
			"ICMP" or "ICMPV6"                         => new Color(1f, 0.85f, 1f),
			"ARP"                                      => new Color(1f, 0.95f, 0.75f),
			_                                          => Color.White,
		};
	}

	// =====================================================================
	// Packet Details pane
	// =====================================================================

	void DetailWindow()
	{
		UI.WindowBegin("Packet Details", ref _detailPose, new Vec2(55, 0) * U.cm, UIWin.Normal);
		if (_guide) UI.Label(Guide.Details);

		if (_detail == null)
		{
			UI.Label(CurrentNumber > 0 ? "Loading packet..." : "Select a packet in the list.");
			UI.WindowEnd();
			return;
		}

		var lines = new List<(DetailNode node, int depth)>();
		void Walk(IEnumerable<DetailNode> nodes, int depth)
		{
			foreach (var n in nodes)
			{
				lines.Add((n, depth));
				if (n.Expanded) Walk(n.Children, depth + 1);
			}
		}
		Walk(_detail.Tree, 0);

		_detailTop = Math.Clamp(_detailTop, 0, Math.Max(0, lines.Count - DetailRows));
		int end = Math.Min(lines.Count, _detailTop + DetailRows);
		for (int i = _detailTop; i < end; i++)
		{
			var (node, depth) = lines[i];
			string marker = node.Children.Count == 0 ? "   " : node.Expanded ? "v  " : ">  ";
			UI.PushId(i);
			UI.PushTint(node == _selectedNode ? new Color(1f, 1f, 0.45f) : depth == 0 ? new Color(0.85f, 0.9f, 1f) : Color.White);
			if (UI.Button(new string(' ', depth * 3) + marker + Clip(node.Label, 66), new Vec2(52, 0) * U.cm))
			{
				if (node.Children.Count > 0) node.Expanded = !node.Expanded;
				_selectedNode = node;
				RebuildHex();
			}
			UI.PopTint();
			UI.PopId();
		}

		UI.HSeparator();
		if (UI.Button("Scroll up"))   _detailTop = Math.Max(0, _detailTop - DetailRows / 2);
		UI.SameLine();
		if (UI.Button("Scroll down")) _detailTop += DetailRows / 2;
		UI.SameLine();
		if (UI.Button("Expand all"))  SetAll(_detail.Tree, true);
		UI.SameLine();
		if (UI.Button("Collapse all")) SetAll(_detail.Tree, false);
		UI.WindowEnd();
	}

	static void SetAll(IEnumerable<DetailNode> nodes, bool expanded)
	{
		foreach (var n in nodes) { n.Expanded = expanded; SetAll(n.Children, expanded); }
	}

	// =====================================================================
	// Packet Bytes pane
	// =====================================================================

	void BytesWindow()
	{
		UI.WindowBegin("Packet Bytes", ref _bytesPose, new Vec2(58, 0) * U.cm, UIWin.Normal);
		if (_guide) UI.Label(Guide.Bytes);

		if (_selectedNode != null && _selectedNode.Size > 0)
			UI.Label($"Selected: {Clip(_selectedNode.Label, 50)}   ({_selectedNode.Size} bytes at offset {_selectedNode.Pos})");

		if (_mono is TextStyle mono) UI.PushTextStyle(mono);
		UI.Text(_hexText.Length == 0 ? "(no packet)" : _hexText, ref _hexScroll, UIScroll.Vertical,
			new Vec2(56, 17) * U.cm, TextAlign.TopLeft, TextFit.Clip);
		if (_mono != null) UI.PopTextStyle();
		UI.WindowEnd();
	}

	/// <summary>Builds the classic hex dump. Bytes belonging to the selected field are printed in capitals.</summary>
	void RebuildHex()
	{
		if (_detail == null) { _hexText = ""; return; }
		var data = _detail.Bytes;
		int selStart = _selectedNode != null && _selectedNode.Size > 0 ? _selectedNode.Pos : -1;
		int selEnd   = selStart >= 0 ? selStart + _selectedNode!.Size : -1;

		var sb = new StringBuilder();
		for (int off = 0; off < data.Length; off += 16)
		{
			sb.Append(off.ToString("x4")).Append("  ");
			for (int i = 0; i < 16; i++)
			{
				if (off + i < data.Length)
				{
					bool sel = off + i >= selStart && off + i < selEnd;
					string h = data[off + i].ToString(sel ? "X2" : "x2");
					sb.Append(sel ? "[" : " ").Append(h).Append(sel ? "]" : " ");
				}
				else sb.Append("    ");
				if (i == 7) sb.Append(' ');
			}
			sb.Append("  ");
			for (int i = 0; i < 16 && off + i < data.Length; i++)
			{
				byte b = data[off + i];
				sb.Append(b >= 32 && b < 127 ? (char)b : '.');
			}
			sb.Append('\n');
		}
		_hexText = sb.ToString();
	}

	// =====================================================================
	// Output window (statistics, follow stream, help)
	// =====================================================================

	void OutputWindow()
	{
		UI.WindowBegin(_outputTitle, ref _outputPose, new Vec2(70, 0) * U.cm, UIWin.Normal);
		if (_mono is TextStyle mono) UI.PushTextStyle(mono);
		UI.Text(_outputText, ref _outputScroll, UIScroll.Vertical, new Vec2(68, 28) * U.cm, TextAlign.TopLeft, TextFit.Clip);
		if (_mono != null) UI.PopTextStyle();
		if (UI.Button("Close")) _outputOpen = false;
		UI.WindowEnd();
	}

	// =====================================================================
	// 3D flow graph (the ladder diagram), driven by the selected packet
	// =====================================================================

	void FlowStep()
	{
		if (_path == null) return;
		if (_flowConversations == null && _flowTask == null)
		{
			string path = _path;
			_flowTask = Task.Run(async () => ConversationBuilder.Build(await _tshark.ReadFileAsync(path, 5000)));
		}
		if (_flowTask is { IsCompleted: true } t)
		{
			_flowConversations = t.IsFaulted ? new List<Conversation>() : t.Result;
			_flowTask = null;
		}
		if (_flowConversations == null) return;

		var conv = _flowConversations.FirstOrDefault(c => c.Packets.Any(p => p.Number == CurrentNumber))
		           ?? _flowConversations.FirstOrDefault();
		if (conv == null) return;
		if (_flowSceneKey != conv.Key)
		{
			_flowScene = new PacketScene(conv);
			_flowSceneKey = conv.Key;
		}
		_flowScene?.Step();
	}

	// =====================================================================
	// helpers
	// =====================================================================

	static string Clip(string s, int max) => s.Length <= max ? s : s.Substring(0, max - 3) + "...";

	public static string? FindSample()
	{
		var dir = new DirectoryInfo(AppContext.BaseDirectory);
		while (dir != null)
		{
			string candidate = Path.Combine(dir.FullName, "samples", "loopback-http.pcapng");
			if (File.Exists(candidate)) return candidate;
			dir = dir.Parent;
		}
		return null;
	}
}
