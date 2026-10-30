using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using StereoKit;
using WiresharkVR.Core;
using WiresharkVR.Core.Vpn;

namespace WiresharkVR.App;

/// <summary>
/// Wireshark's main window recreated in VR: each pane is its own movable window, so the user can
/// arrange them around themselves. Dissection is done by tshark; this class is only the interface.
/// </summary>
class WiresharkApp
{
	const int   PageRows   = 16;
	const int   DetailRows = 14;
	const float RowHeight  = 2.1f * U.cm;
	const float SurfaceZ   = -0.1f * U.cm;
	const float TextZ      = -0.25f * U.cm;

	static readonly string[] FilterShortcuts =
		{ "tcp", "udp", "http", "dns", "icmp", "arp", "tcp.flags.syn == 1", "!(arp)" };

	readonly ICaptureEngine _engine;

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
	TextStyle  _cellStyle;
	readonly StressBall _ball = new StressBall();
	readonly VrKeyboard _keyboard = new VrKeyboard();
	readonly List<string> _recentFilters = new();
	bool   _showOverview = true, _showExpert;
	readonly HashSet<int> _marked = new();
	string? _filterChecked;
	bool    _filterBad;
	CaptureOverview? _overview;
	List<PacketRow>? _overviewRows;
	int              _overviewCount = -1;

	// ---- window poses: main on top, list in the middle, details and bytes below ----
	// A window's pose is its top edge. Details and bytes sit beside the list, angled in toward the user.
	Pose _mainPose    = new Pose( 0.00f,  0.38f, -0.95f, Quat.LookDir(0, 0, 1));
	Pose _listPose    = new Pose( 0.00f, -0.20f, -0.95f, Quat.LookDir(0, 0, 1));
	Pose _detailPose  = new Pose(-0.83f,  0.15f, -0.90f, Quat.LookDir(0.35f, 0, 1));
	Pose _bytesPose   = new Pose( 0.88f,  0.15f, -0.90f, Quat.LookDir(-0.35f, 0, 1));
	Pose _outputPose  = new Pose( 0.00f,  0.15f, -0.70f, Quat.LookDir(0, 0, 1));
	Pose _overviewPose = new Pose(-1.38f,  0.15f, -0.62f, Quat.LookDir(0.8f, 0, 0.6f));
	Pose _expertPose   = new Pose( 1.42f,  0.15f, -0.62f, Quat.LookDir(-0.8f, 0, 0.6f));

	// ---- 3D flow graph ----
	Task<List<Conversation>>? _flowTask;
	List<Conversation>?       _flowConversations;
	PacketScene?              _flowScene;
	string?                   _flowSceneKey;

	// ---- live capture ----
	bool                         _capturing;
	CancellationTokenSource?     _captureCancel;
	Task?                        _captureTask;
	ConcurrentQueue<PacketRow>   _captureQueue = new();
	string                       _captureIface = "";
	bool                         _paused;
	float                        _releaseBudget;
	float                        _stickTravel;
	List<PacketRow>?             _replaySource;
	LiveCapture?                 _vpn;
	float                        _overviewNextAt;
	string?                      _captureTempFile;
	bool                         _liveAutoScroll = true;
	List<string>                 _captureIfaces = new();
	Task<List<string>>?          _ifaceTask;

	/// <param name="forceNative">Use the built-in dissector even when tshark is installed.</param>
	public WiresharkApp(string? initialPath, string? startupError, bool forceNative = false)
	{
		Theme.Apply();
		_cellStyle = Text.MakeStyle(Font.Default, 0.0125f, Color.White);
		_engine = CaptureEngine.Create(forceNative);
		if (startupError != null) SetMessage(startupError, true);
		else if (initialPath != null) LoadFile(initialPath);

		_ifaceTask = Task.Run(() => _engine.ListInterfacesAsync());

		// Hex needs a fixed-width font to line up. Fall back to the default font where none is available.
		foreach (var fontPath in PlatformPaths.MonospaceFonts())
		{
			if (!File.Exists(fontPath)) continue;
			try { _mono = Text.MakeStyle(Font.FromFile(fontPath), 0.012f, Color.White); break; }
			catch (Exception) { /* keep the default font */ }
		}
	}

	// =====================================================================
	// Frame loop
	// =====================================================================

	public void Step()
	{
		PollWork();
		HandleKeys();
		ControllerRays.Step();

		MainWindow();
		if (_showList)    ListWindow();
		if (_showDetails) DetailWindow();
		if (_showBytes)   BytesWindow();
		if (_outputOpen)  OutputWindow();
		if (_showOverview) OverviewWindow();
		if (_showExpert)   ExpertWindow();
		if (_keyboard.IsOpen && _keyboard.Step(ref _filterText, _recentFilters)) ApplyFilter(_filterText);
		if (_showFlow)    FlowStep();
		_ball.Step();
	}

	void HandleKeys()
	{
		HandleControllers();
		if (_rows.Count == 0) return;
		if (Pressed(Key.Down))     { if (_capturing) _liveAutoScroll = false; SelectRow(_selectedIndex + 1); }
		if (Pressed(Key.Up))       { _liveAutoScroll = false; SelectRow(_selectedIndex - 1); }
		if (Pressed(Key.PageDown)) { if (_capturing) _liveAutoScroll = false; SelectRow(_selectedIndex + PageRows); }
		if (Pressed(Key.PageUp))   { _liveAutoScroll = false; SelectRow(_selectedIndex - PageRows); }
	}

	static bool Pressed(Key k) => (Input.Key(k) & BtnState.JustActive) != 0;

	/// <summary>Sticks act on the window last pointed at. A or X pauses a stream; B or Y shows the keyboard.</summary>
	void HandleControllers()
	{
		Vec2 stick = Vec2.Zero;
		foreach (Handed side in new[] { Handed.Left, Handed.Right })
		{
			Controller controller = Input.Controller(side);
			if (!controller.IsTracked) continue;
			if (controller.IsX1JustPressed && _capturing) TogglePause();
			if (controller.IsX2JustPressed) _keyboard.IsOpen = !_keyboard.IsOpen;
			if (controller.stick.Magnitude > stick.Magnitude) stick = controller.stick;
		}

		const float DeadZone = 0.35f, MaxRowsPerSecond = 16, ScrollMetersPerSecond = 0.3f;
		bool sideways = Math.Abs(stick.x) > Math.Abs(stick.y);
		float amount = sideways ? stick.x : stick.y;
		if (Math.Abs(amount) < DeadZone) { _stickTravel = 0; return; }

		string active = ControllerRays.ActiveWindow;
		if (active == "Packet Bytes" || (_outputOpen && active == _outputTitle))
		{
			if (sideways) return;
			float change = amount * ScrollMetersPerSecond * Time.Stepf;
			if (active == "Packet Bytes") _hexScroll.y -= change;
			else _outputScroll.y -= change;
			return;
		}

		bool list = active.StartsWith("Packet List");
		if (!list && active != "Packet Details") return;

		if (sideways)
		{
			// A deliberate flick: one page each time the stick leaves the centre.
			if (_stickTravel == 0)
			{
				if (list) SelectRow(_selectedIndex + Math.Sign(amount) * PageRows);
				else _detailTop += Math.Sign(amount) * DetailRows;
			}
			_stickTravel = 1;
			return;
		}

		_stickTravel += amount * MaxRowsPerSecond * Time.Stepf;
		int rows = (int)_stickTravel;
		if (rows == 0) return;
		_stickTravel -= rows;
		if (list) SelectRow(_selectedIndex - rows);
		else _detailTop = Math.Max(0, _detailTop - rows);
	}

	bool CanInspect => !_capturing || (_paused && (_replaySource != null || _vpn != null));

	void TogglePause()
	{
		_paused = !_paused;
		if (_paused) { if (_selectedIndex >= 0) SelectRow(_selectedIndex); }
		else _liveAutoScroll = true;
	}

	// =====================================================================
	// Loading and background work
	// =====================================================================

	void LoadFile(string path)
	{
		EndStream();
		_path = path;
		_filterText = _appliedFilter = "";
		_selectedIndex = -1;
		_listTop = 0;
		_detail = null;
		_detailForNumber = -1;
		_selectedNode = null;
		_marked.Clear();
		_flowConversations = null; _flowTask = null; _flowScene = null; _flowSceneKey = null;
		SetMessage("Loading " + Path.GetFileName(path) + "...", false);
		StartList("");
	}

	void StartList(string filter)
	{
		if (_path == null) return;
		string path = _path;
		_listTaskFilter = filter;
		_listTask = Task.Run(() => _engine.ListPacketsAsync(path, filter));
	}

	void PollWork()
	{
		if (_pendingOpen is string open) { _pendingOpen = null; if (!_capturing) LoadFile(open); }

		var activeVpn = PlatformPaths.ActiveVpnCapture();
		if (activeVpn != null && activeVpn != _vpn) AttachVpn(activeVpn);
		else if (activeVpn == null && _vpn != null) StopCapture(); // the OS or another VPN ended it
		if (PlatformPaths.TakeVpnDenied()) SetMessage("VPN permission was declined, so capture did not start.", true);

		// Resolve interface list on first poll.
		if (_ifaceTask is { IsCompleted: true } it)
		{
			_ifaceTask = null;
			if (!it.IsFaulted) _captureIfaces = it.Result;
		}

		// Release packets at a smooth rate. While paused they wait in the queue, so nothing is lost.
		if (_capturing && !_paused)
		{
			const float MinPerSecond = 20, CatchUpSpeed = 3;
			_releaseBudget = Math.Min(_releaseBudget + Time.Stepf * Math.Max(MinPerSecond, _captureQueue.Count * CatchUpSpeed), 200);
			int released = 0;
			while (_releaseBudget >= 1 && _captureQueue.TryDequeue(out var pkt))
			{
				_rows.Add(pkt);
				_releaseBudget--;
				released++;
			}
			if (released > 0)
			{
				TrimStream();
				_totalPackets = _rows.Count;
				if (_liveAutoScroll) SelectRow(_rows.Count - 1);
			}
		}

		// Detect capture task completion (stopped or error).
		if (_captureTask is { IsCompleted: true } capTask)
		{
			_captureTask = null;
			if (_capturing)
			{
				_capturing = false;
				_paused = false;
				// Drain any final packets that arrived before the task finished.
				while (_captureQueue.TryDequeue(out var pkt)) _rows.Add(pkt);
				_totalPackets = _rows.Count;
				// Point _path at the temp file so details and hex are browsable.
				if (_captureTempFile != null && File.Exists(_captureTempFile))
					_path = _captureTempFile;
				SetMessage(capTask.IsFaulted
					? "Capture error: " + capTask.Exception!.GetBaseException().Message
					: $"Stream stopped. {_totalPackets:N0} packets kept.",
					capTask.IsFaulted);
			}
		}


		if (_listTask is { IsCompleted: true } list)
		{
			_listTask = null;
			_filterChecked = _listTaskFilter;
			_filterBad = list.IsFaulted;
			if (list.IsFaulted)
			{
				SetMessage(list.Exception!.GetBaseException().Message, true);
			}
			else
			{
				int keep = _selectedIndex >= 0 && _selectedIndex < _rows.Count ? _rows[_selectedIndex].Number : -1;
				_rows = list.Result;
				_appliedFilter = _listTaskFilter;
				if (_appliedFilter.Length > 0)
				{
					_recentFilters.Remove(_appliedFilter);
					_recentFilters.Insert(0, _appliedFilter);
				}
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

		// Re-enable auto-scroll when the user navigates back to the newest packet.
		if (_capturing) _liveAutoScroll = _selectedIndex == _rows.Count - 1;

		int number = _rows[_selectedIndex].Number;
		// While streaming, skip detail fetch: it would chase every new packet.
		if (CanInspect && number != _detailForNumber && _vpn is { } live)
		{
			_detailTaskNumber = number;
			_detailTask = Task.Run(() => live.Detail(number) ?? throw new InvalidOperationException("That packet has left memory. Stop the capture to reopen it from the saved file."));
		}
		else if (CanInspect && number != _detailForNumber && _path != null)
		{
			string path = _path;
			int fileNumber = number;
			if (_replaySource is { Count: > 0 } source) fileNumber = source[(number - 1) % source.Count].Number;
			_detailTaskNumber = number;
			_detailTask = Task.Run(() => _engine.GetDetailAsync(path, fileNumber));
		}
	}

	void ApplyFilter(string filter)
	{
		if (_capturing) { SetMessage("Stop the stream to apply a filter.", true); return; }
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

	void StartCapture(string ifaceLabel)
	{
		EndStream();

		// Derive the interface id (the number before the dot, e.g. "1" from "1. Wi-Fi").
		int dot = ifaceLabel.IndexOf('.');
		string ifaceId = dot > 0 ? ifaceLabel[..dot].Trim() : ifaceLabel;

		_captureTempFile = Path.Combine(Path.GetTempPath(),
			$"wsvr_live_{DateTime.UtcNow:yyyyMMdd_HHmmss}.pcapng");

		_path = null;
		ResetForStream(ifaceLabel);
		var ct = _captureCancel!.Token;
		var tempFile = _captureTempFile;
		var iface = ifaceId;
		_captureTask = Task.Run(async () =>
		{
			await foreach (var row in _engine.CaptureAsync(iface, tempFile, ct))
				_captureQueue.Enqueue(row);
		});

		SetMessage($"Starting capture on {ifaceLabel}...", false);
	}

	void AttachVpn(LiveCapture live)
	{
		EndStream();
		_path = null;
		_vpn = live;
		_captureTempFile = live.FilePath;
		ResetForStream("VPN: this headset");
		var ct = _captureCancel!.Token;
		_captureTask = Task.Run(async () =>
		{
			await foreach (var row in live.RowsAsync(ct))
				_captureQueue.Enqueue(row);
		});
		SetMessage("Capturing this headset's traffic.", false);
	}

	void StartReplay()
	{
		if (_rows.Count == 0) { SetMessage("Open a capture with packets first.", true); return; }
		var source = _rows.ToList();
		EndStream();
		_replaySource = source;
		ResetForStream("REPLAY of " + Path.GetFileName(_path ?? "capture"));
		var ct = _captureCancel!.Token;
		_captureTask = Task.Run(async () =>
		{
			await foreach (var row in CaptureReplay.StreamAsync(source, ct))
				_captureQueue.Enqueue(row);
		});
		SetMessage("Replaying the capture as a stream.", false);
	}

	void ResetForStream(string label)
	{
		_rows = new List<PacketRow>();
		_totalPackets = 0;
		_selectedIndex = -1;
		_listTop = 0;
		_detail = null;
		_detailForNumber = -1;
		_selectedNode = null;
		_marked.Clear();
		_flowConversations = null; _flowTask = null; _flowScene = null; _flowSceneKey = null;
		_captureIface = label;
		_liveAutoScroll = true;
		_paused = false;
		_releaseBudget = 0;
		_capturing = true;
		_captureCancel = new CancellationTokenSource();
	}

	void StopCapture()
	{
		_captureCancel?.Cancel();
		_captureCancel = null;
		if (_vpn == null) return;
		_vpn = null;
		PlatformPaths.StopVpnCapture();
	}

	/// <summary>Abandons any running stream immediately, keeping none of its queued packets.</summary>
	void EndStream()
	{
		StopCapture();
		_captureQueue.Clear();
		_capturing = false;
		_paused = false;
		_replaySource = null;
		_captureTempFile = null;
	}

	/// <summary>Keeps an endless stream from using up the headset's memory: the oldest packets drop off.</summary>
	void TrimStream()
	{
		const int MaxRows = 50_000, TrimRows = 10_000;
		if (_rows.Count <= MaxRows) return;
		_rows.RemoveRange(0, TrimRows);
		_selectedIndex = Math.Max(-1, _selectedIndex - TrimRows);
		_listTop = Math.Max(0, _listTop - TrimRows);
	}

	// =====================================================================
	// Main window: menu bar, toolbar, filter bar, status bar
	// =====================================================================

	void MainWindow()
	{
		ControllerRays.BeginWindow("Wireshark VR", ref _mainPose, new Vec2(85, 0) * U.cm, UIWin.Normal);

		// Menu bar
		foreach (var m in new[] { "File", "Capture", "Analyze", "Statistics", "View", "Help" })
		{
			if (PointerUI.Button(m)) _menu = _menu == m ? "" : m;
			UI.SameLine();
		}
		UI.Label(_menu.Length == 0 ? "" : "<- " + _menu);
		MenuItems();
		UI.HSeparator();

		// Toolbar
		if (_capturing)
		{
			UI.PushTint(new Color(1f, 0.35f, 0.35f));
			if (PointerUI.Button("Stop")) StopCapture();
			UI.PopTint();
			UI.SameLine();
			if (PointerUI.Button(_paused ? "Resume" : "Pause")) TogglePause();
			UI.SameLine();
			if (PointerUI.Button("Newest")) { _liveAutoScroll = true; SelectRow(_rows.Count - 1); }
			UI.SameLine();
			UI.Label(_paused ? $"PAUSED   {_captureQueue.Count:N0} waiting" : _captureIface);
		}
		else
		{
			if (PointerUI.Button("First")) SelectRow(0);
			UI.SameLine();
			if (PointerUI.Button("Prev"))  SelectRow(_selectedIndex - 1);
			UI.SameLine();
			if (PointerUI.Button("Next"))  SelectRow(_selectedIndex + 1);
			UI.SameLine();
			if (PointerUI.Button("Last"))  SelectRow(_rows.Count - 1);
			UI.SameLine();
			if (PointerUI.Button("Reload") && _path != null) { string p = _path; LoadFile(p); }
			UI.SameLine();
			if (PointerUI.Button("Mark") && CurrentNumber > 0 && !_marked.Remove(CurrentNumber)) _marked.Add(CurrentNumber);
			UI.SameLine();
			if (PointerUI.Button("Next marked")) NextMarked();
		}
		UI.SameLine();
		PointerUI.Toggle("Guide mode", ref _guide);
		if (_guide) UI.Label(Guide.Main);
		UI.HSeparator();

		// Display filter bar
		UI.Label("Filter:");
		UI.SameLine();
		// Like Wireshark's filter bar: green once a filter is accepted, red if it is rejected.
		bool filterJudged = _filterText.Length > 0 && _filterChecked == _filterText;
		UI.PushTint(!filterJudged ? Color.White : _filterBad ? Theme.Bad : Theme.Good);
		UI.Input("filterbox", ref _filterText, new Vec2(40, 0) * U.cm, TextContext.Text);
		if (ControllerRays.Clicked()) _keyboard.IsOpen = true;
		UI.PopTint();
		UI.SameLine();
		if (PointerUI.Button("Apply") || Pressed(Key.Return)) ApplyFilter(_filterText);
		UI.SameLine();
		if (PointerUI.Button("Clear")) { _filterText = ""; ApplyFilter(""); }
		if (_guide) UI.Label(Guide.Filter);
		foreach (var s in FilterShortcuts)
		{
			if (PointerUI.Button(s)) { _filterText = s; ApplyFilter(s); }
			UI.SameLine();
		}
		UI.Label("");
		UI.HSeparator();

		// Status bar — orange during live capture, red on error, green otherwise.
		var statusTint = _capturing      ? new Color(1f, 0.65f, 0.2f) :
		                 _messageIsError ? new Color(1f, 0.5f,  0.5f) :
		                                   new Color(0.7f, 1f,  0.7f);
		UI.PushTint(statusTint);
		if (_capturing)
			UI.Label($"{(_paused ? "Paused" : "Streaming")}: {_captureIface}   {_rows.Count:N0} packets");
		else
			UI.Label(_message.Length == 0 ? "Ready" : _message);
		UI.PopTint();
		string file = _path == null ? (_capturing ? "(live capture)" : "no file") : Path.GetFileName(_path);
		if (_guide) UI.Label("Controllers: trigger presses what you point at. The stick scrolls the window you last pointed at.\nA or X pauses a stream. B or Y shows the keyboard. Grip moves a window.");
		UI.Label($"File: {file}    Packets: {_totalPackets}    Displayed: {_rows.Count}    Selected: " +
		         (CurrentNumber > 0 ? "#" + CurrentNumber : "none"));
		UI.Label($"Engine: {_engine.Name}");
		ControllerRays.EndWindow();
	}

	void MenuItems()
	{
		switch (_menu)
		{
			case "File":
				if (PointerUI.Button("Open sample")) { var s = PlatformPaths.SampleCapture(); if (s != null) LoadFile(s); }
				if (PlatformPaths.SupportsFilePicker())
				{
					UI.SameLine();
					if (PointerUI.Button("Browse...")) Platform.FilePicker(PickerMode.Open, f => _pendingOpen = f, () => { }, ".pcap", ".pcapng", ".cap");
				}
				UI.SameLine();
				if (PointerUI.Button("Quit")) SK.Quit();

				// Captures in the app's capture folder (on the headset, fill it with "adb push").
				string? dir = PlatformPaths.CaptureDirectory();
				var files = dir == null ? Array.Empty<string>() : CaptureFiles(dir);
				UI.Label(files.Length == 0 ? "No captures in the capture folder yet." : "Captures in " + dir);
				foreach (var f in files)
					if (PointerUI.Button(Path.GetFileName(f))) LoadFile(f);
				break;

			case "Capture":
				if (_capturing)
				{
					UI.PushTint(new Color(1f, 0.35f, 0.35f));
					if (PointerUI.Button("Stop stream")) { StopCapture(); _menu = ""; }
					UI.PopTint();
					UI.SameLine();
					UI.Label($"{_captureIface}   {_rows.Count:N0} packets");
					break;
				}

				if (PlatformPaths.SupportsVpnCapture() && PointerUI.Button("Capture this headset's traffic"))
				{
					PlatformPaths.RequestVpnCapture();
					SetMessage("Starting capture. Accept the VPN prompt if one appears.", false);
					_menu = "";
				}
				UI.SameLine();
				if (PointerUI.Button("Replay open capture as a stream")) { StartReplay(); _menu = ""; }
				UI.Label("");
				if (_captureIfaces.Count == 0)
				{
					if (_ifaceTask != null) UI.Label("Detecting interfaces...");
				}
				else
				{
					UI.Label("Or capture live from an interface:");
					foreach (var iface in _captureIfaces)
					{
						if (PointerUI.Button(iface)) { StartCapture(iface); _menu = ""; }
						UI.SameLine();
					}
					UI.Label("");
				}
				break;

			case "Analyze":
				if (PointerUI.Button("Filter on selected field")) FilterOnSelectedField();
				UI.SameLine();
				if (PointerUI.Button("Filter on this stream")) FilterOnStream();
				UI.SameLine();
				if (PointerUI.Button("Follow stream")) FollowStream();
				UI.SameLine();
				if (PointerUI.Button("Expert info")) _showExpert = true;
				break;

			case "Statistics":
				if (PointerUI.Button("Protocol hierarchy")) RunOutput("Protocol Hierarchy", p => _engine.StatisticAsync(p, "io,phs", _appliedFilter));
				UI.SameLine();
				if (PointerUI.Button("TCP conversations")) RunOutput("TCP Conversations", p => _engine.StatisticAsync(p, "conv,tcp", _appliedFilter));
				UI.SameLine();
				if (PointerUI.Button("UDP conversations")) RunOutput("UDP Conversations", p => _engine.StatisticAsync(p, "conv,udp", _appliedFilter));
				if (PointerUI.Button("IP conversations")) RunOutput("IP Conversations", p => _engine.StatisticAsync(p, "conv,ip", _appliedFilter));
				UI.SameLine();
				if (PointerUI.Button("IP endpoints")) RunOutput("IP Endpoints", p => _engine.StatisticAsync(p, "endpoints,ip", _appliedFilter));
				break;

			case "View":
				PointerUI.Toggle("Packet list", ref _showList);
				UI.SameLine();
				PointerUI.Toggle("Packet details", ref _showDetails);
				UI.SameLine();
				PointerUI.Toggle("Packet bytes", ref _showBytes);
				UI.SameLine();
				PointerUI.Toggle("3D flow graph", ref _showFlow);
				PointerUI.Toggle("Capture overview", ref _showOverview);
				UI.SameLine();
				PointerUI.Toggle("Expert info", ref _showExpert);
				break;

			case "Help":
				if (PointerUI.Button("Wireshark in 60 seconds")) { _outputTitle = "Wireshark in 60 seconds"; _outputText = Guide.CheatSheet; _outputScroll = Vec2.Zero; _outputOpen = true; }
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
		RunOutput($"Follow {proto.ToUpper()} Stream {index}", p => _engine.FollowStreamAsync(p, proto, index));
	}

	// =====================================================================
	// Packet List pane
	// =====================================================================

	static readonly (string name, float cm, int chars)[] Columns =
	{
		("No.", 6, 7), ("Time", 9, 10), ("Source", 13, 15), ("Destination", 13, 15),
		("Protocol", 8, 9), ("Length", 6, 6), ("Info", 37, 41),
	};

	void ListWindow()
	{
		string listTitle = !_capturing ? "Packet List"
			: _paused ? "Packet List  [PAUSED]"
			: _replaySource != null ? "Packet List  [REPLAY]" : "Packet List  [LIVE]";
		ControllerRays.BeginWindow(listTitle, ref _listPose, new Vec2(95, 0) * U.cm, UIWin.Normal);
		if (_guide) UI.Label(Guide.PacketList);

		DrawRow("header", -1, Columns.Select(c => c.name).ToArray(), Theme.HeaderBg, Theme.HeaderText, false);

		int end = Math.Min(_rows.Count, _listTop + PageRows);
		for (int i = _listTop; i < end; i++)
		{
			var r = _rows[i];
			var (bg, fg) = Theme.RowColors(r);
			if (_marked.Contains(r.Number)) { bg = Color.Black; fg = Color.White; }
			if (i == _selectedIndex)        { bg = Theme.SelectedBg; fg = Color.White; }

			DrawRow("row" + i, i, new[]
			{
				r.Number.ToString(), r.RelativeTime.ToString("0.000000"), r.Source, r.Destination,
				r.Protocol, r.Length.ToString(), r.Info,
			}, bg, fg, true);
		}

		UI.HSeparator();
		if (_rows.Count > PageRows)
		{
			float top = _listTop;
			if (PointerUI.HSlider("listscroll", ref top, 0, _rows.Count - PageRows, 1, UI.LayoutRemaining.x))
				_listTop = (int)top;
		}
		if (PointerUI.Button("Page up"))   SelectRow(_selectedIndex - PageRows);
		UI.SameLine();
		if (PointerUI.Button("Page down")) SelectRow(_selectedIndex + PageRows);
		UI.SameLine();
		UI.Label(_rows.Count == 0 ? "No packets" : $"Rows {_listTop + 1}-{end} of {_rows.Count:N0}");
		ControllerRays.EndWindow();
	}

	/// <summary>Draws one full-width row as a single press target, the way a real packet list behaves.</summary>
	void DrawRow(string id, int rowIndex, string[] cells, Color bg, Color fg, bool pressable)
	{
		Vec2 size = new Vec2(UI.LayoutRemaining.x, RowHeight);
		Vec3 at = UI.LayoutAt;
		UI.LayoutReserve(size);

		if (pressable)
		{
			UI.ButtonBehavior(at, size, id, out _, out BtnState press, out BtnState focus);
			if ((press & BtnState.JustActive) != 0 || ControllerRays.Clicked(RowBounds(at, size))) SelectRow(rowIndex);
			if ((focus & BtnState.Active) != 0) bg = Color.Lerp(bg, Theme.Accent, 0.35f);
		}

		const float gap = 0.05f * U.cm;
		Mesh.Cube.Draw(Material.UI,
			Matrix.TS(at + new Vec3(-size.x / 2, -size.y / 2, SurfaceZ), new Vec3(size.x, size.y - gap, 0.1f * U.cm)),
			bg.ToLinear());

		float x = at.x - 0.4f * U.cm;
		float y = at.y - size.y / 2;
		Color text = fg.ToLinear();
		for (int c = 0; c < cells.Length; c++)
		{
			float width = c == cells.Length - 1 ? x - (at.x - size.x) : Columns[c].cm * U.cm;
			Text.Add(Clip(cells[c], Columns[c].chars), Matrix.T(x, y, TextZ), _cellStyle, text, TextAlign.CenterLeft, TextAlign.CenterLeft);
			x -= width;
		}
	}

	static Bounds RowBounds(Vec3 topLeft, Vec2 size) =>
		new Bounds(topLeft + new Vec3(-size.x / 2, -size.y / 2, 0), new Vec3(size.x, size.y, 0.01f));

	void NextMarked()
	{
		if (_marked.Count == 0) { SetMessage("No marked packets. Select one and press Mark.", true); return; }
		for (int step = 1; step <= _rows.Count; step++)
		{
			int i = (_selectedIndex + step) % _rows.Count;
			if (_marked.Contains(_rows[i].Number)) { SelectRow(i); return; }
		}
		SetMessage("No marked packets match the current filter.", true);
	}

	// =====================================================================
	// Capture overview and expert info
	// =====================================================================

	CaptureOverview CurrentOverview()
	{
		bool stale = _overview == null || !ReferenceEquals(_overviewRows, _rows) || _overviewCount != _rows.Count;
		if (stale && (!_capturing || _overview == null || Time.Totalf >= _overviewNextAt))
		{
			_overviewNextAt = Time.Totalf + 1;
			_overview = new CaptureOverview(_rows);
			_overviewRows = _rows;
			_overviewCount = _rows.Count;
		}
		return _overview!;
	}

	void OverviewWindow()
	{
		ControllerRays.BeginWindow("Capture Overview", ref _overviewPose, new Vec2(55, 0) * U.cm, UIWin.Normal);
		var o = CurrentOverview();
		UI.Label($"{_rows.Count:N0} packets    {o.TotalBytes:N0} bytes    {o.Duration:0.00} s");

		ProtocolBar(o);
		foreach (var (protocol, count) in o.Protocols.Take(6))
		{
			Vec3 at = UI.LayoutAt;
			UI.LayoutReserve(new Vec2(UI.LayoutRemaining.x, 1.9f * U.cm));
			Vec3 swatch = at + new Vec3(-0.7f * U.cm, -0.95f * U.cm, SurfaceZ);
			Mesh.Cube.Draw(Material.UI, Matrix.TS(swatch, new Vec3(1.2f, 1.2f, 0.1f) * U.cm), Theme.ProtocolColor(protocol).ToLinear());
			string share = (100.0 * count / _rows.Count).ToString("0.0");
			Text.Add($"{Clip(protocol, 14)}    {count:N0}    {share}%", Matrix.T(at.x - 2 * U.cm, at.y - 0.95f * U.cm, TextZ),
				_cellStyle, Theme.HeaderText.ToLinear(), TextAlign.CenterLeft, TextAlign.CenterLeft);
		}

		UI.HSeparator();
		UI.Label("Traffic over time (tap a bar to jump there)");
		TrafficGraph(o);
		ControllerRays.EndWindow();
	}

	void ProtocolBar(CaptureOverview o)
	{
		Vec2 size = new Vec2(UI.LayoutRemaining.x, 1.6f * U.cm);
		Vec3 at = UI.LayoutAt;
		UI.LayoutReserve(size);
		if (_rows.Count == 0) return;

		float x = at.x;
		foreach (var (protocol, count) in o.Protocols)
		{
			float w = size.x * count / _rows.Count;
			Mesh.Cube.Draw(Material.UI, Matrix.TS(new Vec3(x - w / 2, at.y - size.y / 2, SurfaceZ), new Vec3(w, size.y, 0.1f * U.cm)),
				Theme.ProtocolColor(protocol).ToLinear());
			x -= w;
		}
	}

	void TrafficGraph(CaptureOverview o)
	{
		Vec2 size = new Vec2(UI.LayoutRemaining.x, 12 * U.cm);
		Vec3 at = UI.LayoutAt;
		UI.LayoutReserve(size);

		float barWidth = size.x / CaptureOverview.Bins;
		for (int i = 0; i < CaptureOverview.Bins; i++)
		{
			Vec3 slot = at + new Vec3(-i * barWidth, 0, 0);
			UI.ButtonBehavior(slot, new Vec2(barWidth, size.y), "traffic" + i, out _, out BtnState press, out BtnState focus);
			bool picked = (press & BtnState.JustActive) != 0 || ControllerRays.Clicked(RowBounds(slot, new Vec2(barWidth, size.y)));
			if (picked && o.FirstRowInBin[i] >= 0) SelectRow(o.FirstRowInBin[i]);

			if (o.Peak == 0 || o.PacketsPerBin[i] == 0) continue;
			float h = size.y * o.PacketsPerBin[i] / o.Peak;
			Color color = (focus & BtnState.Active) != 0 ? Color.White : Theme.Accent;
			Mesh.Cube.Draw(Material.UI,
				Matrix.TS(slot + new Vec3(-barWidth / 2, -size.y + h / 2, SurfaceZ), new Vec3(barWidth * 0.8f, h, 0.1f * U.cm)),
				color.ToLinear());
		}
	}

	void ExpertWindow()
	{
		ControllerRays.BeginWindow("Expert Information", ref _expertPose, new Vec2(45, 0) * U.cm, UIWin.Normal);
		var o = CurrentOverview();
		if (o.Expert.Count == 0) UI.Label("No problems spotted in the displayed packets.");
		foreach (var group in o.Expert)
		{
			UI.PushId(group.Label);
			UI.PushTint(group.IsError ? Theme.Bad : Theme.Warn);
			UI.Label($"{group.Label}: {group.Rows.Count:N0}", new Vec2(32, 0) * U.cm);
			UI.PopTint();
			UI.SameLine();
			if (PointerUI.Button("Next"))
			{
				group.Cursor = (group.Cursor + 1) % group.Rows.Count;
				SelectRow(group.Rows[group.Cursor]);
			}
			UI.PopId();
		}
		UI.HSeparator();
		if (PointerUI.Button("Close")) _showExpert = false;
		ControllerRays.EndWindow();
	}

	// =====================================================================
	// Packet Details pane
	// =====================================================================

	void DetailWindow()
	{
		ControllerRays.BeginWindow("Packet Details", ref _detailPose, new Vec2(55, 0) * U.cm, UIWin.Normal);
		if (_guide) UI.Label(Guide.Details);

		if (!CanInspect)
		{
			UI.Label(_replaySource != null || _vpn != null ? "Pause the stream to inspect a packet." : "Stop the capture to inspect packet details.");
			ControllerRays.EndWindow();
			return;
		}
		if (_detail == null)
		{
			UI.Label(CurrentNumber > 0 ? "Loading packet..." : "Select a packet in the list.");
			ControllerRays.EndWindow();
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
			if (PointerUI.Button(new string(' ', depth * 3) + marker + Clip(node.Label, 66), new Vec2(52, 0) * U.cm))
			{
				if (node.Children.Count > 0) node.Expanded = !node.Expanded;
				_selectedNode = node;
				RebuildHex();
			}
			UI.PopTint();
			UI.PopId();
		}

		UI.HSeparator();
		if (PointerUI.Button("Scroll up"))   _detailTop = Math.Max(0, _detailTop - DetailRows / 2);
		UI.SameLine();
		if (PointerUI.Button("Scroll down")) _detailTop += DetailRows / 2;
		UI.SameLine();
		if (PointerUI.Button("Expand all"))  SetAll(_detail.Tree, true);
		UI.SameLine();
		if (PointerUI.Button("Collapse all")) SetAll(_detail.Tree, false);
		ControllerRays.EndWindow();
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
		ControllerRays.BeginWindow("Packet Bytes", ref _bytesPose, new Vec2(58, 0) * U.cm, UIWin.Normal);
		if (_guide) UI.Label(Guide.Bytes);

		if (_selectedNode != null && _selectedNode.Size > 0)
			UI.Label($"Selected: {Clip(_selectedNode.Label, 50)}   ({_selectedNode.Size} bytes at offset {_selectedNode.Pos})");

		if (_mono is TextStyle mono) UI.PushTextStyle(mono);
		UI.Text(_hexText.Length == 0 ? "(no packet)" : _hexText, ref _hexScroll, UIScroll.Vertical,
			new Vec2(56, 17) * U.cm, TextAlign.TopLeft, TextFit.Clip);
		if (_mono != null) UI.PopTextStyle();
		ControllerRays.EndWindow();
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
		ControllerRays.BeginWindow(_outputTitle, ref _outputPose, new Vec2(70, 0) * U.cm, UIWin.Normal);
		if (_mono is TextStyle mono) UI.PushTextStyle(mono);
		UI.Text(_outputText, ref _outputScroll, UIScroll.Vertical, new Vec2(68, 28) * U.cm, TextAlign.TopLeft, TextFit.Clip);
		if (_mono != null) UI.PopTextStyle();
		if (PointerUI.Button("Close")) _outputOpen = false;
		ControllerRays.EndWindow();
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
			_flowTask = Task.Run(async () => ConversationBuilder.Build(await _engine.ReadFileAsync(path, 5000)));
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

	/// <summary>Capture files in a folder, newest first, capped so the menu stays usable.</summary>
	static string[] CaptureFiles(string dir)
	{
		try
		{
			return Directory.EnumerateFiles(dir)
				.Where(f => f.EndsWith(".pcap", StringComparison.OrdinalIgnoreCase)
				         || f.EndsWith(".pcapng", StringComparison.OrdinalIgnoreCase)
				         || f.EndsWith(".cap", StringComparison.OrdinalIgnoreCase))
				.OrderByDescending(File.GetLastWriteTimeUtc)
				.Take(8)
				.ToArray();
		}
		catch (Exception) { return Array.Empty<string>(); }
	}
}
