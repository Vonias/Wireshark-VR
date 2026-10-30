using System;
using System.IO;
using System.Linq;
using System.Threading;
using Android.App;
using Android.Content;
using Android.Net;
using Android.OS;
using Android.Util;
using Java.Net;
using Microsoft.Win32.SafeHandles;
using WiresharkVR.Core.Vpn;

namespace WiresharkVR.App;

/// <summary>Routes the headset's IPv4 and IPv6 traffic through this app so it can be recorded, then sends it on.</summary>
[Service(Name = "com.companyname.wiresharkvr.app.VpnCaptureService", Permission = "android.permission.BIND_VPN_SERVICE", Exported = false)]
[IntentFilter(new[] { "android.net.VpnService" })]
public class VpnCaptureService : VpnService
{
	const string Tag = "WiresharkVpn";
	const string FallbackDns = "1.1.1.1";

	static VpnCaptureService? _current;

	public static LiveCapture? Active { get; private set; }

	ParcelFileDescriptor? _tun;
	FileStream? _stream;
	UserspaceForwarder? _forwarder;
	LiveCapture? _capture;
	readonly object _writeGate = new();
	volatile bool _running;

	public static void StopCapture() => _current?.Shutdown();

	public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
	{
		if (_running) return StartCommandResult.NotSticky;

		string? folder = PlatformPaths.CaptureDirectory();
		if (folder == null) { StopSelf(); return StartCommandResult.NotSticky; }

		var builder = new Builder(this)
			.SetSession("Wireshark VR capture")!
			.SetMtu(1500)!
			.SetBlocking(true)!
			.AddAddress("10.111.0.2", 32)!
			.AddRoute("0.0.0.0", 0)!
			.AddAddress("fd00:6f::2", 128)!
			.AddRoute("::", 0)!
			.AddDisallowedApplication(PackageName!)!;
		foreach (string dns in NetworkDnsServers()) builder.AddDnsServer(dns);

		_tun = builder.Establish();
		if (_tun == null)
		{
			Log.Warn(Tag, "The VPN was not established.");
			StopSelf();
			return StartCommandResult.NotSticky;
		}

		_capture = new LiveCapture(Path.Combine(folder, $"headset-{DateTime.Now:yyyyMMdd-HHmmss}.pcap"));
		_stream = new FileStream(new SafeFileHandle((IntPtr)_tun.Fd, false), FileAccess.ReadWrite, 0, false);
		_forwarder = new UserspaceForwarder(WriteToTunnel);
		_running = true;
		_current = this;
		Active = _capture;
		new Thread(ReadLoop) { IsBackground = true, Name = "VpnRead" }.Start();
		Log.Info(Tag, "Capture started: " + _capture.FilePath);
		return StartCommandResult.NotSticky;
	}

	/// <summary>Keeps the DNS servers the Wi-Fi network already uses, so lookups go where they normally would.</summary>
	string[] NetworkDnsServers()
	{
		var connectivity = (ConnectivityManager?)GetSystemService(ConnectivityService);
		var servers = connectivity?.GetLinkProperties(connectivity.ActiveNetwork)?.DnsServers
			?.OfType<Inet4Address>().Select(a => a.HostAddress!).ToArray();
		return servers is { Length: > 0 } ? servers : new[] { FallbackDns };
	}

	void WriteToTunnel(byte[] packet)
	{
		lock (_writeGate)
		{
			if (!_running) return;
			_capture?.Add(packet);
			_stream?.Write(packet, 0, packet.Length);
		}
	}

	void ReadLoop()
	{
		var buffer = new byte[32768];
		long count = 0;
		try
		{
			while (_running)
			{
				int read = _stream!.Read(buffer, 0, buffer.Length);
				if (read <= 0) continue;
				_capture!.Add(buffer.AsSpan(0, read));
				_forwarder!.HandleOutbound(buffer, read);
				if (++count % 100 == 0) Log.Info(Tag, $"{count} packets out, {_forwarder.OpenFlows} open flows");
			}
		}
		catch (Exception e) when (_running)
		{
			Log.Error(Tag, "Tunnel read failed: " + e.Message);
			Shutdown();
		}
		catch (Exception) { /* the tunnel was closed by Shutdown */ }
	}

	void Shutdown()
	{
		lock (_writeGate)
		{
			if (!_running) return;
			_running = false;
		}
		Active = null;
		_current = null;
		_forwarder?.Dispose();
		_tun?.Close();
		_capture?.Dispose();
		StopSelf();
		Log.Info(Tag, "Capture stopped.");
	}

	public override void OnRevoke()
	{
		Shutdown();
		base.OnRevoke();
	}

	public override void OnDestroy()
	{
		Shutdown();
		base.OnDestroy();
	}
}
