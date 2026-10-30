using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics;
using Android.OS;
using Android.Runtime;
using Android.Views;
using StereoKit;
using System;
using System.Reflection;
using System.Threading;

namespace WiresharkVR.App;

[Activity(Label = "@string/app_name", MainLauncher = true, Exported = true, LaunchMode = LaunchMode.SingleTask)]
[IntentFilter(new[]{Intent.ActionMain}, Categories = new[]{"org.khronos.openxr.intent.category.IMMERSIVE_HMD", "com.oculus.intent.category.VR", Intent.CategoryLauncher})]
public class MainActivity : Activity, ISurfaceHolderCallback2
{
	View surface;

	protected override void OnCreate(Bundle savedInstanceState)
	{
		base.OnCreate(savedInstanceState);
		_instance = this;
		Run();
	}

#if DEBUG
	protected override void OnResume()
	{
		base.OnResume();
		if (Intent?.GetBooleanExtra("vpnTest", false) == true) RequestVpn();
	}
#endif

	const int VpnConsentRequest = 7001;

	static MainActivity? _instance;
	static volatile bool _vpnDenied;

	public static void RequestVpnFromAnyThread()
	{
		_instance?.RunOnUiThread(() => _instance?.RequestVpn());
	}

	public static bool TakeVpnDenied()
	{
		bool denied = _vpnDenied;
		_vpnDenied = false;
		return denied;
	}

	void RequestVpn()
	{
		Intent? consent = Android.Net.VpnService.Prepare(this);
		if (consent != null) StartActivityForResult(consent, VpnConsentRequest);
		else StartService(new Intent(this, typeof(VpnCaptureService)));
	}

	protected override void OnActivityResult(int requestCode, [GeneratedEnum] Result resultCode, Intent? data)
	{
		base.OnActivityResult(requestCode, resultCode, data);
		if (requestCode != VpnConsentRequest) return;
		if (resultCode == Result.Ok) StartService(new Intent(this, typeof(VpnCaptureService)));
		else _vpnDenied = true;
	}

	protected override void OnDestroy()
	{
		SK.Quit();
		base.OnDestroy();
	}

	static bool running = false;
	void Run()
	{
		if (running) return;
		running = true;

		// Before anything else, give StereoKit the Activity. This should
		// be set before any other SK calls, otherwise native library
		// loading may fail.
		SK.AndroidActivity = this;

		// Set up a surface for StereoKit to draw on, this is only really
		// important for flatscreen experiences.
		Window.TakeSurface(this);
		Window.SetFormat(Format.Unknown);
		surface = new View(this);
		SetContentView(surface);
		surface.RequestFocus();

		// Task.Run will eat exceptions, but Thread.Start doesn't seem to.
		new Thread(InvokeStereoKit).Start();
	}

	static void InvokeStereoKit()
	{
		MethodInfo entryPoint = typeof(MainActivity).Assembly.EntryPoint
			?? throw new Exception("Couldn't find the app's entry point!");

		// Entry points come in a variety of flavors, parse out how we need to
		// invoke.
		ParameterInfo[] entryParams = entryPoint.GetParameters();
		bool     noArgs  = entryParams.Length == 0;
		bool     hasArgs = entryParams.Length == 1 && entryParams[0].ParameterType == typeof(string[]);
		bool     retVoid = entryPoint.ReturnType == typeof(void);
		bool     retInt  = entryPoint.ReturnType == typeof(int);
		string[] args    = new string[] { };

		// Calling as a delegate allows nice exception bubbling.
		if      (noArgs  && retVoid) ((Action)             Delegate.CreateDelegate(typeof(Action),             entryPoint))();
		else if (noArgs  && retInt ) ((Func<int>)          Delegate.CreateDelegate(typeof(Func<int>),          entryPoint))();
		else if (hasArgs && retVoid) ((Action<string[]>)   Delegate.CreateDelegate(typeof(Action<string[]>),   entryPoint))(args);
		else if (hasArgs && retInt ) ((Func<string[],int>) Delegate.CreateDelegate(typeof(Func<string[],int>), entryPoint))(args);
		else throw new Exception("Couldn't invoke the app's entry point!");

		Process.KillProcess(Process.MyPid());
	}

	// Events related to surface state changes
	public void SurfaceChanged     (ISurfaceHolder holder, [GeneratedEnum] Format format, int width, int height) => SK.SetWindow(holder.Surface.Handle);
	public void SurfaceCreated     (ISurfaceHolder holder) => SK.SetWindow(holder.Surface.Handle);
	public void SurfaceDestroyed   (ISurfaceHolder holder) => SK.SetWindow(IntPtr.Zero);
	public void SurfaceRedrawNeeded(ISurfaceHolder holder) { }
}