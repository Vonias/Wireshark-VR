using System.IO;
using Android.App;

namespace WiresharkVR.App;

static partial class PlatformPaths
{
	const string SampleName = "loopback-http.pcapng";

	/// <summary>
	/// The app's own external folder: /sdcard/Android/data/&lt;package&gt;/files/captures.
	/// It needs no storage permission and can be filled over USB with "adb push".
	/// </summary>
	public static partial string? CaptureDirectory()
	{
		string? root = Application.Context.GetExternalFilesDir(null)?.AbsolutePath ?? Application.Context.FilesDir?.AbsolutePath;
		if (root == null) return null;
		string dir = Path.Combine(root, "captures");
		Directory.CreateDirectory(dir);
		return dir;
	}

	/// <summary>Copies the sample out of the APK on first run so it can be opened like any other capture.</summary>
	public static partial string? SampleCapture()
	{
		string? dir = CaptureDirectory();
		if (dir == null) return null;

		string target = Path.Combine(dir, SampleName);
		if (!File.Exists(target))
		{
			using var asset = Application.Context.Assets!.Open(SampleName);
			using var file = File.Create(target);
			asset.CopyTo(file);
		}
		return target;
	}

	public static partial bool SupportsFilePicker() => false;

	public static partial string[] MonospaceFonts() => new[] { "/system/fonts/DroidSansMono.ttf", "/system/fonts/CutiveMono.ttf" };
}
