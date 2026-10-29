using System;
using System.IO;

namespace WiresharkVR.App;

static partial class PlatformPaths
{
	public static partial string? SampleCapture() => SamplesFolder() is string dir ? Path.Combine(dir, "loopback-http.pcapng") : null;

	public static partial string? CaptureDirectory() => SamplesFolder();

	public static partial bool SupportsFilePicker() => true;

	public static partial string[] MonospaceFonts() => new[] { @"C:\Windows\Fonts\consola.ttf" };

	/// <summary>Walks up from the executable until it finds samples/loopback-http.pcapng (works from bin/ folders).</summary>
	static string? SamplesFolder()
	{
		var dir = new DirectoryInfo(AppContext.BaseDirectory);
		while (dir != null)
		{
			string samples = Path.Combine(dir.FullName, "samples");
			if (File.Exists(Path.Combine(samples, "loopback-http.pcapng"))) return samples;
			dir = dir.Parent;
		}
		return null;
	}
}
