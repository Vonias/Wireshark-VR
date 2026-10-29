namespace WiresharkVR.App;

/// <summary>
/// Where captures live. The PC and the headset differ, so each side implements these in
/// PlatformPaths.Net.cs / PlatformPaths.Android.cs (the project files include only their own).
/// </summary>
static partial class PlatformPaths
{
	/// <summary>Path to the bundled sample capture, or null if it can't be found.</summary>
	public static partial string? SampleCapture();

	/// <summary>A folder the user can drop captures into, or null if there isn't one.</summary>
	public static partial string? CaptureDirectory();

	/// <summary>True when the OS file picker can be used (PC), false on the headset.</summary>
	public static partial bool SupportsFilePicker();

	/// <summary>Candidate fixed-width fonts, best first, for the hex dump.</summary>
	public static partial string[] MonospaceFonts();
}
