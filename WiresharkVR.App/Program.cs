using System;
using StereoKit;

namespace WiresharkVR.App;

class Program
{
	static void Main(string[] args)
	{
		// "--sim" forces the desktop simulator window even when a headset runtime is available.
		// Any other argument is the .pcap/.pcapng to open; with none, the bundled sample opens.
		bool sim = Array.IndexOf(args, "--sim") >= 0;
		string? argPath = Array.Find(args, a => !a.StartsWith("--"));

		SKSettings settings = new SKSettings
		{
			appName = "Wireshark VR",
			mode    = sim ? AppMode.Simulator : AppMode.XR,
		};
		if (!SK.Initialize(settings))
			return;

		// The app needs SK initialized first (it allocates GPU meshes).
		string? path = argPath ?? WiresharkApp.FindSample();
		string? error = null;
		WiresharkApp? app = null;
		try
		{
			app = new WiresharkApp(path, path == null ? "No capture found. Use File > Open file..." : null);
		}
		catch (Exception e)
		{
			error = e.Message;
		}

		Pose     errorPose      = new Pose(0, 0, -0.6f, Quat.LookDir(0, 0, 1));
		Matrix   floorTransform = Matrix.TS(0, -1.5f, 0, new Vec3(30, 0.1f, 30));
		Material floorMaterial  = new Material("floor.hlsl");
		floorMaterial.Transparency = Transparency.Blend;

		SK.Run(() => {
			if (Device.DisplayBlend == DisplayBlend.Opaque)
				Mesh.Cube.Draw(floorMaterial, floorTransform);

			if (app != null)
			{
				app.Step();
			}
			else
			{
				UI.WindowBegin("Wireshark VR", ref errorPose, new Vec2(30, 0) * U.cm, UIWin.Normal);
				UI.Label("Could not start:\n" + error);
				UI.WindowEnd();
			}
		});
	}
}
