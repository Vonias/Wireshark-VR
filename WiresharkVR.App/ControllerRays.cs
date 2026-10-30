using System;
using System.Collections.Generic;
using StereoKit;

namespace WiresharkVR.App;

/// <summary>
/// Controller pointers. Each draws a line to the first window it reaches and presses UI directly:
/// StereoKit's hand input never reached the buttons when driven by controllers, or by an overridden
/// hand, so elements ask this class whether the pointer is on them.
/// </summary>
static class ControllerRays
{
	const float MaxLength  = 2.5f;
	const float HeadHeight = 3 * U.cm;
	const float WindowDepth = 5 * U.cm;

	sealed class Pointer
	{
		public bool    Active;
		public Vec3    Origin, Direction, Point;
		public bool    OnWindow;
		public string  Window = "";
		public bool    Pressed, JustPressed, Gripped;
		public string? Grabbed;
		public float   GrabDistance;
		public Vec3    GrabOffset;
	}

	static readonly Pointer[] Pointers = { new Pointer(), new Pointer() };
	static readonly List<(string title, Pose pose, float width, float height)> Windows = new();
	static string _currentWindow = "";
	static Material? _glow;

	/// <summary>The window a pointer last landed on; the sticks act on this one.</summary>
	public static string ActiveWindow { get; private set; } = "Packet List";

	public static bool IsGrabbed(string title) => Array.Exists(Pointers, p => p.Grabbed == title);

	static readonly Color32 Idle = new Color32(120, 200, 235, 255);
	static readonly Color32 Hit  = new Color32(255, 255, 255, 255);
	static readonly Color32 Fade = new Color32(120, 200, 235, 0);

	/// <summary>Use in place of UI.WindowBegin so the window can be carried with the grip.</summary>
	public static void BeginWindow(string title, ref Pose pose, Vec2 size, UIWin style)
	{
		foreach (var p in Pointers)
		{
			if (!p.Active || !p.Gripped) p.Grabbed = null;
			else if (p.Grabbed == null && p.OnWindow && p.Window == title)
			{
				p.Grabbed = title;
				p.GrabDistance = Vec3.Distance(p.Origin, p.Point);
				p.GrabOffset = pose.position - p.Point;
			}
			if (p.Grabbed == title) pose.position = p.Origin + p.Direction * p.GrabDistance + p.GrabOffset;
		}
		_currentWindow = title;
		UI.WindowBegin(title, ref pose, size, style);
	}

	/// <summary>Use in place of UI.WindowEnd so the window can stop the pointer lines.</summary>
	public static void EndWindow()
	{
		float width = UI.LayoutRemaining.x + UI.Settings.margin * 2;
		Windows.Add((_currentWindow, Hierarchy.ToWorld(Pose.Identity), width, -UI.LayoutAt.y));
		UI.WindowEnd();
	}

	/// <summary>Runs before the UI each frame, using the windows drawn on the previous one.</summary>
	public static void Step()
	{
		foreach (Handed side in new[] { Handed.Left, Handed.Right })
		{
			Controller controller = Input.Controller(side);
			if (!controller.IsTracked)
			{
				Pointers[(int)side].Active = false;
				continue;
			}
			Input.HandVisible(side, false);
			Aim(Pointers[(int)side], controller.aim.position, controller.aim.Forward,
				controller.trigger > 0.5f, controller.grip > 0.5f);
		}
		Windows.Clear();
	}

	static void Aim(Pointer p, Vec3 origin, Vec3 direction, bool pressed, bool gripped)
	{
		p.Active = true;
		p.Origin = origin;
		p.Direction = direction;
		p.JustPressed = pressed && !p.Pressed;
		p.Pressed = pressed;
		p.Gripped = gripped;

		if (Nearest(origin, direction) is (float distance, string title))
		{
			p.OnWindow = true;
			p.Window = title;
			ActiveWindow = title;
			p.Point = origin + direction * distance;
			Lines.Add(origin, p.Point, Hit, Idle, 0.003f);
			Mesh.Sphere.Draw(Material.Unlit, Matrix.TS(p.Point, Vec3.One * (pressed ? 0.018f : 0.012f)), Color.White);
		}
		else
		{
			p.OnWindow = false;
			Lines.Add(origin, origin + direction * MaxLength, Idle, Fade, 0.003f);
		}
	}

	/// <summary>Call straight after laying out an element: true on the frame a trigger is pulled while pointing at it.</summary>
	public static bool Clicked() => Clicked(UI.LayoutLast);

	public static bool Clicked(Bounds element)
	{
		bool clicked = false;
		foreach (var p in Pointers)
		{
			if (!p.Active || !p.OnWindow || p.Window != _currentWindow) continue;
			if (!IsOver(p, element, out _)) continue;
			Glow(element);
			clicked |= p.JustPressed;
		}
		return clicked;
	}

	/// <summary>Where a held trigger sits across the element, from 0 at its left edge to 1 at its right, or null.</summary>
	public static float? Dragged(Bounds element)
	{
		foreach (var p in Pointers)
		{
			if (!p.Active || !p.OnWindow || !p.Pressed || p.Window != _currentWindow) continue;
			if (IsOver(p, element, out Vec3 local))
				return Math.Clamp((element.center.x + element.dimensions.x / 2 - local.x) / element.dimensions.x, 0f, 1f);
		}
		return null;
	}

	static bool IsOver(Pointer p, Bounds element, out Vec3 local)
	{
		local = Hierarchy.ToLocal(p.Point);
		return Math.Abs(local.x - element.center.x) <= element.dimensions.x / 2
		    && Math.Abs(local.y - element.center.y) <= element.dimensions.y / 2
		    && Math.Abs(local.z) <= WindowDepth;
	}

	static void Glow(Bounds element)
	{
		if (_glow == null)
		{
			_glow = Material.Unlit.Copy();
			_glow.Transparency = Transparency.Add;
			_glow.DepthWrite = false;
		}
		Vec3 center = element.center + new Vec3(0, 0, -1.3f * U.cm);
		Vec3 size = new Vec3(element.dimensions.x, element.dimensions.y, 0.1f * U.cm);
		Mesh.Cube.Draw(_glow, Matrix.TS(center, size), new Color(0.10f, 0.45f, 0.65f));
	}

	static (float distance, string title)? Nearest(Vec3 origin, Vec3 direction)
	{
		(float distance, string title)? best = null;
		foreach (var (title, pose, width, height) in Windows)
		{
			Vec3 normal = pose.Forward;
			float facing = Vec3.Dot(direction, normal);
			if (Math.Abs(facing) < 0.0001f) continue;

			float distance = Vec3.Dot(pose.position - origin, normal) / facing;
			if (distance <= 0 || (best is { } b && distance >= b.distance)) continue;

			Vec3 offset = origin + direction * distance - pose.position;
			float x = Vec3.Dot(offset, pose.Right);
			float y = Vec3.Dot(offset, pose.Up);
			if (Math.Abs(x) <= width / 2 && y >= -height && y <= HeadHeight) best = (distance, title);
		}
		return best;
	}
}

/// <summary>Standard UI elements that also answer to the controller pointers.</summary>
static class PointerUI
{
	public static bool Button(string text)
	{
		bool pressed = UI.Button(text);
		return ControllerRays.Clicked() || pressed;
	}

	public static bool Button(string text, Vec2 size)
	{
		bool pressed = UI.Button(text, size);
		return ControllerRays.Clicked() || pressed;
	}

	public static bool Toggle(string text, ref bool value)
	{
		bool changed = UI.Toggle(text, ref value);
		if (!ControllerRays.Clicked()) return changed;
		value = !value;
		return true;
	}

	public static bool HSlider(string id, ref float value, float min, float max, float step, float width)
	{
		bool changed = UI.HSlider(id, ref value, min, max, step, width);
		if (ControllerRays.Dragged(UI.LayoutLast) is not float at) return changed;
		value = MathF.Round((min + (max - min) * at) / step) * step;
		return true;
	}
}
