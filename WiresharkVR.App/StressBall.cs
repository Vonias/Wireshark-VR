using System;
using StereoKit;

namespace WiresharkVR.App;

/// <summary>
/// A squishy ball floating in front of you. Pinch it to pick it up and move it anywhere;
/// make a fist around it (grip) to squeeze it and make it squeak.
/// </summary>
class StressBall
{
	const float Radius       = 0.06f;
	const float ReachFactor  = 1.6f;   // how close a hand must be, in ball radii
	const float SqueakOnAt   = 0.45f;  // squeeze level that triggers a squeak
	const float ReleaseAt    = 0.25f;  // squeeze level below which the ball counts as let go

	// Where the ball starts; after that it lives wherever the user last put it.
	Pose _pose = new Pose(0, -0.50f, -0.50f, Quat.Identity);

	readonly Mesh     _mesh = Mesh.GenerateSphere(1f, 24);
	readonly Material _mat  = Material.Default;
	readonly Sound[]  _squeaks;
	readonly Sound    _release;
	readonly Random   _rng = new Random();

	float _squeeze;
	bool  _squeezed;

	public StressBall()
	{
		// Rising chirps with a little vibrato and a second harmonic read as a rubber squeak.
		_squeaks = new[]
		{
			Chirp(1100, 2300, 0.13f, 0.40f),
			Chirp(1400, 2700, 0.10f, 0.40f),
			Chirp( 900, 1900, 0.16f, 0.40f),
			Chirp(1700, 3000, 0.09f, 0.35f),
		};
		_release = Chirp(1500, 700, 0.12f, 0.25f); // the lower "pfft" as it springs back
	}

	public void Step()
	{
		// Pinch to carry. Position only, so the ball keeps its orientation while it's moved.
		UI.Handle("stressball", ref _pose, new Bounds(Vec3.Zero, Vec3.One * Radius * 2f), false, UIMove.PosOnly, UIGesture.Pinch);
		Vec3 center = _pose.position;

		// Only a grip squeezes, so pinching to pick the ball up doesn't set off a squeak.
		float target = 0;
		foreach (Handed side in new[] { Handed.Left, Handed.Right })
		{
			Hand hand = Input.Hand(side);
			if (!hand.IsTracked) continue;
			if (Vec3.Distance(hand.palm.position, center) < Radius * ReachFactor)
				target = Math.Max(target, hand.gripActivation);
		}

		// Ease toward the target so the ball squishes and rebounds instead of snapping.
		_squeeze += (target - _squeeze) * Math.Min(1f, Time.Stepf * 18f);

		if (!_squeezed && _squeeze > SqueakOnAt)
		{
			_squeezed = true;
			_squeaks[_rng.Next(_squeaks.Length)].Play(center, 1f);
		}
		else if (_squeezed && _squeeze < ReleaseAt)
		{
			_squeezed = false;
			_release.Play(center, 0.6f);
		}

		// Squash: shorter and wider as it is squeezed.
		float s = _squeeze;
		Vec3 size = new Vec3(1 + 0.25f * s, 1 - 0.35f * s, 1 + 0.25f * s) * (Radius * 2f);
		Color color = Color.Lerp(new Color(0.95f, 0.30f, 0.30f), new Color(1f, 0.60f, 0.25f), s);
		_mesh.Draw(_mat, Matrix.TRS(center, Quat.Identity, size), color);

		Text.Add("pinch to move, grip to squeeze", Matrix.TRS(center + new Vec3(0, -0.10f, 0), Quat.LookDir(0, 0, 1), Vec3.One * 0.5f));
	}

	static Sound Chirp(float startHz, float endHz, float seconds, float volume)
	{
		float sweep = (endHz - startHz) / seconds;
		return Sound.Generate(t =>
		{
			float vibrato = 1f + 0.03f * MathF.Sin(2 * MathF.PI * 35 * t);
			float phase   = 2 * MathF.PI * (startHz * t + 0.5f * sweep * t * t) * vibrato;
			float attack  = Math.Min(1f, t / 0.005f);
			float decay   = MathF.Exp(-6f * t / seconds);
			float tone    = MathF.Sin(phase) + 0.3f * MathF.Sin(2 * phase);
			return tone * attack * decay * volume;
		}, seconds);
	}
}
