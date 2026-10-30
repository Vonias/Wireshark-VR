using System;
using System.Collections.Generic;
using System.Linq;
using WiresharkVR.Core;

namespace WiresharkVR.App;

/// <summary>Summary of the packet list: protocol mix, traffic over time and likely problems.</summary>
sealed class CaptureOverview
{
	public const int Bins = 48;

	public List<(string protocol, int count)> Protocols { get; } = new();
	public int[]  PacketsPerBin { get; } = new int[Bins];
	public int[]  FirstRowInBin { get; } = new int[Bins];
	public int    Peak { get; private set; }
	public double Duration { get; private set; }
	public long   TotalBytes { get; private set; }
	public List<ExpertGroup> Expert { get; } = new();

	static readonly (string label, string match, bool error)[] ExpertRules =
	{
		("Malformed packets",    "Malformed",      true),
		("Connection resets",    "[RST",           true),
		("Retransmissions",      "Retransmission", false),
		("Out-of-order packets", "Out-Of-Order",   false),
		("Duplicate ACKs",       "Dup ACK",        false),
		("Zero window",          "ZeroWindow",     false),
	};

	public CaptureOverview(List<PacketRow> rows)
	{
		Array.Fill(FirstRowInBin, -1);
		if (rows.Count == 0) return;

		double start = rows[0].RelativeTime;
		Duration = Math.Max(0, rows[^1].RelativeTime - start);
		var counts = new Dictionary<string, int>();
		var groups = ExpertRules.Select(r => new ExpertGroup(r.label, r.error)).ToArray();

		for (int i = 0; i < rows.Count; i++)
		{
			var r = rows[i];
			counts[r.Protocol] = counts.GetValueOrDefault(r.Protocol) + 1;
			TotalBytes += r.Length;

			int bin = Duration <= 0 ? 0 : Math.Clamp((int)((r.RelativeTime - start) / Duration * Bins), 0, Bins - 1);
			PacketsPerBin[bin]++;
			if (FirstRowInBin[bin] < 0) FirstRowInBin[bin] = i;

			for (int g = 0; g < ExpertRules.Length; g++)
				if (r.Info.Contains(ExpertRules[g].match)) groups[g].Rows.Add(i);
		}

		Peak = PacketsPerBin.Max();
		Protocols.AddRange(counts.OrderByDescending(kv => kv.Value).Select(kv => (kv.Key, kv.Value)));
		Expert.AddRange(groups.Where(g => g.Rows.Count > 0));
	}
}

sealed class ExpertGroup
{
	public string    Label { get; }
	public bool      IsError { get; }
	public List<int> Rows { get; } = new();
	public int       Cursor { get; set; } = -1;

	public ExpertGroup(string label, bool isError) { Label = label; IsError = isError; }
}
