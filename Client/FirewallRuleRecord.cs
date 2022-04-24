using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.CompilerServices;
using Client.Annotations;
using TrueMogician.Extensions.Enumerator;

namespace Client;

public record FirewallRuleRecord(FirewallRule Rule) : ISerializable, INotifyPropertyChanged {
	private bool _enabled = true;

	public FirewallRule Rule { get; set; } = Rule;

	public bool Present { get; set; } = true;

	public bool Enabled {
		get => _enabled;
		set {
			if (_enabled != value) {
				_enabled = value;
				OnEnabledChanged();
			}
		}
	}

	public ulong HitCount { get; set; }

	public static FirewallRuleRecord Deserialize(IEnumerator<byte> buffer) {
		var rule = FirewallRule.Deserialize(buffer);
		byte @byte = buffer.GetAndMoveNext();
		return new FirewallRuleRecord(rule) {
			Present = (@byte & 0b10) != 0,
			Enabled = (@byte & 1) != 0,
			HitCount = BitConverter.ToUInt64(buffer.GetAndMove(8))
		};
	}

	public byte[] Serialize() => Rule.Serialize()
		.Append((byte)((Convert.ToByte(Present) << 1) | Convert.ToByte(Enabled)))
		.Concat(BitConverter.GetBytes(HitCount))
		.ToArray();

	public event PropertyChangedEventHandler? PropertyChanged;

	public event EventHandler? EnabledChanged;

	[NotifyPropertyChangedInvocator]
	protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	protected virtual void OnEnabledChanged(EventArgs? e = null) =>
		EnabledChanged?.Invoke(this, e ?? EventArgs.Empty);
}