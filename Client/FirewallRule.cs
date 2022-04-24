using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using Client.Annotations;
using TrueMogician.Extensions.Enumerator;

namespace Client;

public record FirewallRule : ISerializable, INotifyPropertyChanged {
	internal static uint NextId { get; set; } = 1;

	private FirewallRule(uint id, string name) {
		Id = id;
		Name = name;
	}

	public FirewallRule(string name) : this(NextId++, name) { }

	public uint Id { get; }

	public string Name { get; set; }

	public Direction Direction { get; set; } = Direction.InOut;

	public Protocol Protocol { get; set; } = Protocol.Any;

	public MacRule SourceMacRule { get; set; } = MacRule.Default;

	public MacRule DestinationMacRule { get; set; } = MacRule.Default;

	public IpRule SourceIpRule { get; set; } = IpRule.Default;

	public IpRule DestinationIpRule { get; set; } = IpRule.Default;

	public PortRule SourcePortRule { get; set; } = PortRule.Default;

	public PortRule DestinationPortRule { get; set; } = PortRule.Default;

	public byte[] Serialize() => BitConverter.GetBytes(Id)
		.Concat(Encoding.ASCII.GetBytes(Name))
		.Append((byte)0)
		.Append((byte)(((byte)Direction << 6) | (byte)Protocol))
		.Concat(SourceMacRule.Serialize())
		.Concat(DestinationMacRule.Serialize())
		.Concat(SourceIpRule.Serialize())
		.Concat(DestinationIpRule.Serialize())
		.Concat(SourcePortRule.Serialize())
		.Concat(DestinationPortRule.Serialize())
		.ToArray();

	public static FirewallRule Deserialize(IEnumerator<byte> buffer) {
		var id = BitConverter.ToUInt32(buffer.GetAndMove(4));
		var nameBuffer = new List<byte>();
		while (buffer.GetAndMoveNext() is var b && b != 0)
			nameBuffer.Add(b);
		byte tmp = buffer.GetAndMoveNext();
		return new FirewallRule(id, Encoding.ASCII.GetString(nameBuffer.ToArray())) {
			Direction = (Direction)(tmp >> 6),
			Protocol = (Protocol)(tmp & 0b111111),
			SourceMacRule = MacRule.Deserialize(buffer),
			DestinationMacRule = MacRule.Deserialize(buffer),
			SourceIpRule = IpRule.Deserialize(buffer),
			DestinationIpRule = IpRule.Deserialize(buffer),
			SourcePortRule = PortRule.Deserialize(buffer),
			DestinationPortRule = PortRule.Deserialize(buffer)
		};
	}

	public event PropertyChangedEventHandler? PropertyChanged;

	[NotifyPropertyChangedInvocator]
	protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum Protocol : byte {
	Any,

	ARP,

	IPv4,

	IPv6,

	ICMP,

	IPSec,

	TCP,

	UDP
}

[Flags]
public enum Direction : byte {
	In = 1 << 0,

	Out = 1 << 1,

	InOut = In | Out
}

public record MacRule(byte[] Mac, byte[] Mask) : ISerializable, INotifyPropertyChanged {
	public static MacRule Default { get; } = new(new byte[6], new byte[6]);

	public byte[] Mac { get; set; } = Mac;

	public byte[] Mask { get; set; } = Mask;

	public static MacRule Deserialize(IEnumerator<byte> buffer) =>
		new(buffer.GetAndMove(6), buffer.GetAndMove(6));

	public byte[] Serialize() => Mac.Concat(Mask).ToArray();

	public virtual bool Equals(MacRule? other) {
		if (other is null)
			return false;
		return Mac.SequenceEqual(other.Mac) && Mask.SequenceEqual(other.Mask);
	}

	public override int GetHashCode() => HashCode.Combine(Mac, Mask);

	public event PropertyChangedEventHandler? PropertyChanged;

	[NotifyPropertyChangedInvocator]
	protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public record IpRule(byte Version, byte[] Ip, byte[] Mask) : ISerializable, INotifyPropertyChanged {
	public static IpRule Default { get; } = new(4, new byte[4], new byte[4]);

	public byte[] Ip { get; set; } = Ip;

	public byte[] Mask { get; set; } = Mask;

	public static IpRule Deserialize(IEnumerator<byte> buffer) {
		byte version = buffer.GetAndMoveNext();
		int length = version switch {
			4 => 4,
			6 => 16,
			_ => throw new InvalidOperationException($"Invalid IP version: {version}")
		};
		return new IpRule(version, buffer.GetAndMove(length), buffer.GetAndMove(length));
	}

	public byte[] Serialize() => new[] { Version }.Concat(Ip).Concat(Mask).ToArray();

	public virtual bool Equals(IpRule? other) {
		if (other is null)
			return false;
		return Version == other.Version && Ip.SequenceEqual(other.Ip) && Mask.SequenceEqual(other.Mask);
	}

	public override int GetHashCode() => HashCode.Combine(Version, Ip, Mask);

	public event PropertyChangedEventHandler? PropertyChanged;

	[NotifyPropertyChangedInvocator]
	protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public record PortRule(ushort StartPort, ushort EndPort) : ISerializable, INotifyPropertyChanged {
	public PortRule(ushort port) : this(port, port) { }

	public static PortRule Default { get; } = new(0, 65535);

	public ushort StartPort { get; set; } = StartPort;

	public ushort EndPort { get; set; } = EndPort;

	public static PortRule Deserialize(IEnumerator<byte> buffer) =>
		new(BitConverter.ToUInt16(buffer.GetAndMove(2)), BitConverter.ToUInt16(buffer.GetAndMove(2)));

	public byte[] Serialize() => BitConverter.GetBytes(StartPort).Concat(BitConverter.GetBytes(EndPort)).ToArray();

	public event PropertyChangedEventHandler? PropertyChanged;

	[NotifyPropertyChangedInvocator]
	protected virtual void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

public interface ISerializable {
	public byte[] Serialize();
}
