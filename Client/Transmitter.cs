using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using TrueMogician.Extensions.Enumerator;
using static Client.KernelLibrary;

namespace Client;

public static class Transmitter {
	public static int OutBufferLength { get; set; } = 4 << 10;

	public static List<FirewallRuleRecord> Get() {
		byte[] result = SyncBuffer(new byte[] { 0 });
		return new List<FirewallRuleRecord>(DeserializeList(result, FirewallRuleRecord.Deserialize));
	}

	public static bool Post(ICollection<FirewallRuleRecord> records) {
		byte[] result = SyncBuffer(new byte[] { 1 }.Concat(SerializeList(records)).ToArray());
		return result[0] != 0;
	}

	public static byte[] SyncBuffer(byte[] input) {
		var device = CreateFile(
			@"\\.\NDISLWF",
			FileAccess.GenericRead | FileAccess.GenericWrite,
			FileShare.None,
			IntPtr.Zero,
			CreationDisposition.CreateAlways,
			FileAttributes.Normal,
			IntPtr.Zero
		);
		if (device.IsInvalid)
			throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;
		var inBuffer = Marshal.AllocHGlobal(input.Length);
		Marshal.Copy(input, 0, inBuffer, input.Length);
		var outBuffer = Marshal.AllocHGlobal(OutBufferLength);
		bool success = DeviceIoControl(
			device,
			GetIoControlCode(40000, 0x902, 0, 0),
			inBuffer,
			input.Length,
			outBuffer,
			OutBufferLength,
			out int lengthReturned,
			IntPtr.Zero
		);
		Marshal.FreeHGlobal(inBuffer);
		if (!success) {
			Marshal.FreeHGlobal(outBuffer);
			throw Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error())!;
		}
		var result = new byte[lengthReturned];
		Marshal.Copy(outBuffer, result, 0, lengthReturned);
		Marshal.FreeHGlobal(outBuffer);
		device.Close();
		return result;
	}

	internal static IEnumerable<byte> SerializeList<T>(ICollection<T> list) where T : ISerializable =>
		list.Aggregate(BitConverter.GetBytes((long)list.Count).AsEnumerable(), (result, item) => result.Concat(item.Serialize()));

	internal static T[] DeserializeList<T>(byte[] buffer, Func<IEnumerator<byte>, T> deserializer) {
		using var enumerator = buffer.AsEnumerable().GetEnumerator();
		enumerator.MoveNext();
		var length = BitConverter.ToUInt64(enumerator.GetAndMove(8));
		var result = new T[length];
		for (uint i = 0; i < length; i++)
			result[i] = deserializer(enumerator);
		return result;
	}

	private static uint GetIoControlCode(uint deviceType, uint function, uint method, uint access) =>
		(deviceType << 16) | (access << 14) | (function << 2) | method;
}