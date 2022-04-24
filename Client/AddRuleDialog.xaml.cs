using System;
using System.Globalization;
using System.Linq;
using System.Windows;
using System.Windows.Input;

namespace Client {
	/// <summary>
	///     Interaction logic for AddRuleDialog.xaml
	/// </summary>
	public partial class AddRuleDialog {
		private bool _canceled;

		public AddRuleDialog(FirewallRule? initialRule = null) {
			FirewallRule = initialRule ?? new FirewallRule("");
			Mapper = new FirewallRuleMapper(FirewallRule);
			InitializeComponent();
		}

		public static Direction[] DirectionValues { get; } = Enum.GetValues<Direction>();

		public static Protocol[] ProtocolValues { get; } = Enum.GetValues<Protocol>();

		public FirewallRule FirewallRule { get; }

		public FirewallRuleMapper Mapper { get; }

		public static FirewallRule? ShowDialog(FirewallRule? initialRule = null) {
			var dialog = new AddRuleDialog(initialRule);
			(dialog as Window).ShowDialog();
			return dialog._canceled ? null : dialog.FirewallRule;
		}

		private void PortTextBoxPreviewTextInput(object sender, TextCompositionEventArgs e) =>
			e.Handled = !ushort.TryParse(e.Text, out _);

		private void ConfirmButtonClick(object sender, RoutedEventArgs e) => Close();

		private void CancelButtonClick(object sender, RoutedEventArgs e) {
			_canceled = true;
			Close();
		}
	}

	public class FirewallRuleMapper {
		private readonly FirewallRule _rule;

		public FirewallRuleMapper(FirewallRule rule) => _rule = rule;

		public string SourceMac {
			get => StringifyMac(_rule.SourceMacRule.Mac);
			set => _rule.SourceMacRule.Mac = ParseMac(value) ?? _rule.SourceMacRule.Mac;
		}

		public string SourceMacMask {
			get => StringifyMac(_rule.SourceMacRule.Mask);
			set => _rule.SourceMacRule.Mask = ParseMac(value) ?? _rule.SourceMacRule.Mask;
		}

		public string DestinationMac {
			get => StringifyMac(_rule.DestinationMacRule.Mac);
			set => _rule.DestinationMacRule.Mac = ParseMac(value) ?? _rule.DestinationMacRule.Mac;
		}

		public string DestinationMacMask {
			get => StringifyMac(_rule.DestinationMacRule.Mask);
			set => _rule.DestinationMacRule.Mask = ParseMac(value) ?? _rule.DestinationMacRule.Mask;
		}

		public string SourceIp {
			get => StringifyIp(_rule.SourceIpRule.Ip);
			set => _rule.SourceIpRule.Ip = ParseIp(value) ?? _rule.SourceIpRule.Ip;
		}

		public string SourceIpMask {
			get => StringifyIp(_rule.SourceIpRule.Mask);
			set => _rule.SourceIpRule.Mask = ParseIp(value) ?? _rule.SourceIpRule.Mask;
		}

		public string DestinationIp {
			get => StringifyIp(_rule.DestinationIpRule.Ip);
			set => _rule.DestinationIpRule.Ip = ParseIp(value) ?? _rule.DestinationIpRule.Ip;
		}

		public string DestinationIpMask {
			get => StringifyIp(_rule.DestinationIpRule.Mask);
			set => _rule.DestinationIpRule.Mask = ParseIp(value) ?? _rule.DestinationIpRule.Mask;
		}

		public string SourceStartPort {
			get => _rule.SourcePortRule.StartPort.ToString();
			set => _rule.SourcePortRule.StartPort = ushort.Parse(value);
		}

		public string SourceEndPort {
			get => _rule.SourcePortRule.EndPort.ToString();
			set => _rule.SourcePortRule.EndPort = ushort.Parse(value);
		}

		public string DestinationStartPort {
			get => _rule.DestinationPortRule.StartPort.ToString();
			set => _rule.DestinationPortRule.StartPort = ushort.Parse(value);
		}

		public string DestinationEndPort {
			get => _rule.DestinationPortRule.EndPort.ToString();
			set => _rule.DestinationPortRule.EndPort = ushort.Parse(value);
		}

		private static string StringifyMac(byte[] mac) => string.Join(':', mac.Select(p => p.ToString("X2")));

		private static byte[]? ParseMac(string mac) {
			string[] components = mac.Split(':');
			return components.Length != 6 ? null : components.Select(c => byte.Parse(c, NumberStyles.HexNumber)).ToArray();
		}

		private static string StringifyIp(byte[] ip) => ip.Length switch {
			4 => string.Join('.', ip.Select(b => b.ToString())),
			6 => throw new NotImplementedException(),
			_ => throw new ArgumentException($"Wrong number of IP components: {ip.Length}")
		};

		private static byte[]? ParseIp(string ip) {
			if (ip.Contains('.')) {
				string[] components = ip.Split('.');
				return components.Length != 4 ? null : components.Select(byte.Parse).ToArray();
			}
			else if (ip.Contains(':'))
				throw new NotImplementedException();
			return null;
		}
	}
}