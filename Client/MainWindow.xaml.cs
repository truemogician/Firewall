using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Timers;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace Client;

/// <summary>
///     Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow {
	public static TimeSpan UpdateInterval { get; } = TimeSpan.FromSeconds(5);

	public MainWindow() {
		InitializeComponent();
		var source = new BitmapImage();
		source.BeginInit();
		source.StreamSource = new MemoryStream(Resource.Icon);
		source.EndInit();
		Icon = source;
		FirewallRules.AddingNew += (_, args) => {
			if (args.NewObject is FirewallRuleRecord record)
				record.EnabledChanged += (_, _) => Transmitter.Post(FirewallRules);
		};
		try {
			var records = Transmitter.Get();
			foreach (var record in records)
				FirewallRules.Add(record);
			FirewallRule.NextId = records.Select(r => r.Rule.Id).Max() + 1;
		}
		catch (Exception ex) {
			MessageBox.Show($"从驱动读取数据异常，可能是因为防火墙未开启：{ex.Message}");
			Close();
			return;
		}
		var timer = new Timer(UpdateInterval.TotalMilliseconds);
		timer.Elapsed += (_, _) => {
			var hitCount = Transmitter.Get().ToDictionary(r => r.Rule.Id, r => r.HitCount);
			foreach (var record in FirewallRules.Where(record => hitCount.ContainsKey(record.Rule.Id)))
				record.HitCount = hitCount[record.Rule.Id];
		};
		timer.Start();
	}

	public BindingList<FirewallRuleRecord> FirewallRules { get; } = new();

	private void AddButtonClick(object sender, RoutedEventArgs e) {
		var @new = AddRuleDialog.ShowDialog();
		if (@new is not null) {
			FirewallRules.Add(new FirewallRuleRecord(@new));
			Transmitter.Post(FirewallRules);
		}
	}

	private void ModifyButtonClick(object sender, RoutedEventArgs e) {
		int index = (GetDataGridRow(sender) ?? throw new InvalidOperationException()).GetIndex();
		var @new = AddRuleDialog.ShowDialog(FirewallRules[index].Rule);
		if (@new is not null) {
			var record = FirewallRules[index];
			record.Rule = @new;
			record.HitCount = 0;
			record.Present = true;
			Transmitter.Post(FirewallRules);
		}
	}

	private void DeleteButtonClick(object sender, RoutedEventArgs e) {
		var row = GetDataGridRow(sender) ?? throw new InvalidOperationException();
		int index = row.GetIndex();
		if (index == -1)
			throw new InvalidOperationException();
		FirewallRules.RemoveAt(index);
		Transmitter.Post(FirewallRules);
	}

	private static DataGridRow? GetDataGridRow(object sender) {
		var result = sender as Visual;
		for (; result is not null; result = VisualTreeHelper.GetParent(result) as Visual)
			if (result is DataGridRow row)
				return row;
		return null;
	}
}