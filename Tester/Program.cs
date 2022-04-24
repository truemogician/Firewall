using Client;

try {
	if (args.Length == 0 || args[0].ToLower() == "get") {
		var content = Transmitter.Get();
		Console.WriteLine($"{content.Count} rules fetched:");
		foreach (var rule in content)
			Console.WriteLine(rule.ToString());
	}
	else if (args[0].ToLower() == "post") {
		var rules = new List<FirewallRuleRecord> {
			new(new FirewallRule("protocol") { Protocol = Protocol.ARP }),
			new(new FirewallRule("ip") { SourceIpRule = new IpRule(4, new byte[] { 127, 0, 0, 1 }, new byte[] { 255, 255, 255, 0 }) }),
			new(new FirewallRule("port") { DestinationPortRule = new PortRule(6379) })
		};
		Console.WriteLine(Transmitter.Post(rules) ? $"{rules.Count} rules posted successfully" : "Posting failed");
	}
}
catch (Exception ex) {
	Console.Error.WriteLine($"{ex.GetType().Name}: {ex.Message}");
	Console.Error.WriteLine(ex.StackTrace);
}