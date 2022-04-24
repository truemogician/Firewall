namespace Client.Test;

public static class FirewallRuleProvider {
	public static FirewallRule[] FirewallRules { get; } = {
		new("protocol") { Protocol = Protocol.ARP },
		new("ip") { SourceIpRule = new IpRule(4, new byte[] { 127, 0, 0, 1 }, new byte[] { 255, 255, 255, 0 }) },
		new("port") { DestinationPortRule = new PortRule(6379) },
		new("all") {
			Protocol = Protocol.UDP,
			SourceIpRule = new IpRule(4, new byte[] { 192, 168, 0, 1 }, new byte[] { 255, 255, 0, 0 }),
			DestinationPortRule = new PortRule(1, 100)
		}
	};
}