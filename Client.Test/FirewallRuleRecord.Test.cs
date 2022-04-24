using System.Linq;
using NUnit.Framework;
using TrueMogician.Extensions.Enumerator;

namespace Client.Test {
	public class FirewallRuleRecordTests {
		[TestCaseSource(typeof(FirewallRuleProvider), nameof(FirewallRuleProvider.FirewallRules))]
		public void SerializationTest(FirewallRule rule) {
			var record = new FirewallRuleRecord(rule);
			byte[] bytes = record.Serialize();
			Assert.AreEqual(record, FirewallRuleRecord.Deserialize(bytes.AsEnumerable().GetEnumerator().Move()));
		}
	}
}