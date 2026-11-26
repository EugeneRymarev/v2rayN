namespace ServiceLib.Tests.Handler;

public class RoutingExchangeHandlerTests
{
    private static RoutingItem CreateRouting()
    {
        var rules = new List<RulesItem>
        {
            new() { Id = "rule-1", OutboundTag = "direct", Domain = ["geosite:ru"], Remarks = "Россия" },
            new() { Id = "rule-2", OutboundTag = "proxy", Port = "0-65535" },
        };
        return new RoutingItem
        {
            Id = "routing-1",
            Remarks = "Мой набор",
            RuleSet = JsonUtils.Serialize(rules, false),
            RuleNum = rules.Count,
            DomainStrategy = "IPIfNonMatch",
            IsActive = true,
            Locked = true,
            Sort = 7,
        };
    }

    [Test]
    public async Task Export_WritesIndentedReadableJsonWithoutIds()
    {
        var json = RoutingExchangeHandler.Export([CreateRouting()]);

        await json.Contains(Environment.NewLine).Should().BeTrue();
        await json.Contains("Мой набор").Should().BeTrue();
        await json.Contains("Россия").Should().BeTrue();
        await json.Contains("rule-1").Should().BeFalse();
        await json.Contains("routing-1").Should().BeFalse();

        var arr = JsonUtils.ParseJson(json)!.AsArray();
        await arr.Count.Should().BeEqualTo(1);
        await arr[0]!["rules"]!.AsArray().Count.Should().BeEqualTo(2);
        await arr[0]!["domainStrategy"]!.GetValue<string>().Should().BeEqualTo("IPIfNonMatch");
    }

    [Test]
    public async Task Import_RoundTripsExportedRuleSets()
    {
        var json = RoutingExchangeHandler.Export([CreateRouting()]);

        var items = RoutingExchangeHandler.Import(json, "Imported")!;

        await items.Count.Should().BeEqualTo(1);
        var item = items[0];
        await item.Remarks.Should().BeEqualTo("Мой набор");
        await item.Id.IsNullOrEmpty().Should().BeFalse();
        await item.Id.Should().IsNotEqualTo("routing-1");
        await item.IsActive.Should().BeFalse();
        await item.Locked.Should().BeFalse();
        await item.RuleNum.Should().BeEqualTo(2);
        await item.DomainStrategy.Should().BeEqualTo("IPIfNonMatch");

        var rules = JsonUtils.Deserialize<List<RulesItem>>(item.RuleSet)!;
        await rules.Count.Should().BeEqualTo(2);
        await rules[0].OutboundTag.Should().BeEqualTo("direct");
        await rules[0].Domain![0].Should().BeEqualTo("geosite:ru");
        await rules.All(t => !t.Id.IsNullOrEmpty()).Should().BeTrue();
    }

    [Test]
    public async Task Import_AcceptsSingleRuleSetObject()
    {
        const string json = """{ "remarks": "One", "rules": [ { "outboundTag": "block", "domain": ["example.com"] } ] }""";

        var items = RoutingExchangeHandler.Import(json, "Imported")!;

        await items.Count.Should().BeEqualTo(1);
        await items[0].Remarks.Should().BeEqualTo("One");
        await items[0].RuleNum.Should().BeEqualTo(1);
    }

    [Test]
    public async Task Import_PlainRulesArrayBecomesOneRuleSetWithFallbackName()
    {
        const string json = """[ { "outboundTag": "direct", "ip": ["geoip:private"] }, { "outboundTag": "proxy", "port": "0-65535" } ]""";

        var items = RoutingExchangeHandler.Import(json, "Imported")!;

        await items.Count.Should().BeEqualTo(1);
        await items[0].Remarks.Should().BeEqualTo("Imported");
        await items[0].RuleNum.Should().BeEqualTo(2);
    }

    [Test]
    [Arguments("")]
    [Arguments("not json")]
    [Arguments("[]")]
    [Arguments("42")]
    [Arguments("""{ "remarks": "no rules" }""")]
    public async Task Import_ReturnsNullForUnrecognisedText(string json)
    {
        await RoutingExchangeHandler.Import(json, "Imported").Should().BeNull();
    }
}
