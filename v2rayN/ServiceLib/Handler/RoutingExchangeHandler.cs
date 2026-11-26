namespace ServiceLib.Handler;

/// <summary>
/// Converts routing rule sets to and from human-readable JSON for the clipboard.
/// </summary>
public static class RoutingExchangeHandler
{
    /// <summary>
    /// Builds indented JSON describing the given routing rule sets (with their rules).
    /// Internal ids are stripped so the text can be shared and imported elsewhere.
    /// </summary>
    public static string Export(IEnumerable<RoutingItem> routingItems)
    {
        var lst = routingItems.Select(ToExchangeItem).ToList();
        return JsonUtils.SerializeCamelCase(lst);
    }

    /// <summary>
    /// Parses clipboard text into new routing rule sets.
    /// Accepts an array of rule sets, a single rule set object,
    /// or a plain array of rules (which becomes one new rule set named <paramref name="fallbackRemarks"/>).
    /// Returns null when the text is not recognised.
    /// </summary>
    public static List<RoutingItem>? Import(string? strData, string fallbackRemarks)
    {
        var node = JsonUtils.ParseJson(strData);
        List<RoutingExchangeItem>? items = null;

        switch (node)
        {
            case JsonObject obj:
                var single = JsonUtils.Deserialize<RoutingExchangeItem>(obj.ToJsonString());
                if (single != null)
                {
                    items = [single];
                }
                break;

            case JsonArray arr:
                if (arr.Count == 0)
                {
                    return null;
                }
                if (arr.All(IsRoutingSetNode))
                {
                    items = JsonUtils.Deserialize<List<RoutingExchangeItem>>(arr.ToJsonString());
                }
                else
                {
                    var rules = JsonUtils.Deserialize<List<RulesItem>>(arr.ToJsonString());
                    if (rules != null)
                    {
                        items = [new RoutingExchangeItem { Remarks = fallbackRemarks, Rules = rules }];
                    }
                }
                break;
        }

        if (items == null || items.Count == 0 || items.Any(t => t?.Rules == null))
        {
            return null;
        }

        return items.Select(t => FromExchangeItem(t, fallbackRemarks)).ToList();
    }

    private static bool IsRoutingSetNode(JsonNode? node)
    {
        return node is JsonObject obj
            && obj.Any(p => string.Equals(p.Key, nameof(RoutingExchangeItem.Rules), StringComparison.OrdinalIgnoreCase));
    }

    private static RoutingExchangeItem ToExchangeItem(RoutingItem item)
    {
        var rules = JsonUtils.Deserialize<List<RulesItem>>(item.RuleSet) ?? [];
        foreach (var rule in rules)
        {
            rule.Id = null!;
        }
        return new RoutingExchangeItem
        {
            Remarks = item.Remarks,
            Url = item.Url.IsNullOrEmpty() ? null : item.Url,
            CustomIcon = item.CustomIcon.IsNullOrEmpty() ? null : item.CustomIcon,
            CustomRulesetPath4Singbox = item.CustomRulesetPath4Singbox.IsNullOrEmpty() ? null : item.CustomRulesetPath4Singbox,
            DomainStrategy = item.DomainStrategy.IsNullOrEmpty() ? null : item.DomainStrategy,
            DomainStrategy4Singbox = item.DomainStrategy4Singbox.IsNullOrEmpty() ? null : item.DomainStrategy4Singbox,
            Rules = rules,
        };
    }

    private static RoutingItem FromExchangeItem(RoutingExchangeItem item, string fallbackRemarks)
    {
        var rules = item.Rules ?? [];
        foreach (var rule in rules)
        {
            rule.Id = Utils.GetGuid(false);
        }
        return new RoutingItem
        {
            Id = Utils.GetGuid(false),
            Remarks = item.Remarks.IsNullOrEmpty() ? fallbackRemarks : item.Remarks!,
            Url = item.Url ?? string.Empty,
            CustomIcon = item.CustomIcon ?? string.Empty,
            CustomRulesetPath4Singbox = item.CustomRulesetPath4Singbox ?? string.Empty,
            DomainStrategy = item.DomainStrategy ?? string.Empty,
            DomainStrategy4Singbox = item.DomainStrategy4Singbox ?? string.Empty,
            Enabled = true,
            Locked = false,
            IsActive = false,
            RuleNum = rules.Count,
            RuleSet = JsonUtils.Serialize(rules, false),
        };
    }
}
