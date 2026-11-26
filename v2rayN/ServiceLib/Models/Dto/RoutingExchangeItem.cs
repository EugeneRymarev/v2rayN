namespace ServiceLib.Models.Dto;

/// <summary>
/// Portable representation of a routing rule set, used for clipboard import/export.
/// </summary>
public class RoutingExchangeItem
{
    public string? Remarks { get; set; }
    public string? Url { get; set; }
    public string? CustomIcon { get; set; }
    public string? CustomRulesetPath4Singbox { get; set; }
    public string? DomainStrategy { get; set; }
    public string? DomainStrategy4Singbox { get; set; }
    public List<RulesItem>? Rules { get; set; }
}
