namespace ServiceLib.Models.Dto;

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
