namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService
{
    private static readonly HashSet<string> _nonProxyProtocols = ["freedom", "blackhole", "dns", "loopback"];

    private void ApplyWarpTransport()
    {
        var account = _config.WarpItem;
        if (!WarpService.IsEnabled(account))
        {
            return;
        }

        var targets = _coreConfig.outbounds
            .Where(o => o.tag != WarpService.TransportTag
                        && !_nonProxyProtocols.Contains(o.protocol)
                        && (o.streamSettings?.sockopt?.dialerProxy.IsNullOrEmpty() ?? true)
                        && WarpService.ShouldDialThroughWarp(account, GetOutboundServerAddress(o)))
            .ToList();
        var routeIPv6 = WarpService.ShouldRouteIPv6(account, context.HasGlobalIPv6Address);
        if (targets.Count == 0 && !routeIPv6)
        {
            return;
        }

        var warpNode = WarpService.CreateTransportNode(account!);
        var warpOutbound = new CoreConfigV2rayService(context with { Node = warpNode })
            .BuildProxyOutbound(WarpService.TransportTag);
        foreach (var outbound in targets)
        {
            FillDialerProxy(outbound, WarpService.TransportTag);
        }
        _coreConfig.outbounds.Add(warpOutbound);
    }

    private bool UsesWarpIPv6Inbound()
    {
        return !context.IsTunEnabled
               && _config.TunModeItem.EnableTun
               && _config.TunModeItem.EnableLegacyProtect
               && WarpService.ShouldRouteIPv6(_config.WarpItem, context.HasGlobalIPv6Address);
    }

    // Only traffic from TUN is matched: its destination is always an IP,
    // a domain from a proxy client would be resolved just to check the rule.
    private void GenWarpIPv6Rules()
    {
        if (_coreConfig.routing?.rules == null
            || !WarpService.ShouldRouteIPv6(_config.WarpItem, context.HasGlobalIPv6Address))
        {
            return;
        }
        var outboundTag = WarpService.GetIPv6OutboundTag(_config.WarpItem);
        if (UsesWarpIPv6Inbound())
        {
            _coreConfig.routing.rules.Add(new()
            {
                inboundTag = [WarpService.IPv6InboundTag],
                outboundTag = outboundTag,
            });
        }
        if (context.IsTunEnabled)
        {
            _coreConfig.routing.rules.Add(new()
            {
                inboundTag = ["tun"],
                ip = [WarpService.GlobalIPv6Prefix],
                outboundTag = outboundTag,
            });
        }
    }

    internal static string? GetOutboundServerAddress(Outbounds4Ray outbound)
    {
        var settings = outbound.settings;
        if (settings == null)
        {
            return null;
        }
        if (settings.address is JsonValue value && value.TryGetValue(out string? address))
        {
            return address;
        }
        if (settings.address is JsonArray array && array.FirstOrDefault() is JsonValue first
            && first.TryGetValue(out string? firstAddress)
            && outbound.protocol != "wireguard")
        {
            return firstAddress;
        }
        var endpoint = settings.peers?.FirstOrDefault()?.endpoint;
        if (endpoint.IsNullOrEmpty())
        {
            return null;
        }
        if (endpoint!.StartsWith('['))
        {
            var close = endpoint.IndexOf(']');
            return close > 1 ? endpoint[1..close] : null;
        }
        var idx = endpoint.LastIndexOf(':');
        return idx > 0 ? endpoint[..idx] : endpoint;
    }
}
