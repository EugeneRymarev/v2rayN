namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigV2rayService
{
    private static readonly HashSet<string> _nonProxyProtocols = ["freedom", "blackhole", "dns", "loopback"];

    /// <summary>
    /// Makes the core reach proxy servers through Cloudflare WARP (see <see cref="WarpService" />):
    /// adds a WireGuard outbound for WARP and points the first hop of every matching proxy
    /// outbound (one without a dialerProxy yet) at it.
    /// </summary>
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

    /// <summary>
    /// True when the sing-box TUN core runs in front of this config: it hands IPv6 over to the
    /// <see cref="WarpService.IPv6InboundTag" /> inbound.
    /// </summary>
    private bool UsesWarpIPv6Inbound()
    {
        return !context.IsTunEnabled
               && _config.TunModeItem.EnableTun
               && _config.TunModeItem.EnableLegacyProtect
               && WarpService.ShouldRouteIPv6(_config.WarpItem, context.HasGlobalIPv6Address);
    }

    /// <summary>
    /// Sends IPv6 that came from TUN through WARP: the host has no IPv6, so the routing rules
    /// could only send it directly, where it fails. Only traffic from TUN is matched, because its
    /// destination is always an address; a domain from a proxy client would be resolved instead.
    /// </summary>
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
