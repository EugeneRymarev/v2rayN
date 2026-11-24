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
        if (targets.Count == 0)
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
