namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigSingboxService
{
    private static readonly HashSet<string> _nonProxyTypes = ["direct", "block", "dns", "selector", "urltest"];

    /// <summary>
    /// Makes the core reach proxy servers through Cloudflare WARP (see <see cref="WarpService" />):
    /// adds a WireGuard endpoint for WARP and sets it as the detour of the first hop of every
    /// matching proxy outbound/endpoint.
    /// </summary>
    private void ApplyWarpTransport()
    {
        var account = _config.WarpItem;
        if (!WarpService.IsEnabled(account))
        {
            return;
        }

        IEnumerable<BaseServer4Sbox> servers = _coreConfig.outbounds;
        if (_coreConfig.endpoints != null)
        {
            servers = servers.Concat(_coreConfig.endpoints);
        }
        var targets = servers
            .Where(s => s.tag != WarpService.TransportTag
                        && !_nonProxyTypes.Contains(s.type)
                        && s.detour.IsNullOrEmpty()
                        && WarpService.ShouldDialThroughWarp(account, GetServerAddress(s)))
            .ToList();
        // The xray core behind the TUN core has its own WARP; a second connection with the same
        // key would knock the first one out.
        var routeIPv6 = WarpService.ShouldRouteIPv6(account, context.HasGlobalIPv6Address) && !IsXrayTunFrontend();
        if (targets.Count == 0 && !routeIPv6)
        {
            return;
        }

        var warpNode = WarpService.CreateTransportNode(account!);
        var warpServer = new CoreConfigSingboxService(context with { Node = warpNode })
            .BuildProxyOutbound(WarpService.TransportTag);
        foreach (var server in targets)
        {
            server.detour = WarpService.TransportTag;
        }
        FillRangeProxy([warpServer], _coreConfig, false);
    }

    /// <summary>
    /// True when this config only runs TUN and hands traffic to the xray core on the local SOCKS port.
    /// </summary>
    private bool IsXrayTunFrontend()
    {
        return context.IsTunEnabled
               && _node.ConfigType == EConfigType.SOCKS
               && _node.Address == Global.Loopback
               && _node.Port == AppManager.Instance.GetLocalPort(EInboundProtocol.socks);
    }

    /// <summary>
    /// Sends IPv6 through WARP: the host has no IPv6, so the routing rules could only send it
    /// directly, where it fails. When xray runs behind this TUN core, IPv6 goes to its dedicated
    /// inbound and xray sends it through WARP.
    /// </summary>
    private void GenWarpIPv6Rule()
    {
        if (!WarpService.ShouldRouteIPv6(_config.WarpItem, context.HasGlobalIPv6Address))
        {
            return;
        }
        string outbound;
        if (IsXrayTunFrontend())
        {
            outbound = WarpService.IPv6OutboundTag;
            _coreConfig.outbounds.Add(new Outbound4Sbox
            {
                type = "socks",
                tag = outbound,
                server = Global.Loopback,
                server_port = AppManager.Instance.WarpIPv6Port,
                version = "5",
            });
        }
        else
        {
            outbound = WarpService.GetIPv6OutboundTag(_config.WarpItem);
        }
        _coreConfig.route.rules.Add(new()
        {
            ip_cidr = [WarpService.GlobalIPv6Prefix],
            outbound = outbound,
        });
    }

    internal static string? GetServerAddress(BaseServer4Sbox server)
    {
        if (server.server.IsNotEmpty())
        {
            return server.server;
        }
        return server is Endpoints4Sbox endpoint ? endpoint.peers?.FirstOrDefault()?.address : null;
    }
}
