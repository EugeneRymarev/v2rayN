namespace ServiceLib.Services.CoreConfig;

public partial class CoreConfigSingboxService
{
    private static readonly HashSet<string> _nonProxyTypes = ["direct", "block", "dns", "selector", "urltest"];

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
        // xray behind the TUN core has its own WARP, two connections with one key break each other
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

    private bool IsXrayTunFrontend()
    {
        return context.IsTunEnabled
               && _node.ConfigType == EConfigType.SOCKS
               && _node.Address == Global.Loopback
               && _node.Port == AppManager.Instance.GetLocalPort(EInboundProtocol.socks);
    }

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
