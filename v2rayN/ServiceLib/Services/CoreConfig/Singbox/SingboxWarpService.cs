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
        if (targets.Count == 0)
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

    internal static string? GetServerAddress(BaseServer4Sbox server)
    {
        if (server.server.IsNotEmpty())
        {
            return server.server;
        }
        return server is Endpoints4Sbox endpoint ? endpoint.peers?.FirstOrDefault()?.address : null;
    }
}
