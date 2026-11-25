namespace ServiceLib.Enums;

/// <summary>
/// When to reach proxy servers through Cloudflare WARP.
/// </summary>
public enum EWarpMode
{
    Off = 0,

    /// <summary>Only servers whose address is an IPv6 address.</summary>
    Ipv6Only = 1,

    /// <summary>Every proxy server.</summary>
    All = 2,

    /// <summary>No proxy server: WARP itself is the exit, like the official WARP client.</summary>
    WarpOnly = 3,
}
