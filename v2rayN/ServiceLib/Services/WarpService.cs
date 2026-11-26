namespace ServiceLib.Services;

/// <summary>
/// Cloudflare WARP as a transport under the user's proxy servers.
/// WARP gives the device an IPv6 address, so when the core dials a proxy server through WARP,
/// servers that only have IPv6 become reachable even if the ISP offers IPv4 only.
/// The WARP account lives in <see cref="Config.WarpItem" />, not in the server list.
/// </summary>
public static class WarpService
{
    private static readonly string _tag = "WarpService";

    public const string RegistrationUrl = "https://api.cloudflareclient.com/v0a2158/reg";
    public const string ClientVersion = "a-6.10-2158";
    public const string UserAgent = "okhttp/3.12.1";

    // The IPv4 endpoint is used on purpose: the whole point is to work on IPv4-only networks,
    // and a literal IP avoids depending on DNS that may be blocked or poisoned.
    public const string DefaultEndpointHost = "162.159.192.1";
    public const int DefaultEndpointPort = 2408;
    public const int DefaultMtu = 1280;

    /// <summary>Outbound tag of the WARP transport in generated core configs.</summary>
    public const string TransportTag = "warp-transport";

    public const string TransportIndexId = "inner-warp-transport";

    /// <summary>All global unicast IPv6 addresses: the public internet without private ranges.</summary>
    public const string GlobalIPv6Prefix = "2000::/3";

    /// <summary>
    /// Tags of the local link between the sing-box TUN core and the xray core: sing-box hands IPv6
    /// over to this xray inbound, and xray sends everything from it through WARP.
    /// </summary>
    public const string IPv6InboundTag = "warp-ipv6-in";

    public const string IPv6OutboundTag = "warp-ipv6";

    #region account

    public static bool HasAccount(WarpItem? item)
    {
        return item != null
               && item.PrivateKey.IsNotEmpty()
               && item.PeerPublicKey.IsNotEmpty()
               && item.EndpointHost.IsNotEmpty()
               && item.EndpointPort > 0;
    }

    public static bool IsEnabled(WarpItem? item)
    {
        return item?.Mode is EWarpMode.Ipv6Only or EWarpMode.All && HasAccount(item);
    }

    /// <summary>
    /// True when WARP itself should be the exit instead of the selected proxy server.
    /// </summary>
    public static bool IsWarpOnly(WarpItem? item)
    {
        return item?.Mode == EWarpMode.WarpOnly && HasAccount(item);
    }

    /// <summary>
    /// The node the core should run: the WARP node in "WARP only" mode, otherwise the selected server.
    /// </summary>
    public static async Task<ProfileItem?> GetNodeToRunAsync(Config config)
    {
        if (IsWarpOnly(config.WarpItem))
        {
            return CreateTransportNode(config.WarpItem!);
        }
        return await ConfigTextHandler.GetDefaultServer();
    }

    /// <summary>
    /// Creates a new WARP device registration with freshly generated keys.
    /// </summary>
    public static async Task<WarpItem?> RegisterAsync(bool useProxy, CancellationToken cancellationToken = default)
    {
        var (privateKey, publicKey) = X25519Utils.GenerateKeyPair();
        var body = BuildRegistrationBody(publicKey, DateTime.UtcNow);

        using var client = HttpClientHelper.Instance.GetHttpClient(useProxy);
        client.Timeout = TimeSpan.FromSeconds(20);
        using var request = new HttpRequestMessage(HttpMethod.Post, RegistrationUrl)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
        request.Headers.TryAddWithoutValidation("CF-Client-Version", ClientVersion);

        using var response = await client.SendAsync(request, cancellationToken);
        var responseText = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            Logging.SaveLog($"{_tag}: registration failed, HTTP {(int)response.StatusCode}: {responseText}");
            return null;
        }

        return ParseRegistrationResponse(responseText, privateKey);
    }

    public static string BuildRegistrationBody(string publicKey, DateTime utcNow)
    {
        var obj = new JsonObject
        {
            ["key"] = publicKey,
            ["install_id"] = string.Empty,
            ["fcm_token"] = string.Empty,
            ["tos"] = utcNow.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", System.Globalization.CultureInfo.InvariantCulture),
            ["model"] = "PC",
            ["serial_number"] = string.Empty,
            ["locale"] = "en_US",
        };
        return obj.ToJsonString();
    }

    /// <summary>
    /// Reads the answer of the registration API.
    /// </summary>
    public static WarpItem? ParseRegistrationResponse(string? json, string privateKey)
    {
        var root = JsonUtils.ParseJson(json ?? string.Empty);
        // Some API versions wrap the payload in "result"
        if (root?["config"] == null && root?["result"] != null)
        {
            root = root["result"];
        }
        var config = root?["config"];
        var peer = config?["peers"]?.AsArray().FirstOrDefault();
        var peerPublicKey = GetString(peer?["public_key"]);
        if (config == null || peerPublicKey.IsNullOrEmpty())
        {
            return null;
        }

        var addresses = config["interface"]?["addresses"];
        var (host, port) = ParseEndpoint(GetString(peer?["endpoint"]?["v4"]));

        return new WarpItem
        {
            PrivateKey = privateKey,
            PeerPublicKey = peerPublicKey,
            AddressV4 = GetString(addresses?["v4"]),
            AddressV6 = GetString(addresses?["v6"]),
            Reserved = ClientIdToReserved(GetString(config["client_id"])),
            EndpointHost = host,
            EndpointPort = port,
            DeviceId = GetString(root?["id"]),
        };
    }

    /// <summary>
    /// Converts the base64 "client_id" into the "a, b, c" reserved bytes string WireGuard cores expect.
    /// </summary>
    public static string? ClientIdToReserved(string? clientId)
    {
        if (clientId.IsNullOrEmpty())
        {
            return null;
        }
        try
        {
            var bytes = Convert.FromBase64String(clientId!);
            if (bytes.Length < 3)
            {
                return null;
            }
            return string.Join(", ", bytes.Take(3));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Registers a new WARP account, picks a working endpoint and stores it in the settings.
    /// First tries a direct connection; if that fails (the API can be blocked) and a proxy core is running,
    /// retries through the local proxy. The current <see cref="WarpItem.Mode" /> is kept.
    /// </summary>
    public static async Task<RetResult> RegisterToConfigAsync(Config config)
    {
        WarpItem? account = null;
        foreach (var useProxy in new[] { false, true })
        {
            try
            {
                account = await RegisterAsync(useProxy);
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"{_tag} (proxy={useProxy})", ex);
            }
            if (account != null)
            {
                break;
            }
        }

        if (account == null)
        {
            return new RetResult(false, ResUI.MsgWarpRegisterFailed);
        }

        // Pick an address that actually answers from this network; keep the default if none does.
        var best = await FindBestEndpointAsync(account, 60);
        if (best != null)
        {
            account.EndpointHost = best.Host;
            account.EndpointPort = best.Port;
        }

        account.Mode = config.WarpItem?.Mode ?? EWarpMode.Off;
        config.WarpItem = account;
        if (await ConfigTextHandler.SaveConfig() != 0)
        {
            return new RetResult(false, ResUI.OperationFailed);
        }

        var msg = best != null
            ? $"{ResUI.MsgWarpAccountCreated}. {string.Format(ResUI.MsgWarpEndpointSelected, best.Host, best.Port, best.RttMs)}"
            : $"{ResUI.MsgWarpAccountCreated}. {ResUI.MsgWarpEndpointNotFound}";
        return new RetResult(true, msg);
    }

    /// <summary>
    /// Scans WARP addresses with the account's keys and returns the fastest one that answered.
    /// </summary>
    public static async Task<WarpEndpointResult?> FindBestEndpointAsync(WarpItem account, int candidateCount = 100)
    {
        if (account.PrivateKey.IsNullOrEmpty() || account.PeerPublicKey.IsNullOrEmpty())
        {
            return null;
        }
        try
        {
            var results = await WarpEndpointScanner.ScanAsync(account.PrivateKey!, account.PeerPublicKey!, candidateCount);
            return results.FirstOrDefault();
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            return null;
        }
    }

    /// <summary>
    /// Re-picks the best address for the stored WARP account and saves it.
    /// </summary>
    public static async Task<RetResult> SelectBestEndpointAsync(Config config)
    {
        var account = config.WarpItem;
        if (account == null || !HasAccount(account))
        {
            return new RetResult(false, ResUI.MsgWarpNoAccount);
        }
        var best = await FindBestEndpointAsync(account);
        if (best == null)
        {
            return new RetResult(false, ResUI.MsgWarpEndpointNotFound);
        }
        account.EndpointHost = best.Host;
        account.EndpointPort = best.Port;
        if (await ConfigTextHandler.SaveConfig() != 0)
        {
            return new RetResult(false, ResUI.OperationFailed);
        }
        return new RetResult(true, string.Format(ResUI.MsgWarpEndpointSelected, best.Host, best.Port, best.RttMs));
    }

    #endregion account

    #region transport

    /// <summary>
    /// The in-memory WireGuard node that the cores use as the WARP transport.
    /// </summary>
    public static ProfileItem CreateTransportNode(WarpItem account)
    {
        var addresses = new List<string>();
        if (account.AddressV4.IsNotEmpty())
        {
            addresses.Add($"{account.AddressV4}/32");
        }
        if (account.AddressV6.IsNotEmpty())
        {
            addresses.Add($"{account.AddressV6}/128");
        }

        var item = new ProfileItem
        {
            IndexId = TransportIndexId,
            ConfigType = EConfigType.WireGuard,
            CoreType = ECoreType.Xray,
            Remarks = "WARP",
            Address = account.EndpointHost ?? DefaultEndpointHost,
            Port = account.EndpointPort > 0 ? account.EndpointPort : DefaultEndpointPort,
            Password = account.PrivateKey ?? string.Empty,
            Subid = string.Empty,
            IsSub = false,
        };
        item.SetProtocolExtra(item.GetProtocolExtra() with
        {
            WgPublicKey = account.PeerPublicKey,
            WgInterfaceAddress = string.Join(", ", addresses),
            WgReserved = account.Reserved,
            WgMtu = DefaultMtu,
        });
        return item;
    }

    /// <summary>
    /// Addresses that must stay outside TUN: the WARP endpoint itself. Without this the core's own
    /// WireGuard packets are captured by TUN and sent back into the core, so nothing gets through.
    /// </summary>
    public static List<string> GetTunExcludeAddresses(WarpItem? account)
    {
        if (account == null || account.Mode == EWarpMode.Off || !HasAccount(account))
        {
            return [];
        }
        return Utils.IsIpv4(account.EndpointHost) ? [$"{account.EndpointHost}/32"] : [];
    }

    /// <summary>
    /// Whether IPv6 traffic that the routing rules would send directly must go through WARP instead.
    /// A host without its own IPv6 cannot send it anywhere else, so an app that connects to an
    /// IPv6 address (for example a Telegram proxy) would fail.
    /// </summary>
    public static bool ShouldRouteIPv6(WarpItem? account, bool hasGlobalIPv6Address)
    {
        return !hasGlobalIPv6Address && (IsEnabled(account) || IsWarpOnly(account));
    }

    /// <summary>
    /// Outbound that carries IPv6 when <see cref="ShouldRouteIPv6" /> is true. In "everything
    /// through WARP" mode the main proxy is WARP itself.
    /// </summary>
    public static string GetIPv6OutboundTag(WarpItem? account)
    {
        return IsWarpOnly(account) ? Global.ProxyTag : TransportTag;
    }

    /// <summary>
    /// Whether a proxy server at <paramref name="serverAddress" /> should be dialed through WARP.
    /// </summary>
    public static bool ShouldDialThroughWarp(WarpItem? account, string? serverAddress)
    {
        if (!IsEnabled(account) || serverAddress.IsNullOrEmpty())
        {
            return false;
        }
        var host = serverAddress!.Trim().Trim('[', ']');
        // never route WARP through itself
        if (host == account!.EndpointHost)
        {
            return false;
        }
        return account.Mode switch
        {
            EWarpMode.All => true,
            EWarpMode.Ipv6Only => Utils.IsIpv6(host),
            _ => false,
        };
    }

    #endregion transport

    private static (string Host, int Port) ParseEndpoint(string? endpoint)
    {
        // The API answers with e.g. "162.159.192.1:0"; port 0 means "pick any WARP port".
        if (endpoint.IsNullOrEmpty())
        {
            return (DefaultEndpointHost, DefaultEndpointPort);
        }
        var idx = endpoint!.LastIndexOf(':');
        var host = idx > 0 ? endpoint[..idx] : endpoint;
        var port = idx > 0 && int.TryParse(endpoint[(idx + 1)..], out var p) && p is > 0 and <= 65535
            ? p
            : DefaultEndpointPort;
        if (!Utils.IsIpv4(host))
        {
            host = DefaultEndpointHost;
        }
        return (host, port);
    }

    private static string? GetString(JsonNode? node)
    {
        try
        {
            return node?.GetValue<string>().NullIfEmpty();
        }
        catch (InvalidOperationException)
        {
            return node?.ToString().NullIfEmpty();
        }
    }
}
