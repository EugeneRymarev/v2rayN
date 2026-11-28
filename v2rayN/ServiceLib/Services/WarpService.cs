namespace ServiceLib.Services;

public static class WarpService
{
    private static readonly string _tag = "WarpService";

    public const string RegistrationUrl = "https://api.cloudflareclient.com/v0a2158/reg";
    public const string ClientVersion = "a-6.10-2158";
    public const string UserAgent = "okhttp/3.12.1";

    // IPv4 literal: this is for IPv4-only networks, and DNS there may be blocked.
    public const string DefaultEndpointHost = "162.159.192.1";
    public const int DefaultEndpointPort = 2408;
    public const int DefaultMtu = 1280;

    public const string TransportTag = "warp-transport";
    public const string TransportIndexId = "inner-warp-transport";

    public const string GlobalIPv6Prefix = "2000::/3";

    // sing-box TUN hands IPv6 to this xray inbound, xray sends it through WARP
    public const string IPv6InboundTag = "warp-ipv6-in";
    public const string IPv6OutboundTag = "warp-ipv6";

    public static bool HasAccount(WarpItem? item)
    {
        return WarpMasqueService.IsMasque(item) ? WarpMasqueService.HasAccount(item) : HasWireGuardAccount(item);
    }

    public static bool HasWireGuardAccount(WarpItem? item)
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

    public static bool IsWarpOnly(WarpItem? item)
    {
        return item?.Mode == EWarpMode.WarpOnly && HasAccount(item);
    }

    public static async Task<ProfileItem?> GetNodeToRunAsync(Config config)
    {
        if (IsWarpOnly(config.WarpItem))
        {
            return CreateTransportNode(config.WarpItem!);
        }
        return await ConfigTextHandler.GetDefaultServer();
    }

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

    public static WarpItem? ParseRegistrationResponse(string? json, string privateKey)
    {
        var root = JsonUtils.ParseJson(json ?? string.Empty);
        // some API versions wrap it in "result"
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

    public static async Task<RetResult> RegisterToConfigAsync(Config config)
    {
        if (WarpMasqueService.IsMasque(config.WarpItem))
        {
            return await WarpMasqueService.RegisterToConfigAsync(config);
        }

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

        // keep the default address if none answers
        var best = await FindBestEndpointAsync(account, 60);
        if (best != null)
        {
            account.EndpointHost = best.Host;
            account.EndpointPort = best.Port;
        }

        account.Mode = config.WarpItem?.Mode ?? EWarpMode.Off;
        account.Protocol = config.WarpItem?.Protocol ?? EWarpProtocol.WireGuard;
        account.MasqueEndpoint = config.WarpItem?.MasqueEndpoint;
        account.MasqueEndpointH2 = config.WarpItem?.MasqueEndpointH2;
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

    public static async Task<RetResult> SelectBestEndpointAsync(Config config)
    {
        var account = config.WarpItem;
        if (WarpMasqueService.IsMasque(account))
        {
            return await WarpMasqueService.SelectEndpointAsync(config);
        }
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

    public static ProfileItem CreateTransportNode(WarpItem account)
    {
        if (WarpMasqueService.IsMasque(account))
        {
            // usque runs next to the core and serves WARP as SOCKS
            return new ProfileItem
            {
                IndexId = TransportIndexId,
                ConfigType = EConfigType.SOCKS,
                CoreType = ECoreType.Xray,
                Remarks = "WARP",
                Address = Global.Loopback,
                Port = AppManager.Instance.WarpMasquePort,
                Subid = string.Empty,
                IsSub = false,
            };
        }

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

    // WireGuard packets to the WARP endpoint must not go back into TUN
    public static List<string> GetTunExcludeAddresses(WarpItem? account)
    {
        if (account == null || account.Mode == EWarpMode.Off || !HasAccount(account))
        {
            return [];
        }
        if (WarpMasqueService.IsMasque(account))
        {
            // every candidate, so the address check also bypasses TUN
            return WarpMasqueService.GetAllEndpoints(account).Select(host => $"{host}/32").ToList();
        }
        var host = account.EndpointHost;
        return Utils.IsIpv4(host) ? [$"{host}/32"] : [];
    }

    // Without its own IPv6 the host can send IPv6 only through WARP
    public static bool ShouldRouteIPv6(WarpItem? account, bool hasGlobalIPv6Address)
    {
        return !hasGlobalIPv6Address && (IsEnabled(account) || IsWarpOnly(account));
    }

    public static string GetIPv6OutboundTag(WarpItem? account)
    {
        return IsWarpOnly(account) ? Global.ProxyTag : TransportTag;
    }

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

    private static (string Host, int Port) ParseEndpoint(string? endpoint)
    {
        // e.g. "162.159.192.1:0", port 0 means any WARP port
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
