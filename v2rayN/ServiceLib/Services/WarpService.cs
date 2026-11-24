namespace ServiceLib.Services;

/// <summary>
/// Data of a free Cloudflare WARP (WireGuard) device registration.
/// </summary>
public record WarpAccount
{
    public string PrivateKey { get; init; } = string.Empty;
    public string PeerPublicKey { get; init; } = string.Empty;
    public string? AddressV4 { get; init; }
    public string? AddressV6 { get; init; }
    public string? Reserved { get; init; }
    public string EndpointHost { get; init; } = WarpService.DefaultEndpointHost;
    public int EndpointPort { get; init; } = WarpService.DefaultEndpointPort;
    public string? DeviceId { get; init; }
}

/// <summary>
/// Registers a free Cloudflare WARP device and turns it into a WireGuard profile.
/// WARP gives every device an IPv6 address, so routing traffic through it lets a client
/// whose ISP only offers IPv4 reach IPv6 servers and sites.
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
    public const string DefaultDns = "1.1.1.1, 2606:4700:4700::1111";
    public const string DefaultRemarks = "Cloudflare WARP";

    /// <summary>
    /// Creates a new WARP device registration with freshly generated keys.
    /// </summary>
    public static async Task<WarpAccount?> RegisterAsync(bool useProxy, CancellationToken cancellationToken = default)
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
    public static WarpAccount? ParseRegistrationResponse(string? json, string privateKey)
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

        return new WarpAccount
        {
            PrivateKey = privateKey,
            PeerPublicKey = peerPublicKey!,
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

    public static ProfileItem CreateProfileItem(WarpAccount account, string? subId, string? remarks = null)
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
            ConfigType = EConfigType.WireGuard,
            CoreType = ECoreType.Xray,
            Remarks = remarks.IsNullOrEmpty() ? DefaultRemarks : remarks!,
            Address = account.EndpointHost,
            Port = account.EndpointPort,
            Password = account.PrivateKey,
            Subid = subId ?? string.Empty,
            IsSub = false,
        };
        item.SetProtocolExtra(item.GetProtocolExtra() with
        {
            WgPublicKey = account.PeerPublicKey,
            WgInterfaceAddress = string.Join(", ", addresses),
            WgReserved = account.Reserved,
            WgMtu = DefaultMtu,
            WgDns = DefaultDns,
        });
        return item;
    }

    /// <summary>
    /// Registers WARP and saves it as a new WireGuard server.
    /// First tries a direct connection; if that fails (the API can be blocked) and a proxy core is running,
    /// retries through the local proxy. Returns the new profile's IndexId in <see cref="RetResult.Data" />.
    /// </summary>
    public static async Task<RetResult> AddWarpServerAsync(string? subId)
    {
        WarpAccount? account = null;
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

        var item = CreateProfileItem(account, subId);

        // Pick an address that actually answers from this network; keep the default if none does.
        var best = await FindBestEndpointAsync(item, 60);
        if (best != null)
        {
            item.Address = best.Host;
            item.Port = best.Port;
        }

        if (await ConfigDbHandler.AddWireguardServer(item) != 0)
        {
            return new RetResult(false, ResUI.OperationFailed);
        }
        var msg = best != null
            ? $"{ResUI.MsgWarpAdded}. {string.Format(ResUI.MsgWarpEndpointSelected, best.Host, best.Port, best.RttMs)}"
            : $"{ResUI.MsgWarpAdded}. {ResUI.MsgWarpEndpointNotFound}";
        return new RetResult(true, msg, item.IndexId);
    }

    /// <summary>
    /// Scans WARP addresses with the keys of <paramref name="warp" /> and returns the fastest one that answered.
    /// </summary>
    public static async Task<WarpEndpointResult?> FindBestEndpointAsync(ProfileItem warp, int candidateCount = 100)
    {
        var peerPublicKey = warp.GetProtocolExtra().WgPublicKey;
        if (warp.Password.IsNullOrEmpty() || peerPublicKey.IsNullOrEmpty())
        {
            return null;
        }
        try
        {
            var results = await WarpEndpointScanner.ScanAsync(warp.Password, peerPublicKey!, candidateCount);
            return results.FirstOrDefault();
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            return null;
        }
    }

    /// <summary>
    /// Re-picks the best address for an existing WARP profile and saves it.
    /// </summary>
    public static async Task<RetResult> SelectBestEndpointAsync(ProfileItem warp)
    {
        if (warp.ConfigType != EConfigType.WireGuard)
        {
            return new RetResult(false, ResUI.MsgWarpNotWarpProfile);
        }
        var best = await FindBestEndpointAsync(warp);
        if (best == null)
        {
            return new RetResult(false, ResUI.MsgWarpEndpointNotFound);
        }
        warp.Address = best.Host;
        warp.Port = best.Port;
        if (await ConfigDbHandler.AddWireguardServer(warp) != 0)
        {
            return new RetResult(false, ResUI.OperationFailed);
        }
        return new RetResult(true, string.Format(ResUI.MsgWarpEndpointSelected, best.Host, best.Port, best.RttMs), warp.IndexId);
    }

    /// <summary>
    /// The WARP profile to work with for <paramref name="selected" />: the profile itself if it is WARP,
    /// the WARP member of a chain, or the default "Cloudflare WARP" profile.
    /// </summary>
    public static async Task<ProfileItem?> ResolveWarpProfileAsync(ProfileItem? selected)
    {
        if (selected != null && IsWarpProfile(selected))
        {
            return selected;
        }
        if (selected?.ConfigType == EConfigType.ProxyChain)
        {
            foreach (var id in Utils.String2List(selected.GetProtocolExtra().ChildItems) ?? [])
            {
                var child = await ConfigDbQuery.GetProfileItem(id);
                if (child != null && IsWarpProfile(child))
                {
                    return child;
                }
            }
        }
        var byName = await ConfigDbQuery.GetProfileItemViaRemarks(DefaultRemarks);
        return byName is { ConfigType: EConfigType.WireGuard } ? byName : null;
    }

    public static bool IsWarpProfile(ProfileItem item)
    {
        return item.ConfigType == EConfigType.WireGuard
               && (item.Remarks == DefaultRemarks || WarpEndpointScanner.IsWarpAddress(item.Address));
    }

    /// <summary>
    /// Finds an existing WARP profile (by remarks) or registers a new one.
    /// </summary>
    public static async Task<ProfileItem?> GetOrAddWarpServerAsync(string? subId)
    {
        var existing = await ConfigDbQuery.GetProfileItemViaRemarks(DefaultRemarks);
        if (existing is { ConfigType: EConfigType.WireGuard })
        {
            return existing;
        }
        var ret = await AddWarpServerAsync(subId);
        if (!ret.Success || ret.Data is not string indexId)
        {
            return null;
        }
        return await ConfigDbQuery.GetProfileItem(indexId);
    }

    /// <summary>
    /// Builds a proxy chain with WARP and the given server.
    /// <paramref name="warpFirst" /> = true: device → WARP → server. The server is reached over WARP,
    /// so IPv6-only servers work even on an IPv4-only network.
    /// <paramref name="warpFirst" /> = false: device → server → WARP. Sites see a WARP address,
    /// which gives IPv6 even when the server itself has none.
    /// </summary>
    public static ProfileItem CreateChainItem(ProfileItem warp, ProfileItem server, bool warpFirst)
    {
        var chain = new ProfileItem
        {
            ConfigType = EConfigType.ProxyChain,
            CoreType = server.CoreType is ECoreType.sing_box ? ECoreType.sing_box : ECoreType.Xray,
            Remarks = warpFirst
                ? $"WARP → {server.Remarks}"
                : $"{server.Remarks} → WARP",
            Subid = server.Subid,
            IsSub = false,
        };
        List<string> childItems = warpFirst ? [warp.IndexId, server.IndexId] : [server.IndexId, warp.IndexId];
        chain.SetProtocolExtra(chain.GetProtocolExtra() with
        {
            GroupType = nameof(EConfigType.ProxyChain),
            ChildItems = Utils.List2String(childItems),
        });
        return chain;
    }

    public static async Task<RetResult> AddChainAsync(ProfileItem server, bool warpFirst)
    {
        if (server.ConfigType.IsGroupType() || server.ConfigType is EConfigType.Custom)
        {
            return new RetResult(false, ResUI.MsgWarpChainUnsupported);
        }
        if (server.ConfigType == EConfigType.WireGuard && server.Remarks == DefaultRemarks)
        {
            return new RetResult(false, ResUI.MsgWarpChainUnsupported);
        }

        var warp = await GetOrAddWarpServerAsync(server.Subid);
        if (warp == null)
        {
            return new RetResult(false, ResUI.MsgWarpRegisterFailed);
        }

        var chain = CreateChainItem(warp, server, warpFirst);
        if (await ConfigDbHandler.AddServerCommon(chain) != 0)
        {
            return new RetResult(false, ResUI.OperationFailed);
        }
        return new RetResult(true, ResUI.OperationSuccess, chain.IndexId);
    }

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
