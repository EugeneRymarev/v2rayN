using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Services;

public class WarpServiceTests
{
    private const string SampleResponse = """
        {
          "id": "device-123",
          "token": "secret-token",
          "account": { "account_type": "free", "warp_plus": false },
          "config": {
            "client_id": "AQID",
            "peers": [
              {
                "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                "endpoint": {
                  "v4": "162.159.192.7:0",
                  "v6": "[2606:4700:d0::a29f:c007]:0",
                  "host": "engage.cloudflareclient.com:2408"
                }
              }
            ],
            "interface": {
              "addresses": { "v4": "172.16.0.2", "v6": "2606:4700:110:8a36::1" }
            }
          }
        }
        """;

    private static byte[] Hex(string hex) => Convert.FromHexString(hex);

    [Test]
    public async Task X25519_Rfc7748Vector_ShouldMatch()
    {
        // RFC 7748, section 5.2, first test vector
        var scalar = Hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        var u = Hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        var result = X25519Utils.ScalarMult(scalar, u);
        await Convert.ToHexString(result).ToLowerInvariant().Should()
            .BeEqualTo("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    [Test]
    public async Task X25519_Rfc7748AlicePublicKey_ShouldMatch()
    {
        // RFC 7748, section 6.1
        var alicePrivate = Hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        var alicePublic = X25519Utils.PublicKeyFromPrivate(alicePrivate);
        await Convert.ToHexString(alicePublic).ToLowerInvariant().Should()
            .BeEqualTo("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    }

    [Test]
    public async Task GenerateKeyPair_ShouldProduceMatchingKeys()
    {
        var (privateKey, publicKey) = X25519Utils.GenerateKeyPair();
        await Convert.FromBase64String(privateKey).Length.Should().BeEqualTo(32);
        await X25519Utils.PublicKeyFromPrivate(privateKey).Should().BeEqualTo(publicKey);
    }

    [Test]
    public async Task ParseRegistrationResponse_ShouldReadAllFields()
    {
        var account = WarpService.ParseRegistrationResponse(SampleResponse, "priv");

        await (account is not null).Should().BeTrue();
        await account!.PrivateKey.Should().BeEqualTo("priv");
        await account.PeerPublicKey.Should().BeEqualTo("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");
        await account.AddressV4.Should().BeEqualTo("172.16.0.2");
        await account.AddressV6.Should().BeEqualTo("2606:4700:110:8a36::1");
        await account.Reserved.Should().BeEqualTo("1, 2, 3");
        await account.EndpointHost.Should().BeEqualTo("162.159.192.7");
        await account.EndpointPort.Should().BeEqualTo(WarpService.DefaultEndpointPort);
        await account.DeviceId.Should().BeEqualTo("device-123");
    }

    [Test]
    public async Task ParseRegistrationResponse_InvalidJson_ShouldReturnNull()
    {
        await (WarpService.ParseRegistrationResponse("{\"error\":\"x\"}", "priv") is null).Should().BeTrue();
        await (WarpService.ParseRegistrationResponse("not json", "priv") is null).Should().BeTrue();
    }

    [Test]
    public async Task BuildRegistrationBody_ShouldContainKey()
    {
        var body = WarpService.BuildRegistrationBody("PUB", new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc));
        var node = JsonUtils.ParseJson(body)!;
        await node["key"]!.GetValue<string>().Should().BeEqualTo("PUB");
        await node["tos"]!.GetValue<string>().Should().BeEqualTo("2026-01-02T03:04:05.000Z");
    }

    [Test]
    public async Task CreateProfileItem_ShouldBuildWireguardProfileWithIpv6()
    {
        var account = WarpService.ParseRegistrationResponse(SampleResponse, "priv")!;
        var item = WarpService.CreateProfileItem(account, "sub1");
        var extra = item.GetProtocolExtra();

        await item.ConfigType.Should().BeEqualTo(EConfigType.WireGuard);
        await item.Address.Should().BeEqualTo("162.159.192.7");
        await item.Port.Should().BeEqualTo(2408);
        await item.Password.Should().BeEqualTo("priv");
        await item.Subid.Should().BeEqualTo("sub1");
        await extra.WgInterfaceAddress.Should().BeEqualTo("172.16.0.2/32, 2606:4700:110:8a36::1/128");
        await extra.WgReserved.Should().BeEqualTo("1, 2, 3");
        await extra.WgMtu.Should().BeEqualTo(1280);
    }

    [Test]
    public async Task CreateChainItem_ShouldOrderNodes()
    {
        var warp = new ProfileItem { IndexId = "warp", Remarks = WarpService.DefaultRemarks, ConfigType = EConfigType.WireGuard };
        var server = new ProfileItem { IndexId = "srv", Remarks = "My server", ConfigType = EConfigType.VLESS, CoreType = ECoreType.Xray };

        var before = WarpService.CreateChainItem(warp, server, true);
        var after = WarpService.CreateChainItem(warp, server, false);

        await before.ConfigType.Should().BeEqualTo(EConfigType.ProxyChain);
        await before.GetProtocolExtra().ChildItems.Should().BeEqualTo("warp,srv");
        await before.Remarks.Should().BeEqualTo("WARP → My server");
        await after.GetProtocolExtra().ChildItems.Should().BeEqualTo("srv,warp");
        await after.Remarks.Should().BeEqualTo("My server → WARP");
    }

    [Test]
    public async Task WarpFirstChain_Xray_ShouldDialServerThroughWarp()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        CoreConfigTestFactory.BindAppManagerConfig(config);

        var account = WarpService.ParseRegistrationResponse(SampleResponse, Convert.ToBase64String(new byte[32]))!;
        var warp = WarpService.CreateProfileItem(account, string.Empty);
        warp.IndexId = "warp";
        var server = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "srv", "server");
        server.Address = "2001:db8::1";
        var chain = WarpService.CreateChainItem(warp, server, true);
        chain.IndexId = "chain";

        var context = CoreConfigTestFactory.CreateContext(config, chain, ECoreType.Xray);
        context.AllProxiesMap[warp.IndexId] = warp;
        context.AllProxiesMap[server.IndexId] = server;

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.protocol.Should().BeEqualTo("socks");
        var dialer = proxy.streamSettings?.sockopt?.dialerProxy ?? string.Empty;
        await dialer.StartsWith("chain-proxy-1-", StringComparison.Ordinal).Should().BeTrue();
        var warpOutbound = cfg.outbounds.First(o => o.tag == dialer);
        await warpOutbound.protocol.Should().BeEqualTo("wireguard");
    }
}

public class WireGuardHandshakeTests
{
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Test]
    public async Task Blake2s_ShouldMatchReferenceValues()
    {
        // Reference values computed with Python's hashlib.blake2s
        await Hex(Blake2s.Hash(Encoding.ASCII.GetBytes("abc"))).Should()
            .BeEqualTo("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
        await Hex(Blake2s.Hash(ReadOnlySpan<byte>.Empty)).Should()
            .BeEqualTo("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9");
        var key = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var data200 = Enumerable.Range(0, 200).Select(i => (byte)i).ToArray();
        await Hex(Blake2s.Hash(data200, 16, key)).Should().BeEqualTo("42a6f8ff590af21b512e9e088257aa34");
        var data64 = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        await Hex(Blake2s.Hash(data64)).Should()
            .BeEqualTo("56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e");
    }

    [Test]
    public async Task HmacBlake2s_ShouldMatchReferenceValues()
    {
        var longKey = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("key", 30)));
        await Hex(Blake2s.Hmac(longKey, Encoding.ASCII.GetBytes("hello world"))).Should()
            .BeEqualTo("bd5db8f8a597c16e9a0beea40b6a34228846d5a7e7176a8a571239819842e44f");
        var data150 = Enumerable.Range(0, 150).Select(i => (byte)i).ToArray();
        await Hex(Blake2s.Hmac(Encoding.ASCII.GetBytes("k"), data150)).Should()
            .BeEqualTo("69d715727774092482b4401ea2843266da8eefdd5d1c3595bcdfa768f3974c89");
    }

    [Test]
    public async Task Tai64N_ShouldEncodeUnixEpoch()
    {
        var t = WireGuardHandshake.Tai64N(DateTime.UnixEpoch.AddSeconds(1).AddTicks(5));
        await Hex(t).Should().BeEqualTo("400000000000000b" + "000001f4");
    }

    [Test]
    public async Task CreateInitiation_ShouldHaveWireGuardLayout()
    {
        if (!WireGuardHandshake.IsSupported)
        {
            return;
        }
        var (priv, _) = X25519Utils.GenerateKeyPair();
        var (_, peerPub) = X25519Utils.GenerateKeyPair();
        var keys = WireGuardHandshake.StaticKeys.FromBase64(priv, peerPub);
        var msg = WireGuardHandshake.CreateInitiation(keys, 0x01020304, DateTime.UtcNow);

        await msg.Length.Should().BeEqualTo(148);
        await msg[0].Should().BeEqualTo((byte)1);
        await Hex(msg[4..8]).Should().BeEqualTo("04030201");
        await msg[132..].All(b => b == 0).Should().BeTrue();
    }

    [Test]
    public async Task IsAnswerTo_ShouldAcceptResponseAndCookieForOurIndex()
    {
        var response = new byte[92];
        response[0] = 2;
        BitConverter.TryWriteBytes(response.AsSpan(8), 77u);
        var cookie = new byte[64];
        cookie[0] = 3;
        BitConverter.TryWriteBytes(cookie.AsSpan(4), 77u);

        await WireGuardHandshake.IsAnswerTo(response, 77).Should().BeTrue();
        await WireGuardHandshake.IsAnswerTo(cookie, 77).Should().BeTrue();
        await WireGuardHandshake.IsAnswerTo(response, 78).Should().BeFalse();
        await WireGuardHandshake.IsAnswerTo(new byte[148], 77).Should().BeFalse();
    }

    [Test]
    public async Task Scanner_Candidates_ShouldBeDistinctWarpAddresses()
    {
        var list = WarpEndpointScanner.BuildCandidates(80, new Random(1));
        await list.Count.Should().BeEqualTo(80);
        await list.Distinct().Count().Should().BeEqualTo(80);
        await list[0].Should().BeEqualTo((WarpService.DefaultEndpointHost, 2408));
        await list.All(c => WarpEndpointScanner.IsWarpAddress(c.Host)).Should().BeTrue();
        await WarpEndpointScanner.IsWarpAddress("8.8.8.8").Should().BeFalse();
    }

    [Test]
    public async Task Probe_ShouldDetectLocalAnswer()
    {
        if (!WireGuardHandshake.IsSupported)
        {
            return;
        }
        // A fake "server" that answers every initiation with a response carrying the sender index
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        _ = Task.Run(async () =>
        {
            var req = await server.ReceiveAsync();
            var resp = new byte[92];
            resp[0] = 2;
            req.Buffer.AsSpan(4, 4).CopyTo(resp.AsSpan(8));
            await server.SendAsync(resp, req.RemoteEndPoint);
        });

        var (priv, _) = X25519Utils.GenerateKeyPair();
        var (_, peerPub) = X25519Utils.GenerateKeyPair();
        var keys = WireGuardHandshake.StaticKeys.FromBase64(priv, peerPub);
        var rtt = await WarpEndpointScanner.ProbeAsync(keys, "127.0.0.1", port, 2000);
        await (rtt is not null).Should().BeTrue();

        using var silent = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var silentPort = ((IPEndPoint)silent.Client.LocalEndPoint!).Port;
        var none = await WarpEndpointScanner.ProbeAsync(keys, "127.0.0.1", silentPort, 300);
        await (none is null).Should().BeTrue();
    }

    /// <summary>
    /// Writes an initiation with fixed keys so an independent implementation can check it.
    /// Enabled only when WG_HANDSHAKE_DUMP is set.
    /// </summary>
    [Test]
    public async Task DumpInitiationForExternalCheck()
    {
        var path = Environment.GetEnvironmentVariable("WG_HANDSHAKE_DUMP");
        if (path.IsNullOrEmpty())
        {
            return;
        }
        var initiatorPriv = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        var responderPriv = Enumerable.Range(101, 32).Select(i => (byte)i).ToArray();
        X25519Utils.ClampPrivateKey(initiatorPriv);
        X25519Utils.ClampPrivateKey(responderPriv);
        var responderPub = X25519Utils.PublicKeyFromPrivate(responderPriv);
        var keys = new WireGuardHandshake.StaticKeys(initiatorPriv, responderPub);
        var msg = WireGuardHandshake.CreateInitiation(keys, 0xAABBCCDD, new DateTime(2026, 11, 24, 5, 0, 0, DateTimeKind.Utc));
        await File.WriteAllTextAsync(path!, $"{Hex(initiatorPriv)}\n{Hex(responderPriv)}\n{Hex(msg)}\n");
    }
}
