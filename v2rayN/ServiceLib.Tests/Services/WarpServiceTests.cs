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

    private static WarpItem SampleAccount(EWarpMode mode)
    {
        var account = WarpService.ParseRegistrationResponse(SampleResponse, Convert.ToBase64String(new byte[32]))!;
        account.Mode = mode;
        return account;
    }

    [Test]
    public async Task CreateTransportNode_ShouldBuildWireguardNodeWithIpv6()
    {
        var node = WarpService.CreateTransportNode(SampleAccount(EWarpMode.All));
        var extra = node.GetProtocolExtra();

        await node.ConfigType.Should().BeEqualTo(EConfigType.WireGuard);
        await node.IndexId.Should().BeEqualTo(WarpService.TransportIndexId);
        await node.Address.Should().BeEqualTo("162.159.192.7");
        await node.Port.Should().BeEqualTo(2408);
        await extra.WgInterfaceAddress.Should().BeEqualTo("172.16.0.2/32, 2606:4700:110:8a36::1/128");
        await extra.WgReserved.Should().BeEqualTo("1, 2, 3");
        await extra.WgMtu.Should().BeEqualTo(1280);
    }

    [Test]
    public async Task ShouldDialThroughWarp_ShouldFollowMode()
    {
        var all = SampleAccount(EWarpMode.All);
        var v6 = SampleAccount(EWarpMode.Ipv6Only);
        var off = SampleAccount(EWarpMode.Off);

        await WarpService.ShouldDialThroughWarp(all, "example.com").Should().BeTrue();
        await WarpService.ShouldDialThroughWarp(all, "1.2.3.4").Should().BeTrue();
        await WarpService.ShouldDialThroughWarp(v6, "1.2.3.4").Should().BeFalse();
        await WarpService.ShouldDialThroughWarp(v6, "2001:db8::1").Should().BeTrue();
        await WarpService.ShouldDialThroughWarp(v6, "[2001:db8::1]").Should().BeTrue();
        await WarpService.ShouldDialThroughWarp(off, "2001:db8::1").Should().BeFalse();
        // never through itself
        await WarpService.ShouldDialThroughWarp(all, all.EndpointHost).Should().BeFalse();
        // no account -> never
        await WarpService.ShouldDialThroughWarp(new WarpItem { Mode = EWarpMode.All }, "1.2.3.4").Should().BeFalse();
    }

    [Test]
    public async Task WarpOnly_ShouldUseWarpAsExitAndNotChainServers()
    {
        var warpOnly = SampleAccount(EWarpMode.WarpOnly);

        await WarpService.IsWarpOnly(warpOnly).Should().BeTrue();
        await WarpService.IsWarpOnly(SampleAccount(EWarpMode.All)).Should().BeFalse();
        await WarpService.IsWarpOnly(new WarpItem { Mode = EWarpMode.WarpOnly }).Should().BeFalse();
        await WarpService.IsEnabled(warpOnly).Should().BeFalse();
        await WarpService.ShouldDialThroughWarp(warpOnly, "2001:db8::1").Should().BeFalse();
    }

    [Test]
    public async Task Xray_WarpOnly_ShouldRunWarpAsMainOutbound()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.WarpItem = SampleAccount(EWarpMode.WarpOnly);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = WarpService.CreateTransportNode(config.WarpItem);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.protocol.Should().BeEqualTo("wireguard");
        await cfg.outbounds.Any(o => o.tag == WarpService.TransportTag).Should().BeFalse();
        // sniffed names must not replace the real destination
        await cfg.inbounds.All(i => i.sniffing?.routeOnly != false).Should().BeTrue();
    }

    [Test]
    public async Task Singbox_WarpOnly_ShouldRunWarpAsMainEndpoint()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        config.WarpItem = SampleAccount(EWarpMode.WarpOnly);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = WarpService.CreateTransportNode(config.WarpItem);
        node.CoreType = ECoreType.sing_box;
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.sing_box);

        var result = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<SingboxConfig>(result.Data!.ToString())!;

        var proxy = cfg.endpoints!.First(e => e.tag == Global.ProxyTag);
        await proxy.type.Should().BeEqualTo("wireguard");
        await cfg.endpoints!.Any(e => e.tag == WarpService.TransportTag).Should().BeFalse();
    }

    [Test]
    public async Task Xray_WarpOnlyTun_ShouldCarryIPv6WithoutHostIPv6()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.WarpItem = SampleAccount(EWarpMode.WarpOnly);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = WarpService.CreateTransportNode(config.WarpItem);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray, hasGlobalIPv6Address: false);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var tun = cfg.inbounds.First(i => i.protocol == "tun");
        await tun.settings.autoSystemRoutingTable.Should().Contain("::/0");
        await tun.settings.gateway.Should().HaveCount(2);
    }

    [Test]
    public async Task Singbox_WarpOnlyTun_ShouldHaveIPv6Address()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.sing_box, enableIPv6Address: false);
        config.WarpItem = SampleAccount(EWarpMode.WarpOnly);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = WarpService.CreateTransportNode(config.WarpItem);
        node.CoreType = ECoreType.sing_box;
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.sing_box, hasGlobalIPv6Address: false);

        var result = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<SingboxConfig>(result.Data!.ToString())!;

        var tun = cfg.inbounds.First(i => i.type == "tun");
        await tun.address!.Should().HaveCount(2);
        // the WARP endpoint must not loop back into TUN
        await tun.route_exclude_address!.Should().Contain($"{config.WarpItem.EndpointHost}/32");
    }

    [Test]
    public async Task Xray_WarpTun_ShouldKeepEndpointOutOfTunnel()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.WarpItem = SampleAccount(EWarpMode.WarpOnly);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = WarpService.CreateTransportNode(config.WarpItem);
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.Xray);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var routes = cfg.inbounds.First(i => i.protocol == "tun").settings.autoSystemRoutingTable!;
        await routes.Contains("0.0.0.0/0").Should().BeFalse();
        var endpoint = System.Net.IPAddress.Parse(config.WarpItem.EndpointHost!);
        var covered = routes.Select(IPNetwork2.Parse).Any(n => n.Contains(endpoint));
        await covered.Should().BeFalse();
    }

    [Test]
    public async Task GetTunExcludeAddresses_ShouldFollowMode()
    {
        await WarpService.GetTunExcludeAddresses(SampleAccount(EWarpMode.Off)).Count.Should().BeEqualTo(0);
        await WarpService.GetTunExcludeAddresses(SampleAccount(EWarpMode.All)).Should().Contain("162.159.192.7/32");
        await WarpService.GetTunExcludeAddresses(null).Count.Should().BeEqualTo(0);
    }

    [Test]
    public async Task ShouldRouteIPv6_ShouldNeedWarpAndNoHostIPv6()
    {
        await WarpService.ShouldRouteIPv6(SampleAccount(EWarpMode.Ipv6Only), false).Should().BeTrue();
        await WarpService.ShouldRouteIPv6(SampleAccount(EWarpMode.WarpOnly), false).Should().BeTrue();
        await WarpService.ShouldRouteIPv6(SampleAccount(EWarpMode.Ipv6Only), true).Should().BeFalse();
        await WarpService.ShouldRouteIPv6(SampleAccount(EWarpMode.Off), false).Should().BeFalse();
        await WarpService.GetIPv6OutboundTag(SampleAccount(EWarpMode.All)).Should().BeEqualTo(WarpService.TransportTag);
        await WarpService.GetIPv6OutboundTag(SampleAccount(EWarpMode.WarpOnly)).Should().BeEqualTo(Global.ProxyTag);
    }

    [Test]
    public async Task Singbox_TunInFrontOfXray_ShouldHandIPv6ToXray()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.WarpItem = SampleAccount(EWarpMode.Ipv6Only);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var node = new ProfileItem
        {
            CoreType = ECoreType.sing_box,
            ConfigType = EConfigType.SOCKS,
            Address = Global.Loopback,
            Port = AppManager.Instance.GetLocalPort(EInboundProtocol.socks),
        };
        var context = CoreConfigTestFactory.CreateContext(config, node, ECoreType.sing_box, hasGlobalIPv6Address: false);

        var result = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<SingboxConfig>(result.Data!.ToString())!;

        await cfg.inbounds.First(i => i.type == "tun").address!.Should().HaveCount(2);
        var link = cfg.outbounds.First(o => o.tag == WarpService.IPv6OutboundTag);
        await link.type.Should().BeEqualTo("socks");
        await link.server_port.Should().BeEqualTo(AppManager.Instance.WarpIPv6Port);
        var rule = cfg.route.rules.First(r => r.ip_cidr?.Contains(WarpService.GlobalIPv6Prefix) == true);
        await rule.outbound.Should().BeEqualTo(WarpService.IPv6OutboundTag);
        // xray behind it owns the WARP connection
        await (cfg.endpoints?.Any(e => e.tag == WarpService.TransportTag) ?? false).Should().BeFalse();
    }

    [Test]
    public async Task Xray_BehindTun_ShouldSendIPv6FromTunThroughWarp()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.WarpItem = SampleAccount(EWarpMode.Ipv6Only);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var server = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "srv", "server");
        server.Address = "1.2.3.4";
        var context = CoreConfigTestFactory.CreateContext(config, server, ECoreType.Xray, hasGlobalIPv6Address: false)
            with { IsTunEnabled = false };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var inbound = cfg.inbounds.First(i => i.tag == WarpService.IPv6InboundTag);
        await inbound.port.Should().BeEqualTo(AppManager.Instance.WarpIPv6Port);
        await inbound.listen.Should().BeEqualTo(Global.Loopback);
        await inbound.sniffing.enabled.Should().BeFalse();
        var rule = cfg.routing.rules.First(r => r.inboundTag?.Contains(WarpService.IPv6InboundTag) == true);
        await rule.outboundTag.Should().BeEqualTo(WarpService.TransportTag);
        await cfg.outbounds.Any(o => o.tag == WarpService.TransportTag).Should().BeTrue();
        // an IPv4 server is still dialed directly
        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await (proxy.streamSettings?.sockopt?.dialerProxy is null).Should().BeTrue();
    }

    [Test]
    public async Task Xray_HostWithIPv6_ShouldNotRouteIPv6ThroughWarp()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.WarpItem = SampleAccount(EWarpMode.Ipv6Only);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var server = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "srv", "server");
        server.Address = "1.2.3.4";
        var context = CoreConfigTestFactory.CreateContext(config, server, ECoreType.Xray, hasGlobalIPv6Address: true)
            with { IsTunEnabled = false };

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        await cfg.inbounds.Any(i => i.tag == WarpService.IPv6InboundTag).Should().BeFalse();
        await cfg.outbounds.Any(o => o.tag == WarpService.TransportTag).Should().BeFalse();
    }

    [Test]
    public async Task Xray_OwnTun_ShouldSendIPv6FromTunThroughWarp()
    {
        var config = CoreConfigTestFactory.CreateConfigWithTun(ECoreType.Xray, enableIPv6Address: false);
        config.TunModeItem.EnableLegacyProtect = false;
        config.WarpItem = SampleAccount(EWarpMode.All);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var server = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "srv", "server");
        server.Address = "1.2.3.4";
        var context = CoreConfigTestFactory.CreateContext(config, server, ECoreType.Xray, hasGlobalIPv6Address: false);

        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;

        var tun = cfg.inbounds.First(i => i.protocol == "tun");
        await tun.settings.gateway.Should().HaveCount(2);
        var rule = cfg.routing.rules.First(r => r.ip?.Contains(WarpService.GlobalIPv6Prefix) == true);
        await rule.inboundTag!.Should().Contain("tun");
        await rule.outboundTag.Should().BeEqualTo(WarpService.TransportTag);
        await cfg.inbounds.Any(i => i.tag == WarpService.IPv6InboundTag).Should().BeFalse();
    }

    private static V2rayConfig GenerateXray(EWarpMode mode, string serverAddress)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.Xray);
        config.WarpItem = SampleAccount(mode);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var server = CoreConfigTestFactory.CreateSocksNode(ECoreType.Xray, "srv", "server");
        server.Address = serverAddress;
        var context = CoreConfigTestFactory.CreateContext(config, server, ECoreType.Xray);
        var result = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        if (!result.Success)
        {
            throw new InvalidOperationException(result.Msg);
        }
        return JsonUtils.Deserialize<V2rayConfig>(result.Data!.ToString())!;
    }

    [Test]
    public async Task Xray_ModeAll_ShouldDialServerThroughWarp()
    {
        var cfg = GenerateXray(EWarpMode.All, "1.2.3.4");

        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await (proxy.streamSettings?.sockopt?.dialerProxy).Should().BeEqualTo(WarpService.TransportTag);
        var warp = cfg.outbounds.First(o => o.tag == WarpService.TransportTag);
        await warp.protocol.Should().BeEqualTo("wireguard");
        await (warp.streamSettings?.sockopt?.dialerProxy is null).Should().BeTrue();
    }

    [Test]
    public async Task Xray_ModeIpv6Only_ShouldOnlyAffectIpv6Servers()
    {
        var v4 = GenerateXray(EWarpMode.Ipv6Only, "1.2.3.4");
        await v4.outbounds.Any(o => o.tag == WarpService.TransportTag).Should().BeFalse();

        var v6 = GenerateXray(EWarpMode.Ipv6Only, "2001:db8::1");
        var proxy = v6.outbounds.First(o => o.tag == Global.ProxyTag);
        await (proxy.streamSettings?.sockopt?.dialerProxy).Should().BeEqualTo(WarpService.TransportTag);
    }

    [Test]
    public async Task Xray_ModeOff_ShouldNotAddWarp()
    {
        var cfg = GenerateXray(EWarpMode.Off, "2001:db8::1");
        await cfg.outbounds.Any(o => o.tag == WarpService.TransportTag).Should().BeFalse();
    }

    [Test]
    public async Task Singbox_ModeAll_ShouldDetourServerThroughWarp()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        config.WarpItem = SampleAccount(EWarpMode.All);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var server = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, "srv", "server");
        server.Address = "2001:db8::1";
        var context = CoreConfigTestFactory.CreateContext(config, server, ECoreType.sing_box);

        var result = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await result.Success.Should().BeTrue();
        var cfg = JsonUtils.Deserialize<SingboxConfig>(result.Data!.ToString())!;

        var proxy = cfg.outbounds.First(o => o.tag == Global.ProxyTag);
        await proxy.detour.Should().BeEqualTo(WarpService.TransportTag);
        var warp = cfg.endpoints!.First(e => e.tag == WarpService.TransportTag);
        await warp.type.Should().BeEqualTo("wireguard");
        await warp.detour.IsNullOrEmpty().Should().BeTrue();
    }
}

public class WireGuardHandshakeTests
{
    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();

    [Test]
    public async Task Blake2s_ShouldMatchReferenceValues()
    {
        // values from Python hashlib.blake2s
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
        // fake server: answers every initiation with a response
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
}
