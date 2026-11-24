namespace ServiceLib.Services;

public record WarpEndpointResult(string Host, int Port, int RttMs);

/// <summary>
/// Looks for a Cloudflare WARP address and port that answers from the user's network.
/// Some networks block the default 162.159.192.1:2408 but not other WARP addresses or ports,
/// so we send a real WireGuard handshake to a sample of them and keep the fastest one that answers.
/// The address ranges and ports are the ones the open-source warp-plus scanner uses.
/// </summary>
public static class WarpEndpointScanner
{
    private static readonly string _tag = "WarpEndpointScanner";

    // IPv4 only: the feature is meant for networks without IPv6.
    public static readonly string[] Prefixes24 =
    [
        "162.159.192",
        "162.159.195",
        "188.114.96",
        "188.114.97",
        "188.114.98",
        "188.114.99",
    ];

    public static readonly int[] Ports =
    [
        500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942, 943, 945, 946, 955, 968,
        987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476,
        3581, 3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
    ];

    // Ports that most often work, tried on the well-known address first.
    private static readonly int[] PreferredPorts = [2408, 500, 1701, 4500, 878, 894, 2371, 908];

    /// <summary>
    /// True if <paramref name="host" /> belongs to a known WARP range.
    /// </summary>
    public static bool IsWarpAddress(string? host)
    {
        if (host.IsNullOrEmpty())
        {
            return false;
        }
        var idx = host!.LastIndexOf('.');
        return idx > 0 && Prefixes24.Contains(host[..idx]) && Utils.IsIpv4(host);
    }

    /// <summary>
    /// A list of distinct address:port pairs to try: well-known ones first, then random ones.
    /// </summary>
    public static List<(string Host, int Port)> BuildCandidates(int count, Random? random = null)
    {
        var rng = random ?? Random.Shared;
        var result = new List<(string Host, int Port)>();
        var seen = new HashSet<(string, int)>();

        void Add(string host, int port)
        {
            if (result.Count < count && seen.Add((host, port)))
            {
                result.Add((host, port));
            }
        }

        foreach (var port in PreferredPorts)
        {
            Add(WarpService.DefaultEndpointHost, port);
        }
        foreach (var prefix in Prefixes24)
        {
            Add($"{prefix}.{rng.Next(1, 255)}", PreferredPorts[rng.Next(PreferredPorts.Length)]);
        }

        var guard = count * 20;
        while (result.Count < count && guard-- > 0)
        {
            Add($"{Prefixes24[rng.Next(Prefixes24.Length)]}.{rng.Next(1, 255)}", Ports[rng.Next(Ports.Length)]);
        }
        return result;
    }

    /// <summary>
    /// Sends one handshake and returns the round-trip time in ms, or null if there was no answer.
    /// </summary>
    public static async Task<int?> ProbeAsync(WireGuardHandshake.StaticKeys keys, string host, int port,
        int timeoutMs, CancellationToken cancellationToken = default)
    {
        try
        {
            var senderIndex = (uint)RandomNumberGenerator.GetInt32(1, int.MaxValue);
            var packet = WireGuardHandshake.CreateInitiation(keys, senderIndex, DateTime.UtcNow);

            using var udp = new UdpClient(AddressFamily.InterNetwork);
            udp.Connect(IPAddress.Parse(host), port);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(timeoutMs);

            var stopwatch = Stopwatch.StartNew();
            await udp.SendAsync(packet, cts.Token);
            while (true)
            {
                var received = await udp.ReceiveAsync(cts.Token);
                if (WireGuardHandshake.IsAnswerTo(received.Buffer, senderIndex))
                {
                    return (int)Math.Max(1, stopwatch.ElapsedMilliseconds);
                }
            }
        }
        catch (OperationCanceledException)
        {
            return null;
        }
        catch (SocketException)
        {
            return null;
        }
    }

    /// <summary>
    /// Probes candidates in parallel and returns those that answered, fastest first.
    /// </summary>
    public static async Task<List<WarpEndpointResult>> ScanAsync(string privateKey, string peerPublicKey,
        int candidateCount = 100, int concurrency = 20, int timeoutMs = 1500, CancellationToken cancellationToken = default)
    {
        var results = new ConcurrentBag<WarpEndpointResult>();
        if (!WireGuardHandshake.IsSupported)
        {
            Logging.SaveLog($"{_tag}: ChaCha20-Poly1305 is not supported on this system, skipping scan");
            return [];
        }

        WireGuardHandshake.StaticKeys keys;
        try
        {
            keys = WireGuardHandshake.StaticKeys.FromBase64(privateKey, peerPublicKey);
        }
        catch (FormatException ex)
        {
            Logging.SaveLog(_tag, ex);
            return [];
        }

        var candidates = BuildCandidates(candidateCount);
        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = concurrency, CancellationToken = cancellationToken },
            async (candidate, token) =>
            {
                var rtt = await ProbeAsync(keys, candidate.Host, candidate.Port, timeoutMs, token);
                if (rtt is not null)
                {
                    results.Add(new WarpEndpointResult(candidate.Host, candidate.Port, rtt.Value));
                }
            });

        return results.OrderBy(r => r.RttMs).ToList();
    }
}
