using System.IO.Compression;

namespace ServiceLib.Services;

// WARP over MASQUE through usque (github.com/Diniboy1123/usque), run as a local SOCKS proxy.
// MASQUE looks like ordinary HTTPS, so it gets through where the WireGuard handshake is blocked.
public static class WarpMasqueService
{
    private static readonly string _tag = "WarpMasqueService";

    public const string UsqueVersion = "4.2.1";
    public const string ConfigFileName = "warp-masque.json";
    public const string DefaultEndpointH2 = "162.159.198.2";

    public static string ConfigPath => Utils.GetConfigPath(ConfigFileName);

    public static string ExePath => Utils.GetBinPath(Utils.GetExeName("usque"), ECoreType.usque.ToString());

    public static bool IsMasque(WarpItem? item)
    {
        return item?.Protocol is EWarpProtocol.Masque or EWarpProtocol.MasqueHttp2;
    }

    public static bool HasAccount(WarpItem? item)
    {
        return item != null && item.MasqueEndpoint.IsNotEmpty();
    }

    public static bool ShouldRun(WarpItem? item)
    {
        return IsMasque(item) && item!.Mode != EWarpMode.Off && HasAccount(item);
    }

    public static string? GetEndpoint(WarpItem item)
    {
        return item.Protocol == EWarpProtocol.MasqueHttp2
            ? item.MasqueEndpointH2.NullIfEmpty() ?? DefaultEndpointH2
            : item.MasqueEndpoint;
    }

    public static string BuildSocksArguments(WarpItem item, string configPath, int port)
    {
        var args = $"socks -c {configPath.AppendQuotes()} -b {Global.Loopback} -p {port}";
        return item.Protocol == EWarpProtocol.MasqueHttp2 ? $"{args} --http2" : args;
    }

    public static (string? Endpoint, string? EndpointH2) ParseUsqueConfig(string? json)
    {
        var root = JsonUtils.ParseJson(json ?? string.Empty);
        var endpoint = GetIPv4(root?["endpoint_v4"]);
        var endpointH2 = GetIPv4(root?["endpoint_h2_v4"]);
        return (endpoint, endpointH2);
    }

    public static async Task<RetResult> RegisterToConfigAsync(Config config)
    {
        var exe = await EnsureUsqueAsync();
        if (exe.IsNullOrEmpty())
        {
            return new RetResult(false, string.Format(ResUI.MsgWarpMasqueDownloadFailed, ExePath));
        }

        // usque asks before overwriting a config, so register into a new file
        var tmpPath = Utils.GetTempPath($"{Utils.GetGuid(false)}.json");
        var (exitCode, output) = await RunAsync(exe!, $"register -a -c {tmpPath.AppendQuotes()}", TimeSpan.FromSeconds(60));
        if (exitCode != 0 || !File.Exists(tmpPath))
        {
            Logging.SaveLog($"{_tag}: register failed, exit {exitCode}: {output}");
            return new RetResult(false, ResUI.MsgWarpRegisterFailed);
        }

        var (endpoint, endpointH2) = ParseUsqueConfig(await File.ReadAllTextAsync(tmpPath));
        if (endpoint.IsNullOrEmpty())
        {
            File.Delete(tmpPath);
            return new RetResult(false, ResUI.MsgWarpRegisterFailed);
        }
        File.Move(tmpPath, ConfigPath, true);

        config.WarpItem ??= new();
        config.WarpItem.MasqueEndpoint = endpoint;
        config.WarpItem.MasqueEndpointH2 = endpointH2;
        if (await ConfigTextHandler.SaveConfig() != 0)
        {
            return new RetResult(false, ResUI.OperationFailed);
        }
        return new RetResult(true, ResUI.MsgWarpAccountCreated);
    }

    // Returns the usque path, downloading the release on first use
    public static async Task<string?> EnsureUsqueAsync()
    {
        var exe = ExePath;
        if (File.Exists(exe))
        {
            return exe;
        }
        var url = GetDownloadUrl();
        if (url.IsNullOrEmpty())
        {
            return null;
        }

        foreach (var useProxy in new[] { false, true })
        {
            try
            {
                using var client = HttpClientHelper.Instance.GetHttpClient(useProxy);
                client.Timeout = TimeSpan.FromMinutes(2);
                var bytes = await client.GetByteArrayAsync(url);
                using var archive = new ZipArchive(new MemoryStream(bytes), ZipArchiveMode.Read);
                var entry = archive.Entries.FirstOrDefault(e => e.Name == Path.GetFileName(exe));
                if (entry == null)
                {
                    continue;
                }
                entry.ExtractToFile(exe, true);
                if (Utils.IsNonWindows())
                {
                    await Utils.SetLinuxChmod(exe);
                }
                return exe;
            }
            catch (Exception ex)
            {
                Logging.SaveLog($"{_tag} download (proxy={useProxy})", ex);
            }
        }
        return null;
    }

    public static string? GetDownloadUrl()
    {
        var coreInfo = CoreInfoManager.Instance.GetCoreInfo(ECoreType.usque);
        var arm64 = RuntimeInformation.ProcessArchitecture == Architecture.Arm64;
        var x64 = RuntimeInformation.ProcessArchitecture == Architecture.X64;
        string? template = null;
        if (Utils.IsWindows())
        {
            template = arm64 ? coreInfo?.DownloadUrlWinArm64 : x64 ? coreInfo?.DownloadUrlWin64 : null;
        }
        else if (Utils.IsLinux())
        {
            template = arm64 ? coreInfo?.DownloadUrlLinuxArm64 : x64 ? coreInfo?.DownloadUrlLinux64 : null;
        }
        else if (Utils.IsMacOS())
        {
            template = arm64 ? coreInfo?.DownloadUrlOSXArm64 : x64 ? coreInfo?.DownloadUrlOSX64 : null;
        }
        return template.IsNullOrEmpty() ? null : string.Format(template!, $"v{UsqueVersion}", UsqueVersion);
    }

    private static async Task<(int ExitCode, string Output)> RunAsync(string exe, string arguments, TimeSpan timeout)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = exe,
                Arguments = arguments,
                WorkingDirectory = Utils.GetConfigPath(),
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
            },
        };
        process.Start();
        // answer "no" to any question instead of hanging
        process.StandardInput.Close();
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cts = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(true);
            return (-1, "timeout");
        }
        return (process.ExitCode, $"{await stdout}{await stderr}");
    }

    private static string? GetIPv4(JsonNode? node)
    {
        try
        {
            var value = node?.GetValue<string>();
            return Utils.IsIpv4(value) ? value : null;
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }
}
