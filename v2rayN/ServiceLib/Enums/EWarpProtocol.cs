namespace ServiceLib.Enums;

public enum EWarpProtocol
{
    WireGuard = 0,

    // HTTP/3 over QUIC, like the official client
    Masque = 1,

    // HTTP/2 over TCP, for networks that block QUIC
    MasqueHttp2 = 2,
}
