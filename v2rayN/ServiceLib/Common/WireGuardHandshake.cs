using System.Buffers.Binary;

namespace ServiceLib.Common;

/// <summary>
/// Builds a WireGuard "handshake initiation" packet (Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s,
/// see https://www.wireguard.com/protocol/). A server only answers it when the address and port
/// really carry WireGuard and our keys are accepted, so sending it is a reliable "is this endpoint alive" probe.
/// </summary>
public static class WireGuardHandshake
{
    public const int InitiationLength = 148;
    public const byte TypeInitiation = 1;
    public const byte TypeResponse = 2;
    public const byte TypeCookieReply = 3;

    private static readonly byte[] Construction = Encoding.ASCII.GetBytes("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s");
    private static readonly byte[] Identifier = Encoding.ASCII.GetBytes("WireGuard v1 zx2c4 Jason@zx2c4.com");
    private static readonly byte[] LabelMac1 = Encoding.ASCII.GetBytes("mac1----");

    // TAI64 label for 1970-01-01 (2^62 + 10 leap seconds)
    private const ulong Tai64Epoch = 0x400000000000000AUL;

    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    /// <summary>
    /// Keys that stay the same for all probes of one account. Pre-computing the static DH
    /// saves one slow scalar multiplication per probe.
    /// </summary>
    public sealed class StaticKeys
    {
        public byte[] StaticPublic { get; }
        public byte[] PeerPublic { get; }
        public byte[] StaticShared { get; }
        public byte[] Mac1Key { get; }
        public byte[] InitialChainKey { get; }
        public byte[] InitialHash { get; }

        public StaticKeys(byte[] staticPrivate, byte[] peerPublic)
        {
            StaticPublic = X25519Utils.PublicKeyFromPrivate(staticPrivate);
            PeerPublic = peerPublic;
            StaticShared = X25519Utils.ScalarMult(staticPrivate, peerPublic);
            Mac1Key = Blake2s.HashConcat(LabelMac1, peerPublic);
            InitialChainKey = Blake2s.Hash(Construction.AsSpan());
            InitialHash = Blake2s.HashConcat(Blake2s.HashConcat(InitialChainKey, Identifier), peerPublic);
        }

        public static StaticKeys FromBase64(string privateKey, string peerPublicKey)
        {
            return new StaticKeys(Convert.FromBase64String(privateKey), Convert.FromBase64String(peerPublicKey));
        }
    }

    /// <summary>
    /// Creates a handshake initiation with a fresh ephemeral key.
    /// </summary>
    public static byte[] CreateInitiation(StaticKeys keys, uint senderIndex, DateTime utcNow)
    {
        var ephemeralPrivate = RandomNumberGenerator.GetBytes(32);
        X25519Utils.ClampPrivateKey(ephemeralPrivate);
        return CreateInitiation(keys, senderIndex, utcNow, ephemeralPrivate);
    }

    public static byte[] CreateInitiation(StaticKeys keys, uint senderIndex, DateTime utcNow, byte[] ephemeralPrivate)
    {
        var ephemeralPublic = X25519Utils.PublicKeyFromPrivate(ephemeralPrivate);

        var c = keys.InitialChainKey;
        var h = keys.InitialHash;

        c = Kdf1(c, ephemeralPublic);
        h = Blake2s.HashConcat(h, ephemeralPublic);

        var (c1, k1) = Kdf2(c, X25519Utils.ScalarMult(ephemeralPrivate, keys.PeerPublic));
        c = c1;
        var encryptedStatic = Seal(k1, keys.StaticPublic, h);
        h = Blake2s.HashConcat(h, encryptedStatic);

        var (_, k2) = Kdf2(c, keys.StaticShared);
        var encryptedTimestamp = Seal(k2, Tai64N(utcNow), h);

        var msg = new byte[InitiationLength];
        msg[0] = TypeInitiation;
        BinaryPrimitives.WriteUInt32LittleEndian(msg.AsSpan(4), senderIndex);
        ephemeralPublic.CopyTo(msg, 8);
        encryptedStatic.CopyTo(msg, 40);
        encryptedTimestamp.CopyTo(msg, 88);
        var mac1 = Blake2s.Hash(msg.AsSpan(0, 116), 16, keys.Mac1Key);
        mac1.CopyTo(msg, 116);
        // mac2 (bytes 132..147) stays zero: it is only needed when the server sent us a cookie
        return msg;
    }

    /// <summary>
    /// True if <paramref name="packet" /> is the server's answer to our initiation
    /// (a handshake response, or a cookie reply that a busy server sends instead).
    /// </summary>
    public static bool IsAnswerTo(ReadOnlySpan<byte> packet, uint senderIndex)
    {
        if (packet.Length < 8)
        {
            return false;
        }
        var type = packet[0];
        var receiverOffset = type switch
        {
            TypeResponse when packet.Length >= 92 => 8,
            TypeCookieReply when packet.Length >= 64 => 4,
            _ => -1,
        };
        return receiverOffset > 0
               && BinaryPrimitives.ReadUInt32LittleEndian(packet[receiverOffset..]) == senderIndex;
    }

    public static byte[] Tai64N(DateTime utcNow)
    {
        var unixSeconds = utcNow.ToUniversalTime() - DateTime.UnixEpoch;
        var seconds = (ulong)Math.Floor(unixSeconds.TotalSeconds);
        var nanos = (uint)((unixSeconds.Ticks % TimeSpan.TicksPerSecond) * 100);
        var result = new byte[12];
        BinaryPrimitives.WriteUInt64BigEndian(result, Tai64Epoch + seconds);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(8), nanos);
        return result;
    }

    private static byte[] Kdf1(byte[] key, byte[] input)
    {
        var t0 = Blake2s.Hmac(key, input);
        return Blake2s.Hmac(t0, [1]);
    }

    private static (byte[], byte[]) Kdf2(byte[] key, byte[] input)
    {
        var t0 = Blake2s.Hmac(key, input);
        var t1 = Blake2s.Hmac(t0, [1]);
        var t2 = Blake2s.Hmac(t0, Blake2s.Concat(t1, [2]));
        return (t1, t2);
    }

    // AEAD with counter 0: nonce is 12 zero bytes
    private static byte[] Seal(byte[] key, byte[] plaintext, byte[] associatedData)
    {
        using var aead = new ChaCha20Poly1305(key);
        var nonce = new byte[12];
        var cipher = new byte[plaintext.Length];
        var tag = new byte[16];
        aead.Encrypt(nonce, plaintext, cipher, tag, associatedData);
        return Blake2s.Concat(cipher, tag);
    }
}
