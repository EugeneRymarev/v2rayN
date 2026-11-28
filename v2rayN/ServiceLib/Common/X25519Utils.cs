using System.Numerics;

namespace ServiceLib.Common;

// X25519 (RFC 7748) to create WireGuard keys, .NET has no built-in one
public static class X25519Utils
{
    private static readonly BigInteger P = BigInteger.Pow(2, 255) - 19;
    private static readonly BigInteger A24 = 121665;

    public static (string PrivateKey, string PublicKey) GenerateKeyPair()
    {
        var privateKey = RandomNumberGenerator.GetBytes(32);
        ClampPrivateKey(privateKey);
        var publicKey = PublicKeyFromPrivate(privateKey);
        return (Convert.ToBase64String(privateKey), Convert.ToBase64String(publicKey));
    }

    public static byte[] PublicKeyFromPrivate(byte[] privateKey)
    {
        var basePoint = new byte[32];
        basePoint[0] = 9;
        return ScalarMult(privateKey, basePoint);
    }

    public static string PublicKeyFromPrivate(string privateKeyBase64)
    {
        return Convert.ToBase64String(PublicKeyFromPrivate(Convert.FromBase64String(privateKeyBase64)));
    }

    public static void ClampPrivateKey(byte[] key)
    {
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
    }

    public static byte[] ScalarMult(byte[] scalar, byte[] uCoordinate)
    {
        if (scalar.Length != 32 || uCoordinate.Length != 32)
        {
            throw new ArgumentException("X25519 inputs must be 32 bytes");
        }

        var k = (byte[])scalar.Clone();
        ClampPrivateKey(k);
        var uBytes = (byte[])uCoordinate.Clone();
        uBytes[31] &= 127;

        var x1 = Decode(uBytes);
        BigInteger x2 = 1, z2 = 0, x3 = x1, z3 = 1;
        var swap = 0;

        for (var t = 254; t >= 0; t--)
        {
            var kt = (k[t >> 3] >> (t & 7)) & 1;
            swap ^= kt;
            if (swap == 1)
            {
                (x2, x3) = (x3, x2);
                (z2, z3) = (z3, z2);
            }
            swap = kt;

            var a = Mod(x2 + z2);
            var aa = Mod(a * a);
            var b = Mod(x2 - z2);
            var bb = Mod(b * b);
            var e = Mod(aa - bb);
            var c = Mod(x3 + z3);
            var d = Mod(x3 - z3);
            var da = Mod(d * a);
            var cb = Mod(c * b);
            x3 = Mod((da + cb) * (da + cb));
            z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
            x2 = Mod(aa * bb);
            z2 = Mod(e * Mod(aa + (A24 * e)));
        }

        if (swap == 1)
        {
            (x2, x3) = (x3, x2);
            (z2, z3) = (z3, z2);
        }

        var result = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
        return Encode(result);
    }

    private static BigInteger Mod(BigInteger value)
    {
        var r = value % P;
        return r.Sign < 0 ? r + P : r;
    }

    private static BigInteger Decode(byte[] littleEndian)
    {
        return new BigInteger(littleEndian, isUnsigned: true, isBigEndian: false);
    }

    private static byte[] Encode(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: false);
        var result = new byte[32];
        Array.Copy(bytes, result, Math.Min(bytes.Length, 32));
        return result;
    }
}
