using System.Buffers.Binary;

namespace ServiceLib.Common;

/// <summary>
/// BLAKE2s hash (RFC 7693). WireGuard uses it for its handshake; .NET has no built-in version.
/// Only the small one-shot API needed by <see cref="WireGuardHandshake" /> is provided.
/// </summary>
public static class Blake2s
{
    private const int BlockSize = 64;

    private static readonly uint[] IV =
    [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
    ];

    private static readonly byte[,] Sigma =
    {
        { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
        { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
        { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
        { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
        { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
        { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
        { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
        { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
        { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    };

    /// <summary>
    /// Computes BLAKE2s of <paramref name="data" />, optionally keyed (key up to 32 bytes).
    /// </summary>
    public static byte[] Hash(ReadOnlySpan<byte> data, int outLength = 32, ReadOnlySpan<byte> key = default)
    {
        if (outLength is < 1 or > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(outLength));
        }
        if (key.Length > 32)
        {
            throw new ArgumentOutOfRangeException(nameof(key));
        }

        var h = (uint[])IV.Clone();
        h[0] ^= 0x01010000u ^ ((uint)key.Length << 8) ^ (uint)outLength;

        // A keyed hash processes the key, padded to a full block, as the first block.
        var input = new byte[(key.Length > 0 ? BlockSize : 0) + data.Length];
        key.CopyTo(input);
        data.CopyTo(input.AsSpan(key.Length > 0 ? BlockSize : 0));

        ulong counter = 0;
        var offset = 0;
        var block = new byte[BlockSize];
        var m = new uint[16];

        // Every block but the last one
        while (input.Length - offset > BlockSize)
        {
            counter += BlockSize;
            Compress(h, input.AsSpan(offset, BlockSize), m, counter, false);
            offset += BlockSize;
        }

        // Last block (may be empty for an empty unkeyed message)
        var remaining = input.Length - offset;
        Array.Clear(block);
        input.AsSpan(offset, remaining).CopyTo(block);
        counter += (ulong)remaining;
        Compress(h, block, m, counter, true);

        var output = new byte[32];
        for (var i = 0; i < 8; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(i * 4), h[i]);
        }
        return output[..outLength];
    }

    /// <summary>
    /// Hash of the concatenation of several parts.
    /// </summary>
    public static byte[] HashConcat(params byte[][] parts)
    {
        return Hash(Concat(parts).AsSpan());
    }

    /// <summary>
    /// HMAC-BLAKE2s as used by WireGuard (RFC 2104 with a 64-byte block).
    /// </summary>
    public static byte[] Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        var k = new byte[BlockSize];
        if (key.Length > BlockSize)
        {
            Hash(key).CopyTo(k, 0);
        }
        else
        {
            key.CopyTo(k);
        }

        var inner = new byte[BlockSize + data.Length];
        var outerPad = new byte[BlockSize + 32];
        for (var i = 0; i < BlockSize; i++)
        {
            inner[i] = (byte)(k[i] ^ 0x36);
            outerPad[i] = (byte)(k[i] ^ 0x5c);
        }
        data.CopyTo(inner.AsSpan(BlockSize));
        Hash(inner).CopyTo(outerPad, BlockSize);
        return Hash(outerPad);
    }

    public static byte[] Concat(params byte[][] parts)
    {
        var result = new byte[parts.Sum(p => p.Length)];
        var offset = 0;
        foreach (var part in parts)
        {
            part.CopyTo(result, offset);
            offset += part.Length;
        }
        return result;
    }

    private static void Compress(uint[] h, ReadOnlySpan<byte> block, uint[] m, ulong counter, bool last)
    {
        for (var i = 0; i < 16; i++)
        {
            m[i] = BinaryPrimitives.ReadUInt32LittleEndian(block[(i * 4)..]);
        }

        Span<uint> v = stackalloc uint[16];
        for (var i = 0; i < 8; i++)
        {
            v[i] = h[i];
            v[i + 8] = IV[i];
        }
        v[12] ^= (uint)counter;
        v[13] ^= (uint)(counter >> 32);
        if (last)
        {
            v[14] = ~v[14];
        }

        for (var r = 0; r < 10; r++)
        {
            G(v, 0, 4, 8, 12, m[Sigma[r, 0]], m[Sigma[r, 1]]);
            G(v, 1, 5, 9, 13, m[Sigma[r, 2]], m[Sigma[r, 3]]);
            G(v, 2, 6, 10, 14, m[Sigma[r, 4]], m[Sigma[r, 5]]);
            G(v, 3, 7, 11, 15, m[Sigma[r, 6]], m[Sigma[r, 7]]);
            G(v, 0, 5, 10, 15, m[Sigma[r, 8]], m[Sigma[r, 9]]);
            G(v, 1, 6, 11, 12, m[Sigma[r, 10]], m[Sigma[r, 11]]);
            G(v, 2, 7, 8, 13, m[Sigma[r, 12]], m[Sigma[r, 13]]);
            G(v, 3, 4, 9, 14, m[Sigma[r, 14]], m[Sigma[r, 15]]);
        }

        for (var i = 0; i < 8; i++)
        {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    private static void G(Span<uint> v, int a, int b, int c, int d, uint x, uint y)
    {
        unchecked
        {
            v[a] = v[a] + v[b] + x;
            v[d] = uint.RotateRight(v[d] ^ v[a], 16);
            v[c] = v[c] + v[d];
            v[b] = uint.RotateRight(v[b] ^ v[c], 12);
            v[a] = v[a] + v[b] + y;
            v[d] = uint.RotateRight(v[d] ^ v[a], 8);
            v[c] = v[c] + v[d];
            v[b] = uint.RotateRight(v[b] ^ v[c], 7);
        }
    }
}
