using System;

namespace NiL.Cryptography.Hashing;

public sealed class Hmac(IHashFunction h)
{
    public IHashFunction HashFunction { get; } = h ?? throw new ArgumentNullException(nameof(h));

    public byte[] Compute(in ReadOnlySpan<byte> data, in ReadOnlySpan<byte> key)
    {
        var b = HashFunction.BlockSize;

        var k0 = Array.Empty<byte>();

        if (key.Length <= b)
        {
            k0 = new byte[b];
            for (var i = 0; i < key.Length; i++)
                k0[i] = key[i];
        }
        else if (key.Length > b)
        {
            k0 = HashFunction.Compute(key);
            if (k0.Length < b)
                Array.Resize(ref k0, b);
        }

        var inner = new byte[data.Length + k0.Length];
        var ii = 0;
        for (var j = 0; j < k0.Length; j++)
            inner[ii++] = (byte)(k0[j] ^ 0x36);

        for (var j = 0; j < data.Length; j++)
            inner[ii++] = data[j];

        var h0 = HashFunction.Compute(inner);
        var so = new byte[k0.Length + h0.Length];

        for (var i = 0; i < k0.Length; i++)
            so[i] = (byte)(k0[i] ^ 0x5c);

        for (var i = 0; i < h0.Length; i++)
            so[k0.Length + i] = h0[i];

        var h1 = HashFunction.Compute(so);

        return h1;
    }
}
