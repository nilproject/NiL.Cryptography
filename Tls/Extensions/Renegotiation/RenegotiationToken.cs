using System;

namespace NiL.Cryptography.Tls.Extensions.Renegotiation;

public sealed class RenegotiationToken
{
    public RenegotiationToken(byte[] bytes)
    {
        Bytes = bytes ?? throw new ArgumentNullException(nameof(bytes));
    }

    public byte[] Bytes { get; }

    public override bool Equals(object obj)
    {
        if (!(obj is RenegotiationToken renegotiationToken))
            return false;

        if (ReferenceEquals(renegotiationToken.Bytes, Bytes))
            return true;

        if (renegotiationToken.Bytes.Length != Bytes.Length)
            return false;

        for (var i = 0; i < Bytes.Length; i++)
        {
            if (renegotiationToken.Bytes[i] != Bytes[i])
                return false;
        }

        return true;
    }

    public override int GetHashCode()
    {
        unchecked
        {
            int hash;
            var keyLen = Bytes.Length;
            byte b;
            int o;
            hash = (int)((uint)keyLen * 0x30303) ^ 0xb7b7b7;
            for (var i = 0; i < keyLen; i++)
            {
                b = Bytes[i];

                o = hash;
                hash >>= 3;
                hash ^= o * 0x0151_0131;
                hash ^= b * 0x34d8_4881;
            }

            return hash;
        }
    }
}
