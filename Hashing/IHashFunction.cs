using System;

namespace NiL.Cryptography.Hashing;

public interface IHashFunction
{
    public int BlockSize { get; }

    public int DigestSize { get; }

    byte[] Compute(in ReadOnlySpan<byte> data);
}