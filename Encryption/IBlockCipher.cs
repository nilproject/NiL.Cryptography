using System;

namespace NiL.Cryptography.Encryption;

public interface IBlockCipher
{
    byte[] Key { get; }

    int InputBlockSize { get; }
    int OutBlockSize { get; }
    
    void Encrypt(in ReadOnlySpan<byte> input, in Span<byte> output);
    void Decrypt(in ReadOnlySpan<byte> input, in Span<byte> output);
}