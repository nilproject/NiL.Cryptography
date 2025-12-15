using System;

namespace NiL.Cryptography.Encryption;

public interface IAeadCipher
{
    byte[] Key { get; }
    int InputBlockSize { get; }
    int OutBlockSize { get; }

    void Encrypt(in ReadOnlySpan<byte> authData, in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output, in Span<byte> authTag);
    void Decrypt(in ReadOnlySpan<byte> authData, in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output, in Span<byte> authTag);
}