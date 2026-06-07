using System;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

internal interface IAesGcmHwBase
{
    void Crypt(bool encrypt, in ReadOnlySpan<byte> authData, in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output, in Span<byte> authTag);
}
