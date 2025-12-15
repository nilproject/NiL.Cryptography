using System;

namespace NiL.Cryptography.Tls.Tls12;

public interface IEncryptDecryptProcessor
{
    ArraySegment<byte> Encrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType);
    ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType);
}
