using NiL.Cryptography.Tls.Extensions.SignatureScheme;

namespace NiL.Cryptography.Signature;

public interface ISignatureAlgorithm
{
    SignatureScheme Id { get; }
    byte[] Sign(byte[] buffer);
}
