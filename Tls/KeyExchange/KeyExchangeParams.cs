using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public abstract class KeyExchangeParams
{
    public abstract NamedCurve NamedCurve { get; }
}
