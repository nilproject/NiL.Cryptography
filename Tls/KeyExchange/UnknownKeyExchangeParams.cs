using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public sealed class UnknownKeyExchangeParams : KeyExchangeParams
{
    public readonly byte[] Data;

    public UnknownKeyExchangeParams(NamedCurve namedCurve, byte[] data)
    {
        NamedCurve = namedCurve;
        Data = data ?? throw new System.ArgumentNullException(nameof(data));
    }

    public override NamedCurve NamedCurve { get; }
}
