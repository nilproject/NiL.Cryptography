using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public sealed class X448EllipticCurvePointRepresentation : KeyExchangeParams
{
    public readonly byte[] Value;

    public override NamedCurve NamedCurve => NamedCurve.X448;

    public X448EllipticCurvePointRepresentation(byte[] value) => Value = value;
}
