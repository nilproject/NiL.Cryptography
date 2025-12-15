using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public sealed class UnknownEllipticCurvePointRepresentation : KeyExchangeParams
{
    public readonly byte Representation;
    public readonly byte[] Value;

    public UnknownEllipticCurvePointRepresentation(byte representation, byte[] value, NamedCurve namedCurve)
    {
        Representation = representation;
        Value = value;
        NamedCurve = namedCurve;
    }

    public override NamedCurve NamedCurve { get; }
}
