using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public sealed class X25519EllipticCurvePointRepresentation : KeyExchangeParams
{
    public readonly byte[] Value;

    public override NamedCurve NamedCurve => NamedCurve.X25519;

    public X25519EllipticCurvePointRepresentation(byte[] value) => Value = value ?? throw new System.ArgumentNullException(nameof(value));
}
