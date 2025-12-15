using System;
using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls.KeyExchange;

public sealed class UncompressedEllipticCurvePointRepresentation : KeyExchangeParams
{
    public readonly byte LegacyPointFormat = 4;

    public readonly byte[] X;
    public readonly byte[] Y;

    public UncompressedEllipticCurvePointRepresentation(byte[] x, byte[] y, NamedCurve namedCurve)
    {
        X = x ?? throw new ArgumentNullException(nameof(x));
        Y = y ?? throw new ArgumentNullException(nameof(y));
        NamedCurve = namedCurve;
    }

    public override NamedCurve NamedCurve { get; }
}
