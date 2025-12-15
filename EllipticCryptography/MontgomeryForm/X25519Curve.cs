using System;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography.MontgomeryForm;

// https://datatracker.ietf.org/doc/html/rfc7748
public sealed class X25519Curve : ICurve
{
    public X25519Curve(BigUInt<B512> p, BigUInt<B512> a, BigUInt<B512> b)
    {
        P = p;
        A = a;
        B = b;

        InversedModData = NumericsBase.ComputeInversedModData(p.GetRawBuffer());
    }

    public IBigUInt P { get; private set; }

    public IBigUInt A { get; private set; }

    public IBigUInt B { get; private set; }

    public InversedModData InversedModData { get; }

    public bool IsPrecomputeSupported => false;

    public ICurvePoint CreatePoint(IBigUInt x, IBigUInt y) => throw new NotSupportedException();

    public ICurvePoint CreatePoint(IBigUInt x) => new X25519CurvePoint((BigUInt<B512>)x, this);
}
