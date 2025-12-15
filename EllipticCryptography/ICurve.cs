using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography;

public interface ICurve
{
    IBigUInt P { get; }
    IBigUInt A { get; }
    IBigUInt B { get; }

    ICurvePoint CreatePoint(IBigUInt x, IBigUInt y);

    ICurvePoint CreatePoint(IBigUInt x);

    InversedModData InversedModData { get; }

    bool IsPrecomputeSupported { get; }
}
