using System;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography;

public sealed class CurveDefinition
{
    private CurveDefinition()
    {
    }

    public static CurveDefinition Create<TCurvePoint>(
        NamedCurve name,
        ICurve curve,
        TCurvePoint basePoint,
        IBigUInt order,
        int numbersInKey,
        bool networkOrder) where TCurvePoint : ICurvePoint
    {
        var result = new CurveDefinition()
        {
            Name = name,
            Curve = curve ?? throw new ArgumentNullException(nameof(curve)),
            BasePoint = basePoint,
            Order = order,
            BasePointMultiplier = curve.IsPrecomputeSupported ? CurvePointMultiplier.For(basePoint) : null,
            NumbersInKey = numbersInKey,
            IsNetworkOrder = networkOrder
        };

        result.BasePointMultiplier?.Multiply(curve.P);

        return result;
    }

    public NamedCurve Name { get; private init; }
    public ICurve Curve { get; private init; }
    public ICurvePoint BasePoint { get; private init; }
    public IBigUInt Order { get; private init; }
    public ICurvePointMultiplier BasePointMultiplier { get; private init; }
    public int NumbersInKey { get; private init; }
    public bool IsNetworkOrder { get; private init; }
}
