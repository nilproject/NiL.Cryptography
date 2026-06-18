using System;
using System.Collections.Generic;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography;

public static class CurvePointMultiplier
{
    public static ICurvePointMultiplier<TCurvePoint> For<TCurvePoint>(TCurvePoint basePoint) where TCurvePoint : ICurvePoint
    {
        switch (basePoint.Size)
        {
            case 128: return new CurvePointMultiplier<B128, TCurvePoint>(basePoint);
            case 256: return new CurvePointMultiplier<B256, TCurvePoint>(basePoint);
            case 512: return new CurvePointMultiplier<B512, TCurvePoint>(basePoint);
            default: throw new NotImplementedException(nameof(ICurvePointMultiplier<TCurvePoint>) + " for " + basePoint.Size + " bits");
        }
    }
}

public interface ICurvePointMultiplier
{
    ICurvePoint Multiply(IBigUInt value);
}

public interface ICurvePointMultiplier<TCurvePoint> : ICurvePointMultiplier where TCurvePoint : ICurvePoint
{
    ICurvePoint ICurvePointMultiplier.Multiply(IBigUInt value) => Multiply(value);

    new TCurvePoint Multiply(IBigUInt value);
}

public sealed class CurvePointMultiplier<TSize, TCurvePoint> : ICurvePointMultiplier<TCurvePoint> where TSize : INumberSize where TCurvePoint : ICurvePoint
{
    private readonly List<TCurvePoint[]> _precomputed;

    private const int _GroupBits = 8;
    private const int _GroupSize = (1 << _GroupBits) - 1;
    private const int _Mask = _GroupSize;

    public TCurvePoint Point { get; }

    public CurvePointMultiplier(TCurvePoint point)
    {
        Point = point;

        _precomputed = computePoints();
    }

    private List<TCurvePoint[]> computePoints()
    {
        var precomputed = new List<TCurvePoint[]>
        {
            new TCurvePoint[_GroupSize]
        };
        precomputed[0][0] = Point;
        var layer = precomputed[0];
        fillLayer(layer);
        return precomputed;
    }

    private static void fillLayer(TCurvePoint[] layer)
    {
        for (var i = 1; i < _GroupSize; i++)
            layer[i] = (TCurvePoint)(layer[i - 1] + layer[0]);
    }

    private TCurvePoint getPoint(int degree, uint index)
    {
        if (_precomputed.Count <= degree)
        {
            lock (_precomputed)
            {
                while (_precomputed.Count <= degree)
                {
                    var layer = new TCurvePoint[_GroupSize];
                    var prevLayer = _precomputed[_precomputed.Count - 1];
                    layer[0] = (TCurvePoint)(prevLayer[_GroupSize - 1] + prevLayer[0]);
                    fillLayer(layer);
                    _precomputed.Add(layer);
                }
            }
        }

        return _precomputed[degree][index];
    }

    TCurvePoint ICurvePointMultiplier<TCurvePoint>.Multiply(IBigUInt value) => Multiply((BigUInt<TSize>)value);

    public TCurvePoint Multiply(BigUInt<TSize> m)
    {
        var result = TCurvePoint.Zero;

        var buffer = m.GetRawBuffer();
        var degree = 0;

        for (var i = 0; i < buffer.Length; i++)
        {
            var v = buffer[i];
            for (var j = 0; j < 32 / _GroupBits; j++, degree++)
            {
                var d = v & _Mask;
                v >>= _GroupBits;
                if (d != 0)
                {
                    var point = getPoint(degree, d - 1);
                    result += point;
                }
            }
        }

        return (TCurvePoint)result;
    }
}
