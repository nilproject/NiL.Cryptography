using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography;

public interface ICurvePoint
{
    public static abstract ICurvePoint Zero { get; }

    int Size { get; }
    IBigUInt X { get; }
    IBigUInt Y { get; }
    IBigUInt Z { get; }

    ICurvePoint Normalize();

    public static ICurvePoint operator *(IBigUInt number, ICurvePoint point) => point.Multiply(number);
    public static ICurvePoint operator *(ICurvePoint point, IBigUInt number) => point.Multiply(number);
    public static ICurvePoint operator +(ICurvePoint x, ICurvePoint y) => x.Add(y);

    ICurvePoint Add(ICurvePoint y);
    ICurvePoint Multiply(IBigUInt number);

    string ToString(string format);
}
