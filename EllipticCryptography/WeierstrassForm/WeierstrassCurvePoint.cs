using NiL.Cryptography.Numerics;
using System;
using System.Numerics;
using System.Runtime.CompilerServices;
using static NiL.Cryptography.Numerics.NumericsBase;

namespace NiL.Cryptography.EllipticCryptography.WeierstrassForm;

public sealed class WeierstrassCurvePoint<TSize> : ICurvePoint where TSize : INumberSize
{
    private static readonly int _intsCount = TSize.Size / 32;

    public static readonly WeierstrassCurvePoint<TSize> Zero = new() { };

    static ICurvePoint ICurvePoint.Zero => Zero;

    public int Size => TSize.Size;

    private BigUInt<TSize> _x;
    private BigUInt<TSize> _y;
    private BigUInt<TSize> _z;
    private WeierstrassCurve<TSize> _curve;

    public BigUInt<TSize> X => _x;
    public BigUInt<TSize> Y => _y;
    public BigUInt<TSize> Z => _z;
    public WeierstrassCurve<TSize> Curve => _curve;
    IBigUInt ICurvePoint.X => X;
    IBigUInt ICurvePoint.Y => Y;
    IBigUInt ICurvePoint.Z => Z;

    public bool Normalized => _z == 1;

    private WeierstrassCurvePoint() { }

    internal WeierstrassCurvePoint(BigUInt<TSize> x, BigUInt<TSize> y, BigUInt<TSize> z, WeierstrassCurve<TSize> curve)
    {
        if (curve == null)
            throw new ArgumentNullException(nameof(curve));

        _x = x;
        _y = y;
        _z = z;
        _curve = curve;
    }

    internal WeierstrassCurvePoint(BigUInt<TSize> x, BigUInt<TSize> y, WeierstrassCurve<TSize> curve)
        : this(x, y, 1, curve)
    {
    }

    private static readonly BigUInt<TSize> _three = 3;

    ICurvePoint ICurvePoint.Add(ICurvePoint y) => this + (WeierstrassCurvePoint<TSize>)y;

    public static WeierstrassCurvePoint<TSize> operator +(WeierstrassCurvePoint<TSize> x, WeierstrassCurvePoint<TSize> y)
    {
        if (x == Zero)
            return y;

        if (y == Zero)
            return x;

        if (x._curve != y._curve)
            throw new InvalidOperationException();

        return doSumProj(x, y);
    }

    [SkipLocalsInit]
    public static unsafe WeierstrassCurvePoint<TSize> Mul2n(WeierstrassCurvePoint<TSize> point, int n = 1)
    {
        if (point == null)
            throw new ArgumentNullException(nameof(point));

        if (n == 0 || point._z == 0)
            return Zero;

        var length = point._curve.P.GetRawBuffer().Length;

        var x2 = new BigUInt<TSize>(0);
        var z2 = new BigUInt<TSize>(0);
        var y2 = new BigUInt<TSize>(0);

        var px = point._x;
        var py = point._y;
        var pz = point._z;

        var temp0 = stackalloc uint[length];
        var temp1 = stackalloc uint[length];

        var qy = stackalloc uint[length];
        var xqy = stackalloc uint[length];

        var p = stackalloc uint[length];

        var invMod = point._curve.InversedModData;

        Zero(temp0 + invMod.InvModLen, length - invMod.InvModLen);
        Zero(temp1 + invMod.InvModLen, length - invMod.InvModLen);

        fixed (uint* mod = invMod.AlignedMod)
        fixed (uint* a = point._curve.A.GetRawBuffer())

        fixed (uint* k = x2.GetRawBuffer())
        fixed (uint* yr = y2.GetRawBuffer())
        fixed (uint* j = z2.GetRawBuffer())
        fixed (uint* x = px.GetRawBuffer())
        fixed (uint* y = py.GetRawBuffer())
        fixed (uint* z = pz.GetRawBuffer())
        {
            var q = j;

            #region p
            if (point._curve.AIsMinus3)
            {
                if (Add(x, z, temp0, invMod.ModLen) != 0)
                    while (Sub(temp0, mod, temp0, invMod.ModLen) == 0) ;

                if (Sub(x, z, temp1, invMod.ModLen) < 0)
                    while (Add(temp1, mod, temp1, invMod.ModLen) == 0) ;

                Mul(temp0, temp1, p, length);
                Reduce(p, length, invMod);

                Mul(p, 3, p, invMod.ModLen + 1);
                if (p[invMod.ModLen] != 0)
                    Reduce(p, invMod.ModLen + 1, invMod);
            }
            else
            {
                Sqr(x, p, length);
                Reduce(p, length, invMod);

                Mul(p, 3, p, invMod.ModLen + 1);
                if (p[invMod.ModLen] != 0)
                    Reduce(p, length, invMod);

                if (!point._curve.AIsZero)
                {
                    Sqr(z, temp0, length);
                    Reduce(temp0, length, invMod);
                    Mul(temp0, a, temp1, length);
                    Reduce(temp1, length, invMod);

                    if (Add(p, temp1, p, invMod.ModLen) != 0)
                        while (Sub(p, mod, p, invMod.ModLen) == 0) ;
                }
            }
            #endregion

            #region q
            Mul(z, y, q, length);
            Reduce(q, length, invMod);

            if (Add(q, q, q, invMod.ModLen) > 0)
                while (Sub(q, mod, q, invMod.ModLen) == 0) ;
            #endregion

            #region k
            Mul(y, q, qy, length);
            Reduce(qy, length, invMod);

            Mul(x, qy, xqy, length);
            Reduce(xqy, length, invMod);

            Mul(xqy, 4, temp0, invMod.ModLen + 1);
            if (temp0[invMod.ModLen] != 0)
                Reduce(temp0, invMod.ModLen + 1, invMod);

            Sqr(p, temp1, length);
            Reduce(temp1, length, invMod);

            Zero(&k[invMod.ModLen], length - invMod.ModLen);
            if (Sub(temp1, temp0, k, invMod.ModLen) < 0)
                while (Add(k, mod, k, invMod.ModLen) == 0) ;
            #endregion

            #region yr
            Mul(xqy, 6, xqy, invMod.ModLen + 1);

            if (Sub(xqy, temp1, xqy, invMod.ModLen) != 0)
                while (Add(xqy, mod, xqy, invMod.ModLen) == 0) ;

            Reduce(xqy, invMod.ModLen + 1, invMod);

            Mul(xqy, p, temp0, length);
            Reduce(temp0, length, invMod);

            Sqr(qy, temp1, length);
            Reduce(temp1, length, invMod);

            if (Add(temp1, temp1, temp1, invMod.ModLen) != 0)
                while (Sub(temp1, mod, temp1, invMod.ModLen) == 0) ;

            if (Sub(temp0, temp1, yr, invMod.ModLen) < 0)
                while (Add(yr, mod, yr, invMod.ModLen) == 0) ;
            #endregion

            while (n-- > 1)
            {
                #region p
                if (point._curve.AIsMinus3)
                {
                    Sqr(j, temp1, length);
                    Reduce(temp1, length, invMod);

                    if (Add(k, temp1, temp0, invMod.ModLen) != 0)
                        while (Sub(temp0, mod, temp0, invMod.ModLen) == 0) ;

                    if (Sub(k, temp1, temp1, invMod.ModLen) < 0)
                        while (Add(temp1, mod, temp1, invMod.ModLen) == 0) ;

                    Mul(temp0, temp1, p, length);
                    Reduce(p, length, invMod);

                    Mul(p, 3, p, invMod.ModLen + 1);
                    if (p[invMod.ModLen] != 0)
                        Reduce(p, invMod.ModLen + 1, invMod);
                }
                else
                {
                    Sqr(k, p, length);
                    Reduce(p, length, invMod);

                    Mul(p, 3, p, invMod.ModLen + 1);
                    if (p[invMod.ModLen] != 0)
                        Reduce(p, length, invMod);

                    if (!point._curve.AIsZero)
                    {
                        Sqr(j, temp0, length);
                        Reduce(temp0, length, invMod);
                        Sqr(temp0, temp1, length);
                        Reduce(temp1, length, invMod);
                        Mul(temp1, a, temp0, length);
                        Reduce(temp0, length, invMod);

                        if (Add(p, temp0, p, invMod.ModLen) != 0)
                            while (Sub(p, mod, p, invMod.ModLen) == 0) ;
                    }
                }

                #endregion

                #region q
                Mul(j, yr, temp0, length); // j = q
                Reduce(temp0, length, invMod);

                if (Add(temp0, temp0, q, invMod.ModLen) > 0)
                    while (Sub(q, mod, q, invMod.ModLen) == 0) ;
                #endregion

                #region k
                Sqr(yr, qy, length);
                Reduce(qy, length, invMod);

                Mul(k, qy, xqy, length);
                Reduce(xqy, length, invMod);

                Mul(xqy, 8, temp0, invMod.ModLen + 1);
                Reduce(temp0, invMod.ModLen + 1, invMod);

                Sqr(p, temp1, length);
                Reduce(temp1, length, invMod);

                if (Sub(temp1, temp0, k, length) != 0)
                    while (Add(k, mod, k, length) == 0) ;
                #endregion

                #region yr
                Mul(xqy, 12, xqy, invMod.ModLen + 1);

                if (Sub(xqy, temp1, xqy, invMod.ModLen + 1) < 0)
                    while (Add(xqy, mod, xqy, invMod.ModLen + 1) == 0) ;

                Reduce(xqy, invMod.ModLen + 1, invMod);

                Mul(xqy, p, temp0, length);
                Reduce(temp0, length, invMod);

                Sqr(qy, temp1, length);
                Reduce(temp1, length, invMod);

                Mul(temp1, 8, temp1, invMod.ModLen + 1);
                Reduce(temp1, invMod.ModLen + 1, invMod);

                if (Sub(temp0, temp1, yr, invMod.ModLen) < 0)
                    while (Add(yr, mod, yr, invMod.ModLen) == 0) ;
                #endregion
            }

            Mul(k, j, temp0, length);
            Reduce(temp0, length, invMod);

            Move(temp0, k, invMod.ModLen);

            Sqr(j, temp0, length);
            Reduce(temp0, length, invMod);

            Mul(temp0, j, temp1, length);
            Reduce(temp1, length, invMod);

            Move(temp1, j, invMod.ModLen);
        }

        return new WeierstrassCurvePoint<TSize> { _x = x2, _y = y2, _z = z2, _curve = point._curve };
    }

    private static WeierstrassCurvePoint<TSize> doSumProj(WeierstrassCurvePoint<TSize> p1, WeierstrassCurvePoint<TSize> p2)
    {
        if (p1 == Zero)
            return p2;

        if (p2 == Zero)
            return p1;

        if (p1._x == p2._x && p1._y == p2._y && p1._z == p2._z)
            return Mul2n(p1);

        var z3 = new BigUInt<TSize>(0);
        var y3 = new BigUInt<TSize>(0);
        var x3 = new BigUInt<TSize>(0);

        var result = new WeierstrassCurvePoint<TSize> { _x = x3, _y = y3, _z = z3, _curve = p1._curve };
        sumProjNotEquals(p1, p2, result);
        return result;
    }

    private static void doSumProj(WeierstrassCurvePoint<TSize> p1, WeierstrassCurvePoint<TSize> p2, WeierstrassCurvePoint<TSize> result)
    {
        if (p1._z == 0)
        {
            Array.Copy(
                p2._x.GetRawBuffer(),
                result._x.GetRawBuffer(),
                result._curve.P.GetRawBuffer().Length);
            Array.Copy(
                p2._y.GetRawBuffer(),
                result._y.GetRawBuffer(),
                result._curve.P.GetRawBuffer().Length);
            Array.Copy(
                p2._z.GetRawBuffer(),
                result._z.GetRawBuffer(),
                result._curve.P.GetRawBuffer().Length);
            return;
        }

        if (p2._z == 0)
        {
            Array.Copy(
                p1._x.GetRawBuffer(),
                result._x.GetRawBuffer(),
                result._curve.P.GetRawBuffer().Length);
            Array.Copy(
                p1._y.GetRawBuffer(),
                result._y.GetRawBuffer(),
                result._curve.P.GetRawBuffer().Length);
            Array.Copy(
                p1._z.GetRawBuffer(),
                result._z.GetRawBuffer(),
                result._curve.P.GetRawBuffer().Length);
            return;
        }

        if (p1._x == p2._x && p1._y == p2._y && p1._z == p2._z)
            throw new NotImplementedException();

        sumProjNotEquals(p1, p2, result);
    }

    [SkipLocalsInit]
    private static unsafe void sumProjNotEquals(WeierstrassCurvePoint<TSize> p1, WeierstrassCurvePoint<TSize> p2, WeierstrassCurvePoint<TSize> result)
    {
        var length = p1._curve.P.GetRawBuffer().Length;
        var invMod = p1._curve.InversedModData;

        var ps = stackalloc uint[length];
        var qs = stackalloc uint[length];
        var y1z2 = stackalloc uint[length];
        var x2z1 = stackalloc uint[length];
        var zz = stackalloc uint[length];

        var p = stackalloc uint[length];
        var q = stackalloc uint[length];

        var temp0 = stackalloc uint[length];

        Zero(temp0 + invMod.InvModLen, length - invMod.InvModLen);

        fixed (uint* mod = invMod.AlignedMod)

        fixed (uint* x1 = p1._x.GetRawBuffer())
        fixed (uint* y1 = p1._y.GetRawBuffer())
        fixed (uint* z1 = p1._z.GetRawBuffer())

        fixed (uint* x2 = p2._x.GetRawBuffer())
        fixed (uint* y2 = p2._y.GetRawBuffer())
        fixed (uint* z2 = p2._z.GetRawBuffer())

        fixed (uint* j = result._z.GetRawBuffer())
        fixed (uint* yr = result._y.GetRawBuffer())
        fixed (uint* k = result._x.GetRawBuffer())
        {
            var temp1 = j;
            var x1z2 = yr;

            #region p
            Mul(y1, z2, y1z2, length);
            Reduce(y1z2, length, invMod);

            Mul(y2, z1, p, length);

            if (Sub(p, y1z2, p, length) != 0)
                while (Add(p, mod, p, length) == 0) ;
            else
                Reduce(p, length, invMod);

            Sqr(p, ps, length);
            Reduce(ps, length, invMod);
            #endregion

            #region q
            Mul(x1, z2, x1z2, length);
            Reduce(x1z2, length, invMod);

            Mul(x2, z1, x2z1, length);
            Reduce(x2z1, length, invMod);

            if (Sub(x2z1, x1z2, q, length) != 0)
                while (Add(q, mod, q, length) == 0) ;

            Sqr(q, qs, length);
            Reduce(qs, length, invMod);
            #endregion

            #region k
            if (Add(x2z1, x1z2, temp0, invMod.ModLen) != 0)
                while (Sub(temp0, mod, temp0, invMod.ModLen) == 0) ;

            Mul(temp0, qs, temp1, length);
            Reduce(temp1, length, invMod);

            Mul(z1, z2, zz, length);
            Reduce(zz, length, invMod);

            Mul(zz, ps, k, length);

            if (Sub(k, temp1, k, length) != 0)
                while (Add(k, mod, k, length) == 0) ;
            else
                Reduce(k, length, invMod);
            #endregion

            #region yr
            Mul(x1z2, qs, temp0, length);

            if (Sub(temp0, k, temp0, length) != 0)
                while (Add(temp0, mod, temp0, length) == 0) ;
            else
                Reduce(temp0, length, invMod);

            Mul(temp0, p, yr, length);
            Reduce(yr, length, invMod);

            var qt = qs;
            Mul(qs, q, temp1, length);
            Reduce(temp1, length, invMod);
            Move(temp1, qt, invMod.ModLen);

            Mul(y1z2, qt, temp0, length);
            Reduce(temp0, length, invMod);

            if (Sub(yr, temp0, yr, invMod.ModLen) != 0)
            {
                while (Add(yr, mod, yr, invMod.ModLen) == 0) ;
                yr[invMod.ModLen] = 0;
            }
            #endregion

            #region j
            Mul(zz, qt, j, length);
            Reduce(j, length, invMod);

            Mul(k, q, temp0, length);
            Reduce(temp0, length, invMod);
            Move(temp0, k, invMod.ModLen);
            #endregion
        }
    }

    ICurvePoint ICurvePoint.Normalize() => Normalize();

    public unsafe WeierstrassCurvePoint<TSize> Normalize()
    {
        if (Normalized)
            return this;

        var newX = new BigUInt<TSize>(0);
        var newY = new BigUInt<TSize>(0);

        //var invZ = BigUInt<TSize>.ModInverse(_z, _curve.P);
        var invZ = stackalloc uint[_intsCount];

        fixed (uint* zBytes = _z.GetRawBuffer())
        fixed (uint* curvePBytes = _curve.P.GetRawBuffer())
        fixed (uint* newXBytes = newX.GetRawBuffer())
        fixed (uint* newYBytes = newY.GetRawBuffer())
        fixed (uint* xBytes = _x.GetRawBuffer())
        fixed (uint* yBytes = _y.GetRawBuffer())
        {
            ModInverse(zBytes, curvePBytes, invZ, _intsCount);

            Mul(xBytes, invZ, newXBytes, _intsCount);
            Reduce(newXBytes, _intsCount, Curve.InversedModData);
            Mod(newXBytes, curvePBytes, _intsCount);

            Mul(yBytes, invZ, newYBytes, _intsCount);
            Reduce(newYBytes, _intsCount, Curve.InversedModData);
            Mod(newYBytes, curvePBytes, _intsCount);
        }

        return new WeierstrassCurvePoint<TSize>
        {
            _x = newX,
            _y = newY,
            _z = 1,
            _curve = _curve
        };
    }

    private static WeierstrassCurvePoint<TSize> doSumRef(WeierstrassCurvePoint<TSize> x, WeierstrassCurvePoint<TSize> y)
    {
        BigInteger p = x._curve.P.ToBigInteger();
        BigInteger m;       

        if (x.X == y.X)
        {
            var y2 = x._y.ToBigInteger() + x._y.ToBigInteger();
            while (y2 > p)
                y2 -= p;
            var d = BigInteger.ModPow(y2, p - 2, p);
            if (d > p)
                d %= p;

            var xx = x._x.ToBigInteger() * x._x.ToBigInteger() % p;
            m = _three.ToBigInteger() * xx + x._curve.A.ToBigInteger();
            while (m > p)
                m -= p;
            m *= d;
        }
        else
        {
            var t = p + x._x.ToBigInteger() - y._x.ToBigInteger();
            while (t > p)
                t -= p;
            var d = BigInteger.ModPow(t, p - 2, p);
            if (d > p)
                d %= p;

            m = x._y.ToBigInteger() - y._y.ToBigInteger();
            if (x._y < y._y)
                m += p;
            m *= d;
        }

        m %= p;
        var xr = (p + p + m * m - x._x.ToBigInteger() - y._x.ToBigInteger()) % p;
        var mm = m * ((p + xr - x._x.ToBigInteger()) % p) % p;
        var yr = (p + p - (x._y.ToBigInteger() + mm)) % p;

        //return new CurvePoint<TSize>{ _x = xr, _y = yr, _curve = x._curve };
        return new WeierstrassCurvePoint<TSize>(BigUInt<TSize>.FromBytes(xr.ToByteArray()), BigUInt<TSize>.FromBytes(yr.ToByteArray()), x._curve);
    }

    ICurvePoint ICurvePoint.Multiply(IBigUInt number) => (BigUInt<TSize>)number * this;

    public unsafe static WeierstrassCurvePoint<TSize> operator *(BigUInt<TSize> d, WeierstrassCurvePoint<TSize> p)
    {
        if (d == 0 || p == Zero)
            return Zero;

        var premuls = new WeierstrassCurvePoint<TSize>[16];
        premuls[0] = Mul2n(p, 4);                         // 10000
        premuls[1] = doSumProj(premuls[0], p);            // 10001
        premuls[2] = doSumProj(premuls[1], p);            // 10010
        premuls[3] = doSumProj(premuls[2], p);            // 10011
        premuls[4] = doSumProj(premuls[3], p);            // 10100
        premuls[5] = doSumProj(premuls[4], p);            // 10101
        premuls[6] = doSumProj(premuls[5], p);            // 10110
        premuls[7] = doSumProj(premuls[6], p);            // 10111

        premuls[8] = doSumProj(premuls[7], p);             // 11000
        premuls[9] = doSumProj(premuls[8], p);             // 11001
        premuls[10] = doSumProj(premuls[9], p);            // 11010
        premuls[11] = doSumProj(premuls[10], p);           // 11011
        premuls[12] = doSumProj(premuls[11], p);           // 11100
        premuls[13] = doSumProj(premuls[12], p);           // 11101
        premuls[14] = doSumProj(premuls[13], p);           // 11110
        premuls[15] = doSumProj(premuls[14], p);           // 11111

        var tempResult0 = new WeierstrassCurvePoint<TSize>(0, 0, 0, p.Curve);
        var tempResult1 = new WeierstrassCurvePoint<TSize>(0, 0, 0, p.Curve);

        //var r = Zero;
        var x = 0u;
        var n = 1;
        fixed (uint* buffer = d.GetRawBuffer())
        {
            var i = _intsCount;
            while (i-- > 0 && buffer[i] == 0) ;

            for (; i >= 0; i--)
            {
                var v = buffer[i];

                for (var j = 0; j < 32; j++, n++, v <<= 1)
                {
                    x <<= 1;
                    x |= v >> 31 & 1;

                    if (x < 0x10)
                        continue;

                    //r = doSumProj(Mul2n(r, n), premuls[x & 0xf]);
                    doSumProj(Mul2n(tempResult1, n), premuls[x & 0xf], tempResult0);
                    //doSumProj(tempResult1, premuls[x & 0xf], tempResult0);
                    var t = tempResult0;
                    tempResult0 = tempResult1;
                    tempResult1 = t;

                    n = 0;
                    x = 0;
                }
            }
        }

        var r = tempResult1;

        if (x != 0)
        {
            n--;

            while (n-- > 0)
            {
                r = Mul2n(r);

                if ((x >> n & 1) != 0)
                {
                    r = doSumProj(r, p);
                }
            }
        }
        else if (n > 1)
        {
            r = Mul2n(r, n - 1);
        }

        return r;
    }

    public static WeierstrassCurvePoint<TSize> operator *(WeierstrassCurvePoint<TSize> g, BigUInt<TSize> d)
    {
        return d * g;
    }

    public override bool Equals(object obj)
    {
        if (obj == null || obj is not WeierstrassCurvePoint<TSize> curvePoint)
        {
            return false;
        }

        return _curve == curvePoint._curve && _x == curvePoint._x && _y == curvePoint._y && _z == curvePoint._z;
    }

    public override int GetHashCode()
    {
        return _x.GetHashCode() ^ _y.GetHashCode() ^ _curve.GetHashCode();
    }

    public static bool operator ==(WeierstrassCurvePoint<TSize> x, WeierstrassCurvePoint<TSize> y)
    {
        if (ReferenceEquals(x, y))
            return true;

        if (x as object == null)
            return false;

        if (y as object == null)
            return false;

        return x.Equals(y);
    }

    public static bool operator !=(WeierstrassCurvePoint<TSize> x, WeierstrassCurvePoint<TSize> y)
    {
        return !(x == y);
    }

    public string ToString(string format)
    {
        if (this == Zero)
            return "Zero";

        return X.ToString(format) + "; " + Y.ToString(format) + (!Normalized ? "; " + Z.ToString(format) : "");
    }

    public override string ToString()
    {
        return ToString("");
    }
}
