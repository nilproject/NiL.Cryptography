using System;
using NiL.Cryptography.Numerics;
using static NiL.Cryptography.Numerics.NumericsBase;

namespace NiL.Cryptography.EllipticCryptography.MontgomeryForm
{
    // https://martin.kleppmann.com/papers/curve25519.pdf
    // https://datatracker.ietf.org/doc/html/rfc7748
    public unsafe sealed class X25519CurvePoint : ICurvePoint
    {
        private X25519Curve _curve;

        public X25519CurvePoint(BigUInt<B512> x, X25519Curve montgomeryCurve)
        {
            X = x;
            _curve = montgomeryCurve;
        }

        public static ICurvePoint Zero => throw new NotImplementedException();

        public int Size => B512.Size;

        public IBigUInt X { get; private set; }

        IBigUInt ICurvePoint.Y => new BigUInt<B512>();

        IBigUInt ICurvePoint.Z => new BigUInt<B512>(1);

        ICurvePoint ICurvePoint.Add(ICurvePoint y)
        {
            throw new NotSupportedException();
        }

        //[SkipLocalsInit]
        public unsafe ICurvePoint Multiply(IBigUInt number)
        {
            int len = Size / 32;
            var x1 = stackalloc uint[len];
            var x2 = stackalloc uint[len];
            var z2 = stackalloc uint[len];
            var x3 = stackalloc uint[len];
            var z3 = stackalloc uint[len];
            var tmp0 = stackalloc uint[len];
            var tmp1 = stackalloc uint[len];
            var a = stackalloc uint[len];
            var aa = stackalloc uint[len];
            var b = stackalloc uint[len];
            var bb = stackalloc uint[len];
            var e = stackalloc uint[len];
            var c = stackalloc uint[len];
            var d = stackalloc uint[len];
            var cb = stackalloc uint[len];
            var swap = 0u;
            var modData = _curve.InversedModData;
            uint* swapTemp;

            fixed (uint* pk = (number as IBigUIntInternal).GetRawBuffer())
            fixed (uint* u = (X as IBigUIntInternal).GetRawBuffer())
            fixed (uint* p = (_curve.P as IBigUIntInternal).GetRawBuffer())
            fixed (uint* ap = modData.AlignedMod)
            {

                Move(u, x1, len);
                x2[0] = 1;
                Move(u, x3, len);
                z3[0] = 1;

                for (int i = 8; i-- > 0;)
                {
                    var k = pk[i];

                    if (i == 0)
                        k &= 0xffff_fff8;
                    else if (i == 7)
                    {
                        k &= 0x7fff_ffff;
                        k |= 0x4000_0000;
                    }

                    for (var t = i == 7 ? 31 : 32; t-- > 0;)
                    {
                        var kt = (k >> t) & 1;
                        swap ^= kt;
                        if (swap != 0)
                        {
                            swapTemp = x2;
                            x2 = x3;
                            x3 = swapTemp;

                            swapTemp = z2;
                            z2 = z3;
                            z3 = swapTemp;
                        }
                        swap = kt;

                        // A = x_2 + z_2
                        if (Add(x2, z2, a, len / 2) != 0)
                            while (Sub(a, ap, a, len / 2) == 0) ;

                        // AA = A ^ 2
                        Sqr(a, bb, len);
                        Reduce(bb, len, modData);
                        Move(bb, aa, len / 2);

                        // B = x_2 - z_2
                        if (Sub(x2, z2, b, len / 2) != 0)
                            while (Add(b, ap, b, len / 2) == 0) ;

                        // BB = B^2
                        Sqr(b, e, len);
                        Reduce(e, len, modData);
                        Move(e, bb, len / 2);

                        // E = AA - BB
                        if (Sub(aa, bb, e, len / 2) != 0)
                            while (Add(e, ap, e, len / 2) == 0) ;

                        // C = x_3 + z_3
                        if (Add(x3, z3, c, len / 2) != 0)
                            while (Sub(c, ap, c, len / 2) == 0) ;

                        // D = x_3 - z_3
                        if (Sub(x3, z3, d, len / 2) != 0)
                            while (Add(d, ap, d, len / 2) == 0) ;

                        // DA = D * A
                        Mul(d, a, x2, len); // x2=da
                        Reduce(x2, len, modData);

                        // CB = C * B
                        Mul(c, b, cb, len);
                        Reduce(cb, len, modData);

                        // x_3 = (DA + CB)^2
                        if (Add(x2, cb, b, len / 2) != 0)
                            while (Sub(b, ap, b, len / 2) == 0) ;

                        Sqr(b, x3, len);
                        Reduce(x3, len, modData);

                        // z_3 = x_1 * (DA - CB)^2
                        if (Sub(x2, cb, b, len / 2) != 0)
                            while (Add(b, ap, b, len / 2) == 0) ;

                        Sqr(b, x2, len); // x2 as temp storage
                        Reduce(x2, len, modData);
                        Mul(x1, x2, z3, len);
                        Reduce(z3, len, modData);

                        // x_2 = AA * BB
                        Mul(aa, bb, x2, len);
                        Reduce(x2, len, modData);

                        // z_2 = E * (AA + a24 * E)
                        Mul(e, 121665, b, len);
                        Add(aa, b, b, len);
                        Reduce(b, len, modData);
                        Mul(e, b, z2, len);
                        Reduce(z2, len, modData);
                    }
                }

                if (swap != 0)
                {
                    swapTemp = x2;
                    x2 = x3;
                    x3 = swapTemp;

                    swapTemp = z2;
                    z2 = z3;
                    z3 = swapTemp;
                }

                ModInverse(z2, p, tmp1, len);
                Mul(tmp1, x2, z2, len);
                Reduce(z2, len, modData);
                Mod(z2, p, len);

                return new X25519CurvePoint(BigUInt<B512>.FromBytes(new Span<byte>(z2, len * 4)), _curve);
            }
        }

        public ICurvePoint Normalize() => this;

        public string ToString(string format) => X.ToString(format);

        public static ICurvePoint operator *(BigUInt<B512> number, X25519CurvePoint point) => point.Multiply(number);
        public static ICurvePoint operator *(X25519CurvePoint point, BigUInt<B512> number) => point.Multiply(number);
        public static ICurvePoint operator +(X25519CurvePoint x, X25519CurvePoint y) => throw new NotSupportedException();
    }
}
