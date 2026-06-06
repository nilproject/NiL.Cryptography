//#define BENCH
#define PUBLIC

using System;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using NiL.Tools;

#if NET7_0_OR_GREATER
using uint128 = System.UInt128;
#endif

namespace NiL.Cryptography.Numerics;

#if BENCH || DEBUG || PUBLIC
public
#else
internal
#endif
    static unsafe class NumericsBase
{
    public static ulong Mul(uint* left, uint* right, uint* result, int length)
    {
#if NET7_0_OR_GREATER
        //return (ulong)Mul128((ulong*)left, (ulong*)right, (ulong*)result, length / 2);
#endif

#if BENCH
        BenchStopwatch.Start();
#endif

#if false
        for (var i = 0; i < length; i++)
            result[i] = 0;

        var overflow = 0ul;
        for (var i = 0; i < length; i++)
        {
            if (right[i] == 0)
                continue;

            var v = 0ul;
            for (var j = 0; j < length - i; j++)
            {
                v += (ulong)left[j] * right[i];
                v += result[i + j];
                result[i + j] = (uint)v;
                v >>= 32;
            }

            overflow += v;
        }

        return overflow;

#else
        unchecked
        {
            var countR = 0;
            var lastNonZero = 0;
            for (var i = 0; i < length; i++)
            {
                if (left[i] != 0)
                    lastNonZero = i;

                if (right[i] != 0)
                    countR++;

                result[i] = 0;
            }

            var resultEnd = &result[length];
            var floatResultEnd = &result[lastNonZero + 2];
            if (floatResultEnd > resultEnd)
                floatResultEnd = resultEnd;

            ulong v0;
            uint* l;
            uint* res;
            ulong yv;
            var overflow = 0ul;
            for (; countR != 0; result++, right++)
            {
                if (*right != 0)
                {
                    countR--;

                    yv = *right;
                    v0 = 0ul;
                    l = left;
                    res = result;

                    for (; res < floatResultEnd; l++, res++)
                    {
                        var t = *l * yv;
                        v0 = (v0 >> 32) + *res;
                        v0 = t + v0;
                        *res = (uint)v0;
                    }

                    overflow += v0 >> 32;
                }

                if (floatResultEnd < resultEnd)
                    floatResultEnd++;
            }

#if BENCH
            BenchStopwatch.Stop();
#endif
            return overflow;
        }
#endif
    }

#if NET7_0_OR_GREATER
    public static uint128 Mul128(uint* left, uint* right, uint* result, int length)
        => Mul128((ulong*)left, (ulong*)right, (ulong*)result, length >> 1);

    public static uint128 Mul128(ulong* left, ulong* right, ulong* result, int length)
    {
#if BENCH
        BenchStopwatch.Start();
#endif

        unchecked
        {
            var countR = 0;
            var lastNonZero = 0;
            for (var i = 0; i < length; i++)
            {
                if (left[i] != 0)
                    lastNonZero = i;

                if (right[i] != 0)
                    countR++;

                result[i] = 0;
            }

            var resultEnd = &result[length];
            var floatResultEnd = &result[Math.Min(length, lastNonZero + 2)];
            uint128 v;
            ulong* l;
            ulong* res;
            uint128 yv;
            uint128 overflow = 0;
            for (var i = 0; countR != 0; i++, right++)
            {
                if (*right != 0)
                {
                    yv = *right;
                    v = 0ul;
                    l = left;
                    res = &result[i];

                    for (; res < floatResultEnd; l++, res++)
                    {
                        v += new uint128(0, *l) * yv;
                        v += *res;
                        *res = (ulong)v;
                        v >>= 64;
                    }

                    overflow += v;

                    countR--;
                }

                if (floatResultEnd < resultEnd)
                    floatResultEnd++;
            }

#if BENCH
            BenchStopwatch.Stop();
#endif

            return overflow;
        }
    }
#endif

    public static ulong Mul(uint* left, uint right, uint* result, int length)
    {
        unchecked
        {
            var resultEnd = &result[length];

            ulong o = 0ul;
            uint* l = left;
            ulong v;

            for (; result < resultEnd; l++, result++)
            {
                v = (ulong)*l * right;
                v += o;
                o = v >> 32;
                *result = (uint)v;
            }

            return o;
        }
    }

    public static ulong Sqr(uint* x, uint* result, int length)
    {
        unchecked
        {
            Zero(result, length);

            var overflow = 0ul;
            ulong o;
            uint* l;
            uint* res;
            ulong yv;
            ulong v;

            var resultEnd = &result[length];

            while (length > 0 && x[length - 1] == 0)
                length--;

            var floatResultEnd = &result[length + 1];
            if (floatResultEnd > resultEnd)
                floatResultEnd--;

            for (var i = 0; i < length; i++)
            {
                if (floatResultEnd < resultEnd)
                    floatResultEnd++;

                if (x[i] != 0)
                {
                    l = &x[i];
                    yv = l[0];

                    res = &result[i << 1];

                    v = yv * yv;

                    if (res >= resultEnd)
                    {
                        overflow += v;
                        break;
                    }

                    v += *res;
                    *res = (uint)v;
                    o = v >> 32;

                    res++;
                    l++;

                    for (; res < floatResultEnd; l++, res++)
                    {
                        v = *l * yv;
                        o = *res + o;
                        *res = (uint)((v << 1) + o);
                        o = (v + (o >> 1)) >> 31;
                    }

                    overflow += o;
                }
            }

            return overflow;
        }
    }

    public static uint Add(uint* left, uint* right, uint* result, int length)
    {
        var o = 0u;
        var v = 0ul;
        for (var i = 0; i < length; i++)
        {
            v = (ulong)left[i] + right[i] + o;
            result[i] = (uint)v;
            o = (uint)(v >> 32);
        }

        return o;
    }

    public static uint Add(uint* left, uint right, uint* result, int length)
    {
        var o = right;
        for (var i = 0; i < length && o != 0; i++)
        {
            var v = (ulong)left[i] + o;
            result[i] = (uint)v;
            o = (uint)(v >> 32);
        }

        return o;
    }

    public static int Sub(uint* left, uint* right, uint* result, int length)
    {
        var o = 0L;
        for (var i = 0; i < length; i++)
        {
            var v = left[i] - (long)right[i] + o;
            result[i] = (uint)v;
            o = v >> 32;
        }

        return (int)o;
    }

    public static int Sub(uint* left, uint right, uint* result, int length)
    {
        var o = 0L;
        var v = left[0] - (long)right;
        result[0] = (uint)v;
        o = v >> 32;
        for (var i = 1; o != 0 && i < length; i++)
        {
            v = left[i] + o;
            result[i] = (uint)v;
            o = v >> 32;
        }

        return (int)o;
    }

    [SkipLocalsInit]
    public static void DivMod(uint* left, uint* right, uint* result, int length)
    {
        if (length == 1)
        {
            var sd = left[0] / right[0];
            if (result != null)
                result[0] = sd;
            left[0] -= right[0] * sd;
            return;
        }

        if (result != null)
            Zero(result, length);

        var topX = length - 1;
        var topY = topX >> 1;
        while (topY >= 0 && ((ulong*)right)[topY] == 0)
            topY--;
        topY = topY * 2 + 1;

        while (topY >= 0 && right[topY] == 0)
            topY--;

        if (topY < 0)
            return;

        var r = (ulong)right[topY];
        var r1 = r + 1;

        ulong l, d, o;
        int tTopX, delta, count;
        var sub = stackalloc uint[length];

        for (; ; )
        {
            while (topX >= 0 && left[topX] == 0)
                topX--;

            if (topX < topY)
                break;

            tTopX = topX;
            l = left[tTopX];
            if (tTopX > topY)
                l = l << 32 | left[--tTopX];

            d = l / r1;
            if (d == 0)
            {
                if (l >= r)
                    d = 1; // last iteration
                else
                    return;
            }


            delta = tTopX - topY;
            int lmd = length - delta;
            count = topY + 2; // for overflow
            if (count > lmd)
                count = lmd;

            for (; ; )
            {
                o = 0ul;
                {
                    for (var i = 0; i < count; i++)
                    {
                        o += right[i] * d;
                        sub[i] = (uint)o;
                        o >>= 32;
                    }
                }

                if (Sub(left + delta, sub, left + delta, lmd) != 0)
                {
                    Add(left + delta, sub, left + delta, lmd);
                    d >>= 1;
                    if (d == 0) // last iteration
                        return;
                }
                else
                {
                    if (result != null)
                    {
                        o = result[delta] + d;
                        result[delta] = (uint)o;
                        o >>= 32;
                        for (var i = delta + 1; o != 0 && i < length; i++)
                        {
                            o += result[i];
                            result[i] = (uint)o;
                            o >>= 32;
                        }
                    }

                    break;
                }
            }
        }
    }

#if BENCH
    public readonly static System.Diagnostics.Stopwatch BenchStopwatch = new System.Diagnostics.Stopwatch();
#endif

    internal static InversedModData ComputeInversedModData(uint[] mod)
    {
        int length = mod.Length;

        var topY = -1;
        for (var i = 0; i < length; i++)
        {
            if (mod[i] != 0)
                topY = i;
        }

        var modLen = topY + 1;

        var alignedMod = new uint[length];
        var alModMul = (uint)(1ul << (31 - NumberTools.IntLog(mod[topY])));
        fixed (uint* almod = alignedMod)
        fixed (uint* m = mod)
            Mul(m, alModMul, almod, length);

        int baseRemLen;

        var baseRem = new uint[modLen];

        var j = 0;
        for (; alignedMod[j] == 0 && j < length; j++)
        {
            baseRem[j] = 0;
        }

        baseRemLen = j;
        baseRem[j] = (uint)-alignedMod[j];
        j++;

        for (; j < modLen; j++)
        {
            baseRem[j] = ~alignedMod[j];
            if (alignedMod[j] != uint.MaxValue)
                baseRemLen = j;
        }

        var result = new InversedModData
        {
            InvMod = baseRem,
            InvModLen = baseRemLen + 1,
            ModLen = modLen,
            AlignedMod = alignedMod,
        };

        result.Is256k1 = result.InvModLen == 2 && result.InvMod[1] == 1;
        result.Is256r1 = result.InvModLen == 7
            && result.InvMod[0] == 1
            && result.InvMod[3] == uint.MaxValue
            && result.InvMod[4] == uint.MaxValue
            && result.InvMod[5] == uint.MaxValue
            && result.InvMod[6] == uint.MaxValue - 1;

        return result;
    }

    public static void Reduce(uint* left, int length, in InversedModData inversedMod)
    {
        var leftTop = &left[inversedMod.ModLen];
        var leftTopSize = length - inversedMod.ModLen;

        if (inversedMod.Is256r1)
        {
            reduce256r1(left, leftTop, leftTopSize);
            return;
        }

        if (inversedMod.Is256k1)
        {
            reduce256k1(left, length, inversedMod.InvMod, leftTop, leftTopSize);
            return;
        }

        reduceGeneric(left, length, inversedMod, leftTop, leftTopSize);
    }

    private static void reduceGeneric(uint* left, int length, InversedModData inversedMod, uint* leftTop, int leftTopSize)
    {
        fixed (uint* fixInvMod = inversedMod.InvMod)
        {
            var i = leftTopSize - 1;
            var s = (uint)-(inversedMod.InvModLen << 16);
            while (i >= 0)
            {
                var v = leftTop[i];

                if (v == 0)
                {
                    i--;
                    continue;
                }

                leftTop[i] = 0;

                var o = 0ul;
                var j = s;
                var dst = left + i;
                if (v != 1)
                {
#if false
                    while (true)
                    {
                        var t0 = *(ulong*)&fixInvMod[(ushort)j];
                        var t2 = *(ulong*)&dst[(ushort)j];
                        var t1 = t0 >> 32;
                        t0 = (uint)t0;

                        o += (uint)t2;

                        t0 *= (ulong)v;
                        t1 *= (ulong)v;

                        t0 += o;
                        t1 += t2 >> 32;
                        t1 += t0 >> 32;

                        if (j < 0xfffdffff)
                        {
                            *(ulong*)&dst[(ushort)j] = (uint)t0 | (t1 << 32);
                            o = t1 >> 32;
                            j += 0x20002;
                        }
                        else
                        {
                            dst[(ushort)j] = (uint)t0;
                            o = t0 >> 32;
                            j += 0x10001;
                            break;
                        }
                    }
#else
                    for (; j > 0xffff; j += 0x10001)
                    {
                        var sj = (ushort)j;
                        o += fixInvMod[sj] * (ulong)v;
                        o += dst[sj];
                        dst[sj] = (uint)o;
                        o >>= 32;
                    }
#endif
                }
                else
                {
                    for (; j > 0xffff; j += 0x10001)
                    {
                        var sj = (ushort)j;
                        o += fixInvMod[sj];
                        o += dst[sj];
                        dst[sj] = (uint)o;
                        o >>= 32;
                    }
                }

                while (o != 0 && j < length)
                {
                    o += dst[(ushort)j];
                    dst[(ushort)j] = (uint)o;
                    o >>= 32;
                    j++;
                }
            }
        }
    }

    private static void reduce256r1(uint* left, uint* leftTop, int leftTopSize)
    {
        ulong overflow = 0;
        ulong t = 0;
        ulong v = 0;
        uint* dst;
        leftTopSize--;
        while (leftTopSize >= 0)
        {
            v = leftTop[leftTopSize];

            if (v == 0)
            {
                leftTopSize--;
                continue;
            }

            var vf = (v << 32) - v;

            leftTop[leftTopSize] = 0;

            dst = left + leftTopSize;

            overflow = dst[0];
            overflow += v;
            t = overflow;
            dst[0] = (uint)t;
            overflow >>= 32;

            overflow += dst[1];
            t = overflow;
            dst[1] = (uint)t;
            overflow >>= 32;
            dst++;
            dst++;

            overflow += dst[0];
            t = overflow;
            dst[0] = (uint)t;
            overflow >>= 32;

            overflow += vf;
            overflow += dst[1];
            t = overflow;
            dst[1] = (uint)t;
            overflow >>= 32;
            dst++;
            dst++;

            overflow += vf;
            overflow += dst[0];
            t = overflow;
            dst[0] = (uint)t;
            overflow >>= 32;
            dst++;

            overflow += vf;
            overflow += *dst;
            t = overflow;
            *dst = (uint)t;
            overflow >>= 32;
            dst++;

            overflow += vf - v;
            overflow += dst[0];
            t = overflow;
            dst[0] = (uint)t;
            overflow >>= 32;
            dst++;

            overflow += dst[0];
            t = overflow;
            dst[0] = (uint)t;

            t = overflow >> 32;
            dst[1] = (uint)t;
        }
    }

    private static void reduce256k1(uint* left, int length, uint[] invMod, uint* leftTop, int leftTopSize)
    {
        var bm = invMod[0];
        for (var i = 0; i < 2; i++)
        {
            var o = 0ul;
            var j = 0;
            for (; j < leftTopSize; j++)
            {
                ulong ltj = leftTop[j];
                leftTop[j] = 0;

                if (ltj == 0 && o == 0)
                    continue;

                var v = ltj * bm;
                o += left[j] + v;
                left[j] = (uint)o;
                o >>= 32;
                o += ltj;
            }

            for (; o != 0 && j < length; j++)
            {
                o += left[j];
                left[j] = (uint)o;
                o >>= 32;
            }

            leftTopSize = j - leftTopSize;
        }

        return;
    }

    [SkipLocalsInit]
    public static void Mod(uint* left, uint* mod, int length)
    {

        if (length == 1)
        {
            left[0] = left[0] % mod[0];
            return;
        }

#if BENCH
        //BenchStopwatch.Start();
#endif

        var topX = -1;
        var topY = -1;
        for (var i = 0; i < length; i++)
        {
            if (left[i] != 0)
                topX = i;

            if (mod[i] != 0)
                topY = i;
        }

        if (topX == -1 || topY == -1)
            return;

        if (topX < topY || (topX == topY && left[topX] < mod[topY]))
            return;

        var modLen = topY + 1;

        var baseRem = stackalloc uint[modLen];
        var baseRemLen = 0;

        {
            var i = 0;
            for (; mod[i] == 0 && i < length; i++)
            {
                baseRem[i] = 0;
            }

            baseRemLen = i;
            baseRem[i] = (uint)-mod[i];
            i++;

            for (; i < modLen; i++)
            {
                baseRem[i] = ~mod[i];
                if (mod[i] != uint.MaxValue)
                    baseRemLen = i;
            }
        }

        var leftTop = &left[modLen];
        var leftTopSize = length - modLen;

        baseRemLen++;

        if ((mod[topY] & 0x8000_0000) == 0 || baseRemLen == modLen)
        {
            DivMod(left, mod, null, length);
            return;
        }

        unchecked
        {
            var longMul = baseRemLen == 1;
            longMul |= baseRemLen == 2 && baseRem[1] == 1;

            if (longMul)
            {
                var bm = ((ulong*)baseRem)[0];
                var masked = bm & uint.MaxValue;
                for (var i = 0; i < baseRemLen; i++)
                {
                    var o = 0ul;
                    var t = left;
                    var j = 0;
                    for (; j < leftTopSize; j++, t++)
                    {
                        if (leftTop[j] == 0 && o == 0)
                            continue;

                        var v = leftTop[j] * masked;

                        o += *t + v;
                        *t = (uint)o;
                        o >>= 32;
                        o += leftTop[j];
                        leftTop[j] = 0;
                    }

                    for (; o != 0 && j < length; j++, t++)
                    {
                        o += *t;
                        *t = (uint)o;
                        o >>= 32;
                    }
                }
            }
            else
            {
                ulong ltv = 0ul;
                var start = leftTopSize - 1;
                for (var i = start; i >= 0;)
                {
                    ltv = leftTop[i];
                    if (ltv == 0)
                    {
                        i--;
                        continue;
                    }

                    leftTop[i] = 0;

                    var o = 0ul;
                    var dst = &left[i];
                    var j = 0;
                    for (; j < baseRemLen; j++, dst++)
                    {
                        o += *dst + baseRem[j] * ltv;
                        *dst = (uint)o;
                        o >>= 32;
                    }

                    while (o != 0 && j < length - i)
                    {
                        o += *dst;
                        *dst = (uint)o;
                        o >>= 32;
                        j++;
                        dst++;
                    }
                }
            }

            if (Cmp(left, mod, modLen + 1) >= 0)
                Sub(left, mod, left, modLen + 1);

#if BENCH
        //BenchStopwatch.Stop();
#endif
        }
    }

    //[SkipLocalsInit]
    public static void ModInverse(uint* x, uint* mod, uint* result, int length)
    {
        if (length == 0)
            return;

        var temp = stackalloc uint[length];

        var a = x;
        var b = mod;

        var d = stackalloc uint[length];
        var r = stackalloc uint[length];

        var pv = stackalloc uint[length];
        var pf = result;

        var mv = stackalloc uint[length];
        var mf = stackalloc uint[length];

        Move(b, r, length);
        DivMod(r, a, d, length);

        if (IsZero(r, length))
        {
            Move(d, pf, length);
            return;
        }

        Move(a, pv, length);
        Zero(pf, length);
        pf[0] = 1;

        Move(r, mv, length);
        Move(d, mf, length);

        var sw = false;

        var i = 0;

        var len = length;

        while (!IsZero(pv + 1, length - 1) || pv[0] != 1) // pv != 1
        {
            i++;

            while (len > 0
                && mv[len - 1] == 0
                && pv[len - 1] == 0
                && r[len - 1] == 0)
                len--;

            // d = (pv / mv) | 0;
            // r = pv - mv * d;

            // Move(pv, r, length);
            var t = pv;
            pv = r;
            r = t;

            DivMod(r, mv, d, len);

            if (IsZero(r, len))
            {
                if (!sw)
                {
                    // pf = pf + mf * (d - 1);
                    AddInt(d, -1, length);
                    Mul(mf, d, temp, length);
                    Add(pf, temp, pf, length);
                }

                break;
            }

            // pf = pf + mf * d
            Mul(mf, d, temp, length);
            Add(pf, temp, pf, length);

            Move(r, pv, len);

            Add(mf, pf, mf, length);
            Sub(mv, r, mv, len);

            if (Cmp(mv, pv, len) > 0)
            {
                sw ^= true;

                t = pv;
                pv = mv;
                mv = r;
                r = t;

                t = pf;
                pf = mf;
                mf = t;
            }
        }
    }

    public static uint AddInt(uint* number, int v, int length)
    {
        var longs = (ulong*)number;
        var i = 0;
        var hLen = length >> 1;
        var o = (ulong)v;
        for (; o != 0 && i < hLen; i++, longs++)
        {
            var l = *longs;
            l += o;
            o = (*longs & ~l) >> 63;
            *longs = l;
        }

        if (o != 0)
        {
            i <<= 1;
            if (i < length)
            {
                o += number[i];
                number[i] += (uint)o;
                o >>= 32;
            }
        }

        return (uint)o;
    }

    public static void Zero(uint* value, int length)
    {
        var longs = (ulong*)value;
        var i = 0;
        var hLen = length >> 1;
        for (; i < hLen; i++, longs++)
            *longs = 0;

        i <<= 1;
        if (i < length)
            value[i] = 0;
    }

    public static bool IsZero(uint* value, int length)
    {
        var longs = (ulong*)value;
        var i = 0;
        var hLen = length >> 1;
        for (; i < hLen; i++, longs++)
        {
            if (*longs != 0)
                return false;
        }

        i <<= 1;
        if (i < length && value[i] != 0)
            return false;

        return true;
    }

    public static void Move(uint* src, uint* target, int length)
    {
        for (var end = target + length; target != end; target++, src++)
            *target = *src;
    }

    [SkipLocalsInit]
    public static void ModPow(uint* x, uint* power, uint* mod, uint* result, int length)
    {
        var temp0 = stackalloc uint[length];
        var thirdDegree = stackalloc uint[length];
        var sevenDegree = stackalloc uint[length];
        var sixteenDegree = stackalloc uint[length];

        Mul(x, x, temp0, length);
        DivMod(temp0, mod, null, length);
        Mul(temp0, x, thirdDegree, length);
        DivMod(thirdDegree, mod, null, length);

        Mul(thirdDegree, thirdDegree, temp0, length);
        DivMod(temp0, mod, null, length);
        Mul(x, temp0, sevenDegree, length);
        DivMod(sevenDegree, mod, null, length);

        Mul(sevenDegree, sevenDegree, temp0, length);
        DivMod(temp0, mod, null, length);
        Mul(temp0, x, sixteenDegree, length);
        DivMod(sixteenDegree, mod, null, length);

        Zero(temp0, length);
        Zero(result, length);
        temp0[0] = 1;
        result[0] = 1;

        var compute = false;
        var swapResult = false;
        var mulDegreeIndex = 0;
        var skip = 0;

        for (var i = length; i-- > 0;)
        {
            var v = power[i];
            if (v == 0 && !compute)
                continue;

            for (var j = 0; j < 32; j++)
            {
                uint* t;
                if (compute)
                {
                    Mul(temp0, temp0, result, length);
                    DivMod(result, mod, null, length);
                    t = result;
                    result = temp0;
                    temp0 = t;
                    swapResult ^= true;
                }

                if (--skip <= 0 && (v & 0x8000_0000) != 0)
                {
                    if (mulDegreeIndex == 0 && (v & 0xc000_0000) == 0xc000_0000)
                    {
                        if ((v & 0xf000_0000) == 0xf000_0000)
                        {
                            // 16
                            mulDegreeIndex = 3;
                            skip = 3;
                        }
                        else if ((v & 0xe000_0000) == 0xe000_0000)
                        {
                            // 7
                            mulDegreeIndex = 2;
                            skip = 2;
                        }
                        else
                        {
                            // 3
                            mulDegreeIndex = 1;
                            skip = 1;
                        }
                    }
                    else
                    {
                        if (mulDegreeIndex == 1)
                        {
                            Mul(temp0, thirdDegree, result, length);
                        }
                        else if (mulDegreeIndex == 2)
                        {
                            Mul(temp0, sevenDegree, result, length);
                        }
                        else if (mulDegreeIndex == 3)
                        {
                            Mul(temp0, sixteenDegree, result, length);
                        }
                        else
                            Mul(temp0, x, result, length);

                        DivMod(result, mod, null, length);
                        t = result;
                        result = temp0;
                        temp0 = t;
                        swapResult ^= true;
                        compute = true;
                        mulDegreeIndex = 0;
                    }
                }

                v <<= 1;
            }
        }

        if (!swapResult)
        {
            for (var i = 0; i < length; i++)
            {
                result[i] = temp0[i];
            }
        }
    }

    public static int IntLog(uint* uints, int intsCount)
    {
        for (var i = intsCount; i-- > 0;)
        {
            if (uints[i] != 0)
            {
                return (i << 5) + NumberTools.IntLog(uints[i]);
            }
        }

        return 0;
    }

    public static void Shift(uint* left, int shift, uint* result, int length)
    {
        if (shift == 0)
        {
            while (length-- > 0)
                result[length] = left[length];

            return;
        }

        var indexShift = shift / 32;
        if (indexShift <= -length || indexShift >= length)
            return;

        var bitShift = Math.Abs(shift) % 32;
        int invBitShift = 32 - bitShift;

        var start = Math.Max(0, -indexShift);
        var end = Math.Min(length, length - indexShift) - 1;
        var s = Math.Sign(-shift) | 1;
        if (s < 0)
        {
            start ^= end;
            end ^= start;
            start ^= end;
        }

        end += s;
        for (var i = start; i != end; i += s)
        {
            var v = left[i];
            var si = i + indexShift;
            if (bitShift != 0)
            {
                if (shift > 0)
                {
                    result[si] = v << bitShift;

                    if (++si < length)
                    {
                        result[si] |= v >> invBitShift;
                    }
                }
                else
                {
                    result[si] = v >> bitShift;

                    if (--si >= 0)
                        result[si] |= v << invBitShift;
                }
            }
            else
            {
                result[si] = v;
            }
        }

        if (indexShift < 0)
        {
            for (var i = length + indexShift; i < length; i++)
                result[i] = 0;
        }
        else
        {
            for (var i = 0; i < Math.Min(indexShift, length); i++)
                result[i] = 0;
        }
    }

    internal static void NumStrSum(ulong[] left, ulong[] rigth, ref ulong[] output)
    {
        const ulong _mask8 = 0x8888_8888_8888_8888;
        var leftLen = left.Length;
        int rightLen = rigth.Length;
        var len = Math.Max(leftLen, rightLen);
        if (output.Length < len)
            output = new ulong[len];

        var go = 0u;
        for (var i = 0; i < output.Length; i++)
        {
            var l = i < leftLen ? left[i] : 0;
            var r = i < rightLen ? rigth[i] : 0;

            l += go;
            go = 0;

            var el = l;
            l += r;
            var o = ((el | r) & ~l & _mask8) >> 3;
            l += o * 6;
            r = l;
            go |= (uint)(o >> 60);
            for (; ; )
            {
                o = ((l & _mask8) >> 2) & (l >> 1 | l);
                if (o == 0)
                    break;

                l += o * 3;
            }

            go |= (uint)((r & ~l) >> 63);

            output[i] = l;

            if (go != 0 && i + 1 == output.Length)
                Array.Resize(ref output, output.Length * 2);
        }
    }

    public static string FormatStr(string format, uint* x, int length)
    {
        var formatId = format.Length == 0 ? 'g' : format[0];
        switch (char.ToLower(formatId))
        {
            case 'g':
            {
                var curDeg = 0;
                var curBit = 0;
                var str = new ulong[] { 1 };
                var res = new ulong[] { 0 };
                for (var i = 0; i < length; i++)
                {
                    var v = x[i];
                    if (v == 0)
                        curBit += 32;
                    else
                    {
                        for (var b = 0; b < 32; b++, curBit++)
                        {
                            if ((v & 1) != 0)
                            {
                                while (curDeg < curBit)
                                {
                                    NumStrSum(str, str, ref str);
                                    curDeg++;
                                }

                                NumStrSum(res, str, ref res);
                            }

                            v >>= 1;
                        }
                    }
                }

                if (res.Length == 0 || (res.Length == 1 && res[0] is 0))
                    return "0";

                Array.Reverse(res);
                return string.Concat(res.SkipWhile(x => x is 0).Select((x, i) => x.ToString(i == 0 ? "X1" : "X16", CultureInfo.InvariantCulture)));
            }

            case 'x':
            {
                var align = format.Length <= 1 ? 1 : int.Parse(format.Substring(1));
                var fid = formatId.ToString();
                var result = new StringBuilder(length * 8);
                var b = (byte*)x;
                var print = false;
                for (var i = length * 4; i-- > 0;)
                {
                    if (print || b[i] != 0 || (i + 1) * 2 <= align)
                    {
                        if (b[i] < 16 && (print || align >= (i + 1) * 2))
                            result.Append('0');

                        result.Append(b[i].ToString(fid));

                        print = true;
                    }
                }

                if (result.Length == 0)
                    return "".PadLeft(align, '0');

                return result.ToString();
            }

            default: throw new NotImplementedException();
        }
    }

    internal static void ParseHex(string hex, byte* bytes, int length)
    {
        for (var i = 0; i < hex.Length && i >> 3 < length; i++)
        {
            var v = hexCharToInt(hex[hex.Length - i - 1]);
            bytes[i >> 1] |= (byte)(v << 4 * (i & 1));
        }
    }

    private static int hexCharToInt(char p)
    {
        return (p % 'a' % 'A' + 10) % ('0' + 10);
    }

    public static int Cmp(uint* left, uint* right, int length)
    {
        for (var i = length; i-- > 0;)
        {
            var c = (long)left[i] - right[i];
            if (c != 0)
                return Math.Sign(c);
        }

        return 0;
    }
}
