using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace NiL.Cryptography.Numerics;

internal interface IBigUIntInternal
{
    uint[] GetRawBuffer();
}

public interface IBigUInt
{
    int Size { get; }

    public static IBigUInt FromBytes(int numberSize, scoped in ReadOnlySpan<byte> bytes, bool bigEndian = false)
    {
        if (numberSize == B128.Size) return BigUInt<B128>.FromBytes(bytes, bigEndian);
        if (numberSize == B256.Size) return BigUInt<B256>.FromBytes(bytes, bigEndian);
        if (numberSize == B512.Size) return BigUInt<B512>.FromBytes(bytes, bigEndian);
        throw new NotImplementedException(nameof(FromBytes) + " for " + numberSize + " bits");
    }

    int MostSignificantBitIndex();

    byte[] ToBytes(int maxLength = int.MaxValue, bool bigEndian = false);
    void ToBytes(byte[] target, int startIndex = 0, int maxLength = int.MaxValue, bool bigEndian = false);

    IBigUInt ModInverse(IBigUInt mod);
    public static IBigUInt operator >>(IBigUInt x, int s) => x.ShiftRight(s);
    public static IBigUInt operator %(IBigUInt x, IBigUInt y) => x.Mod(y);
    public static IBigUInt operator *(IBigUInt x, IBigUInt y) => x.Multiply(y);
    public static IBigUInt operator +(IBigUInt x, IBigUInt y) => x.Add(y);

    bool Equals(uint other);

    IBigUInt Add(IBigUInt y);
    IBigUInt Multiply(IBigUInt y);
    IBigUInt Mod(IBigUInt y);
    IBigUInt ShiftRight(int shift);

    string ToString(string format);
}

public unsafe struct BigUInt<TSize> : IBigUInt, IBigUIntInternal where TSize : INumberSize
{
    private static readonly int _intsCount = TSize.Size / 32;

    private uint[] _uints;

    public int Size => TSize.Size;

    public BigUInt(uint x)
    {
        _uints = new uint[_intsCount];
        _uints[0] = x;
    }

    public BigUInt(ulong x)
    {
        _uints = new uint[_intsCount];
        _uints[0] = (uint)x;
        _uints[1] = (uint)(x >> 32);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public int BitAt(int n)
    {
        return (int)(_uints[n >> 5] >> (n & 0x1f) & 1);
    }

    public static implicit operator BigUInt<TSize>(uint x)
    {
        return new BigUInt<TSize>(x);
    }

    public static implicit operator BigUInt<TSize>(ulong x)
    {
        return new BigUInt<TSize>(x);
    }

    IBigUInt IBigUInt.Multiply(IBigUInt y) => this * (BigUInt<TSize>)y;

    public static BigUInt<TSize> operator *(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == null || y._uints == null)
            return 0;

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* yInts = y._uints)
        fixed (uint* rInts = result._uints)
        {
            if (NumericsBase.Mul(xInts, yInts, rInts, _intsCount) != 0)
                throw new OverflowException();

            return result;
        }
    }
    IBigUInt IBigUInt.Add(IBigUInt y) => this + (BigUInt<TSize>)y;

    public static BigUInt<TSize> operator +(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == null)
            return y;

        if (y._uints == null)
            return x;

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* yInts = y._uints)
        fixed (uint* rInts = result._uints)
        {
            NumericsBase.Add(xInts, yInts, rInts, _intsCount);

            return result;
        }
    }

    public static BigUInt<TSize> operator -(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (y._uints == null)
            return x;

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* yInts = y._uints)
        fixed (uint* rInts = result._uints)
        {
            NumericsBase.Sub(xInts, yInts, rInts, _intsCount);

            return result;
        }
    }

    public static BigUInt<TSize> operator /(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == null)
            return 0;

        if (y._uints == null)
            throw new DivideByZeroException();

        var mod = stackalloc uint[_intsCount];
        for (var i = 0; i < _intsCount; i++)
            mod[i] = x._uints[i];

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* yInts = y._uints)
        fixed (uint* rInts = result._uints)
        {
            NumericsBase.DivMod(mod, yInts, rInts, _intsCount);

            return result;
        }
    }

    public static BigUInt<TSize> operator %(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == null)
            return 0;

        if (y._uints == null)
            throw new DivideByZeroException();

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* yInts = y._uints)
        fixed (uint* rInts = result._uints)
        {
            NumericsBase.Move(xInts, rInts, _intsCount);

            NumericsBase.Mod(rInts, yInts, _intsCount);

            return result;
        }
    }

    public static BigUInt<TSize> operator <<(BigUInt<TSize> x, int s)
    {
        if (x._uints == null)
            return 0;

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* rInts = result._uints)
        {
            NumericsBase.Shift(xInts, s, rInts, _intsCount);

            return result;
        }
    }

    public static BigUInt<TSize> operator >>(BigUInt<TSize> x, int s)
    {
        if (x._uints == null)
            return 0;

        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* rInts = result._uints)
        {
            NumericsBase.Shift(xInts, -s, rInts, _intsCount);

            return result;
        }
    }

    public static bool operator ==(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == y._uints)
            return true;

        if (x._uints == null || y._uints == null)
            return false;

        for (var i = 0; i < _intsCount; i++)
        {
            if (x._uints[i] != y._uints[i])
                return false;
        }

        return true;
    }

    public static bool operator ==(BigUInt<TSize> x, uint y)
    {
        if (x._uints == null)
            return y == 0;

        if (x._uints[0] != y)
            return false;

        for (var i = 1; i < _intsCount; i++)
        {
            if (x._uints[i] != 0)
                return false;
        }

        return true;
    }

    public static bool operator ==(uint x, BigUInt<TSize> y)
    {
        return y == x;
    }

    public static bool operator !=(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        return !(x == y);
    }

    public static bool operator !=(BigUInt<TSize> x, uint y)
    {
        return !(x == y);
    }

    public static bool operator !=(uint x, BigUInt<TSize> y)
    {
        return !(x == y);
    }

    public static bool operator <(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == y._uints)
            return false;

        if (x._uints == null && y._uints != null)
            return true;

        if (x._uints != null && y._uints == null)
            return true;


        fixed (uint* xInts = x._uints)
        fixed (uint* yInts = y._uints)
            return NumericsBase.Cmp(xInts, yInts, _intsCount) < 0;
    }

    public static bool operator >(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        if (x._uints == y._uints)
            return false;

        if (x._uints == null && y._uints != null)
            return false;

        if (x._uints != null && y._uints == null)
            return true;

        fixed (uint* xInts = x._uints)
        fixed (uint* yInts = y._uints)
            return NumericsBase.Cmp(xInts, yInts, _intsCount) > 0;
    }

    public static bool operator >=(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        return !(x < y);
    }

    public static bool operator <=(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        return !(x > y);
    }

    public override string ToString()
    {
        fixed (uint* x = _uints)
            return NumericsBase.FormatStr("G", x, _intsCount);
    }

    public string ToString(string format)
    {
        fixed (uint* src = _uints)
            return NumericsBase.FormatStr(format, src, _intsCount);
    }

    public static BigUInt<TSize> ParseHex(string hex)
    {
        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* rInts = result._uints)
        {
            var bytes = (byte*)rInts;
            NumericsBase.ParseHex(hex, bytes, _intsCount);
        }

        return result;
    }

    public static BigUInt<TSize> ModPow(BigUInt<TSize> x, BigUInt<TSize> power, BigUInt<TSize> mod)
    {
        BigUInt<TSize> result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* pInts = power._uints)
        fixed (uint* rInts = result._uints)
        fixed (uint* mInts = mod._uints)
            NumericsBase.ModPow(xInts, pInts, mInts, rInts, _intsCount);

        return result;
    }

    IBigUInt IBigUInt.ModInverse(IBigUInt mod) => ModInverse(this, (BigUInt<TSize>)mod);

    public static BigUInt<TSize> ModInverse(BigUInt<TSize> x, BigUInt<TSize> mod)
    {
        BigUInt<TSize> result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* rInts = result._uints)
        fixed (uint* mInts = mod._uints)
            NumericsBase.ModInverse(xInts, mInts, rInts, _intsCount);

        return result;
    }

    public static BigUInt<TSize> Sqr(BigUInt<TSize> x)
    {
        var result = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* xInts = x._uints)
        fixed (uint* rInts = result._uints)
            NumericsBase.Sqr(xInts, rInts, _intsCount);

        return result;
    }

    public int MostSignificantBitIndex()
    {
        fixed (uint* xInts = &_uints[0])
            return NumericsBase.IntLog(xInts, _intsCount);
    }

    public static BigUInt<TSize> FromBytes(scoped in ReadOnlySpan<byte> x, bool bigEndian = false)
    {
        var r = new BigUInt<TSize> { _uints = new uint[_intsCount] };

        fixed (uint* ints = &r._uints[0])
        {
            var bytes = (byte*)ints;
            if (bigEndian)
            {
                for (var i = 0; i < x.Length; i++)
                    bytes[i] = x[x.Length - i - 1];
            }
            else
            {
                for (var i = 0; i < x.Length; i++)
                    bytes[i] = x[i];
            }
        }

        return r;
    }

    uint[] IBigUIntInternal.GetRawBuffer() => GetRawBuffer();

    internal uint[] GetRawBuffer() => _uints;

    public BigInteger ToBigInteger()
    {
        unsafe
        {
            fixed (uint* pData = _uints)
            {
                return new(new ReadOnlySpan<byte>(pData, _uints.Length * 4));
            }
        }
    }

    public byte[] ToBytes(int maxLength = int.MaxValue, bool bigEndian = false)
    {
        if (_uints == null)
            return [];

        var len = Math.Min(_intsCount * 4, maxLength);
        var result = new byte[len];

        ToBytes(result, 0, result.Length * 4, bigEndian);

        return result;
    }

    public void ToBytes(byte[] target, int startIndex = 0, int maxLength = int.MaxValue, bool bigEndian = false)
    {
        if (_uints == null)
        {
            for (var i = 0; i < maxLength; i++)
                target[i] = 0;
            return;
        }

        var len = Math.Min(maxLength, target.Length - startIndex);
        fixed (uint* ints = _uints)
        {
            var bytes = (byte*)ints;
            for (var i = len; i < _intsCount * 4; i++)
            {
                if (bytes[i] != 0)
                    throw new OverflowException();
            }

            var targetIndex = startIndex + (bigEndian ? len - 1 : 0);

            for (var i = 0; i < len; i++)
            {
                target[targetIndex] = bytes[i];
                if (bigEndian)
                    targetIndex--;
                else
                    targetIndex++;
            }
        }
    }

    public override bool Equals(object obj)
    {
        if (obj == null || !(obj is BigUInt<TSize> other))
        {
            return false;
        }

        return this == other;
    }

    public override int GetHashCode()
    {
        if (_uints == null)
            return 0;

        var result = 0u;
        for (var i = 0; i < _intsCount; i++)
        {
            result = result >> 3 ^ result * 21;
            result ^= _uints[i];
        }

        return (int)result;
    }

    IBigUInt IBigUInt.Mod(IBigUInt y)
    {
        return this % (BigUInt<TSize>)y;
    }

    IBigUInt IBigUInt.ShiftRight(int shift)
    {
        return this >> shift;
    }

    bool IBigUInt.Equals(uint other) => this == other;
}
