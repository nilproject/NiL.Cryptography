using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NiL.Cryptography.Hashing;

public sealed class Sha1 : IHashFunction
{
    public static readonly Sha1 Instance = new Sha1();
    private Sha1() { }

    public unsafe struct FixedUint32Array
    {
        private const int _len = 5;

        private fixed uint _data[_len];

        public int Length => _len;

        public uint this[int index]
        {
            get
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                return _data[index];
            }

            set
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                _data[index] = value;
            }
        }
    }

    public unsafe struct FixedByteArray
    {
        private const int _len = 20;

        private fixed byte _data[_len];

        public int Length => _len;

        public byte this[int index]
        {
            get
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                return _data[index ^ 3]; // big endian
            }

            set
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                _data[index ^ 3] = value;
            }
        }
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct Result
    {
        [FieldOffset(0)]
        public readonly FixedUint32Array AsUint32;

        [FieldOffset(0)]
        public readonly FixedByteArray AsBytes;

        internal Result(uint x0, uint x1, uint x2, uint x3, uint x4) : this()
        {
            AsUint32[0] = x0;
            AsUint32[1] = x1;
            AsUint32[2] = x2;
            AsUint32[3] = x3;
            AsUint32[4] = x4;
        }

        public byte[] ToByteArray()
        {
            var result = new byte[AsBytes.Length];
            for (var i = 0; i < AsBytes.Length; i++)
                result[i] = AsBytes[i];

            return result;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint shl(int bits, uint x) => x << bits | x >> sizeof(uint) * 8 - bits;

    private static uint f0(uint m, uint l, uint k) => m & l | ~m & k;
    private static uint k0 = 0x5A827999;

    private static uint f1(uint m, uint l, uint k) => m ^ l ^ k;
    private static uint k1 = 0x6ED9EBA1;

    private static uint f2(uint m, uint l, uint k) => m & l | m & k | l & k;
    private static uint k2 = 0x8F1BBCDC;

    private static uint f3(uint m, uint l, uint k) => m ^ l ^ k;
    private static uint k3 = 0xCA62C1D6;

    public int BlockSize => 64;

    public int DigestSize => 20;

    byte[] IHashFunction.Compute(in ReadOnlySpan<byte> data)
    {
        var digest = Compute(data);
        var result = new byte[digest.AsBytes.Length];
        for (var i = 0; i < digest.AsBytes.Length; i++)
        {
            result[i] = digest.AsBytes[i];
        }

        return result;
    }

    public static Result Compute(in ReadOnlySpan<byte> message)
    {
        var dataBitLength = message.Length * 8 + 1;
        dataBitLength += (512 + (448 - dataBitLength % 512)) % 512;
        dataBitLength += 64;

        var m = new uint[dataBitLength / (8 * sizeof(uint))];

        for (var i = 0; i < message.Length; i++)
        {
            m[i >> 2] |= (uint)(message[i] << ((i & 3) ^ 3) * 8);
        }

        var srcBitLen = (ulong)message.Length * 8UL;
        m[message.Length >> 2] |= (uint)(1 << ((4 - (message.Length & 3)) * 8 - 1));
        m[m.Length - 2] = (uint)(srcBitLen >> 32);
        m[m.Length - 1] = (uint)(srcBitLen);

        uint h0 = 0x67452301u;
        uint h1 = 0xEFCDAB89u;
        uint h2 = 0x98BADCFEu;
        uint h3 = 0x10325476u;
        uint h4 = 0xC3D2E1F0u;

        const int rounds = 80;
        var w = new uint[rounds];

        for (var i = 0; i < m.Length / 16; i++)
        {
            var a = h0;
            var b = h1;
            var c = h2;
            var d = h3;
            var e = h4;

            for (var j = 0; j < 20; j++)
            {
                if (j < 16)
                    w[j] = m[j + i * 16];
                else
                    w[j] = shl(1, w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]);

                var t = f0(b, c, d) + k0;
                t += shl(5, a) + e + w[j];

                e = d;
                d = c;
                c = shl(30, b);
                b = a;
                a = t;
            }

            for (var j = 20; j < 40; j++)
            {
                w[j] = shl(1, w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]);

                var t = f1(b, c, d) + k1;
                t += shl(5, a) + e + w[j];

                e = d;
                d = c;
                c = shl(30, b);
                b = a;
                a = t;
            }

            for (var j = 40; j < 60; j++)
            {
                w[j] = shl(1, w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]);

                var t = f2(b, c, d) + k2;
                t += shl(5, a) + e + w[j];

                e = d;
                d = c;
                c = shl(30, b);
                b = a;
                a = t;
            }

            for (var j = 60; j < 80; j++)
            {
                w[j] = shl(1, w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16]);

                var t = f3(b, c, d) + k3;
                t += shl(5, a) + e + w[j];

                e = d;
                d = c;
                c = shl(30, b);
                b = a;
                a = t;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
        }

        return new Result(h0, h1, h2, h3, h4);
    }
}
