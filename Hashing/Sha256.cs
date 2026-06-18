using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NiL.Cryptography.Hashing;

public class Sha256 : IHashFunction
{
    public static readonly Sha256 Instance = new Sha256();
    private Sha256() { }

    public unsafe struct FixedUint32Array
    {
        private const int _len = 8;

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

    public unsafe struct FixedByteArray : IEnumerable<byte>
    {
        private const int _len = 32;

        private fixed byte _data[_len];

        public int Length => _len;

        public byte this[int index]
        {
            get
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                return _data[index ^ 3];
            }

            set
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                _data[index ^ 3] = value;
            }
        }

        public IEnumerator<byte> GetEnumerator()
        {
            for (var i = 0; i < _len; i++)
                yield return this[i];
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct Result
    {
        [FieldOffset(0)]
        public readonly FixedUint32Array AsUint32;

        [FieldOffset(0)]
        public readonly FixedByteArray AsBytes;

        internal Result(uint x0, uint x1, uint x2, uint x3, uint x4, uint x5, uint x6, uint x7) : this()
        {
            AsUint32[0] = x0;
            AsUint32[1] = x1;
            AsUint32[2] = x2;
            AsUint32[3] = x3;
            AsUint32[4] = x4;
            AsUint32[5] = x5;
            AsUint32[6] = x6;
            AsUint32[7] = x7;
        }
    }

    private static readonly uint[] K =
        [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ];

    public int BlockSize => 64;

    public int DigestSize => 32;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint rightRotate(int bits, uint x) => ((x >> bits) | (x << (32 - bits)));
    //private static uint rightRotate(int bits, uint x) => (uint)((x * 0x1_0000_0001ul) >> bits);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint e1Ch(uint x, uint y, uint z) => (rightRotate(6, x) ^ rightRotate(11, x) ^ rightRotate(25, x)) + ((x & y) | (~x & z));
    //private static uint e1Ch(uint x, uint y, uint z)
    //{
    //    var t = Pclmulqdq.CarrylessMultiply(Vector128.Create((ulong)x), Vector128.Create(2322172853370881ul), 0);
    //    t = Sse2.ShiftRightLogical(t, 25);
    //    return (uint)((ulong*)&t)[0] + ((x & y) | (~x & z));
    //}

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint e0Maj(uint x, uint y, uint z) => (rightRotate(2, x) ^ rightRotate(13, x) ^ rightRotate(22, x)) + ((z | (x & y)) & (x | y));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint s0(uint x) => rightRotate(7, x) ^ rightRotate(18, x) ^ (x >> 3);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint s1(uint x) => rightRotate(17, x) ^ rightRotate(19, x) ^ (x >> 10);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static unsafe Result Compute(in ReadOnlySpan<byte> message)
    {
        var messageLen = message.Length;
        var additionalSize = (((512 + (448 - ((messageLen * 8L + 1) % 512))) % 512) + 64 + 1) / 8;
        var tail = stackalloc byte[(int)additionalSize];

        *(uint*)(&tail[additionalSize - 8]) = (uint)(messageLen * 8L >> 32);
        *(uint*)(&tail[additionalSize - 4]) = (uint)(messageLen * 8L);

        uint h0 = 0x6A09E667u;
        uint h1 = 0xBB67AE85u;
        uint h2 = 0x3C6EF372u;
        uint h3 = 0xA54FF53Au;
        uint h4 = 0x510E527Fu;
        uint h5 = 0x9B05688Cu;
        uint h6 = 0x1F83D9ABu;
        uint h7 = 0x5BE0CD19u;

        var w = stackalloc uint[16];
        var iterationsCount = (messageLen + additionalSize) / (4 * 16);
        var dataPos = 0;
        tail -= messageLen;

        fixed (uint* pK = K)
        fixed (byte* m = message)
        {
            uint t1, t2;
            while (iterationsCount-- > 0)
            {
                var j = 0;
                for (; j < 16 && dataPos < (messageLen & ~3); j++)
                {
                    w[j] = *(uint*)(&m[dataPos]);
                    dataPos += 4;
                }

                for (t2 = 0; t2 < j; t2++)
                {
                    t1 = w[t2];
                    w[t2] =
                        t1 << 24
                        | (t1 & 0xff00) << 8
                        | (t1 >> 8) & 0xff00
                        | t1 >> 24;
                }

                if (j < 16)
                {
                    var left = messageLen - dataPos;
                    if (left > 0)
                    {
                        if (left == 3)
                        {
                            ((byte*)w)[(dataPos & 63) + 3] = m[dataPos];
                            ((byte*)w)[(dataPos & 63) + 2] = m[dataPos + 1];
                            ((byte*)w)[(dataPos & 63) + 1] = m[dataPos + 2];
                            ((byte*)w)[(dataPos & 63) + 0] = 0x80;
                        }
                        else if (left == 2)
                        {
                            ((byte*)w)[(dataPos & 63) + 3] = m[dataPos];
                            ((byte*)w)[(dataPos & 63) + 2] = m[dataPos + 1];
                            ((byte*)w)[(dataPos & 63) + 1] = 0x80;
                            ((byte*)w)[(dataPos & 63) + 0] = 0;
                        }
                        else if (left == 1)
                        {
                            ((byte*)w)[(dataPos & 63) + 3] = m[dataPos];
                            ((byte*)w)[(dataPos & 63) + 2] = 0x80;
                            ((byte*)w)[(dataPos & 63) + 1] = 0;
                            ((byte*)w)[(dataPos & 63) + 0] = 0;
                        }

                        dataPos += 4;
                        j++;
                    }
                    else if (left == 0)
                    {
                        ((byte*)w)[(dataPos & 63) + 3] = 0x80;
                        ((byte*)w)[(dataPos & 63) + 2] = 0;
                        ((byte*)w)[(dataPos & 63) + 1] = 0;
                        ((byte*)w)[(dataPos & 63) + 0] = 0;

                        dataPos += 4;
                        j++;
                    }

                    for (; j < 16; j++)
                    {
                        t1 = *(uint*)(&tail[dataPos]);
                        w[(dataPos >> 2) & 15] = t1;
                        dataPos += 4;
                    }
                }

                uint a = h0;
                uint b = h1;
                uint c = h2;
                uint d = h3;
                uint e = h4;
                uint f = h5;
                uint g = h6;
                uint h = h7;

                for (j = 0; j < 16; j++)
                {
                    t1 = h + pK[j] + w[j] + e1Ch(e, f, g);
                    t2 = t1 + e0Maj(a, b, c);

                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t2;
                }

                byte j2 = 16 - 2;
                byte j15 = 16 - 15;
                byte j16 = 16 - 16;
                byte j7 = 16 - 7;

                for (; j < 64; j++)
                {
                    var wNext =
                        s0(w[j15 & 15])
                        + s1(w[j2 & 15])
                        + w[j16 & 15]
                        + w[j7 & 15];

                    w[j16 & 15] = wNext;

                    t1 = e1Ch(e, f, g);
                    wNext += h + pK[j];
                    t2 = e0Maj(a, b, c);

                    t1 += wNext;

                    h = g;
                    g = f;
                    f = e;
                    e = d + t1;
                    d = c;
                    c = b;
                    b = a;
                    a = t2 + t1;

                    j2++;
                    j15++;
                    j16++;
                    j7++;
                }

                h0 += a;
                h1 += b;
                h2 += c;
                h3 += d;
                h4 += e;
                h5 += f;
                h6 += g;
                h7 += h;
            }
        }

        return new Result(h0, h1, h2, h3, h4, h5, h6, h7);
    }

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
}
