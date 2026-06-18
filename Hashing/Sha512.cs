using System;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace NiL.Cryptography.Hashing;

using System;
using System.IO;
using System.Runtime.Intrinsics.X86;
using System.Text;

public class Sha512 : IHashFunction
{
    public static readonly Sha512 Instance = new Sha512();
    private Sha512() { }

    public unsafe struct FixedUint64Array
    {
        private const int _len = 8;

        private fixed ulong _data[_len];

        public int Length => _len;

        public ulong this[int index]
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
        private const int _len = 64;

        private fixed byte _data[_len];

        public int Length => _len;

        public byte this[int index]
        {
            get
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                return _data[index ^ 7];
            }

            set
            {
                if (index < 0 || index >= _len)
                    throw new ArgumentOutOfRangeException();

                _data[index ^ 7] = value;
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
        public readonly FixedUint64Array AsUint64;

        [FieldOffset(0)]
        public readonly FixedByteArray AsBytes;

        internal Result(ulong x0, ulong x1, ulong x2, ulong x3, ulong x4, ulong x5, ulong x6, ulong x7) : this()
        {
            AsUint64[0] = x0;
            AsUint64[1] = x1;
            AsUint64[2] = x2;
            AsUint64[3] = x3;
            AsUint64[4] = x4;
            AsUint64[5] = x5;
            AsUint64[6] = x6;
            AsUint64[7] = x7;
        }
    }

    private static readonly ulong[] K =
    [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
        0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
        0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
        0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
        0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
        0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
        0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
        0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
        0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
        0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ];

    public int BlockSize => 64;

    public int DigestSize => 32;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong rightRotate(int bits, ulong x) => ((x >> bits) | (x << (64 - bits)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong e1Ch(ulong x, ulong y, ulong z) => (rightRotate(14, x) ^ rightRotate(18, x) ^ rightRotate(41, x)) + ((x & y) | (~x & z));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong e0Maj(ulong x, ulong y, ulong z) => (rightRotate(28, x) ^ rightRotate(34, x) ^ rightRotate(39, x)) + ((z | (x & y)) & (x | y));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong s0(ulong x) => rightRotate(1, x) ^ rightRotate(8, x) ^ (x >> 7);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static ulong s1(ulong x) => rightRotate(61, x) ^ rightRotate(19, x) ^ (x >> 6);

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static unsafe Result Compute(in ReadOnlySpan<byte> message)
    {
        var messageLen = message.Length;
        var additionalSize = (((1024 + (896 - ((messageLen * 8L + 1) % 1024))) % 1024) + 128 + 1) / 8;
        var tail = stackalloc byte[(int)additionalSize];

        *(uint*)(&tail[additionalSize - 8]) = (uint)(messageLen * 8L >> 32);
        *(uint*)(&tail[additionalSize - 4]) = (uint)(messageLen * 8L);

        ulong h0 = 0x6a09e667f3bcc908;
        ulong h1 = 0xbb67ae8584caa73b;
        ulong h2 = 0x3c6ef372fe94f82b;
        ulong h3 = 0xa54ff53a5f1d36f1;
        ulong h4 = 0x510e527fade682d1;
        ulong h5 = 0x9b05688c2b3e6c1f;
        ulong h6 = 0x1f83d9abfb41bd6b;
        ulong h7 = 0x5be0cd19137e2179;

        var w64 = stackalloc ulong[16];
        var w32 = (uint*)w64;
        var iterationsCount = (messageLen + additionalSize) / (sizeof(ulong) * 16);
        var dataPos = 0;
        tail -= messageLen;

        fixed (ulong* pK = K)
        fixed (byte* m = message)
        {
            ulong t1, t2;
            while (iterationsCount-- > 0)
            {
                var j = 0;
                for (; j < 32 && dataPos < (messageLen & ~3); j++)
                {
                    w32[j] = *(uint*)(&m[dataPos]);
                    dataPos += sizeof(uint);
                }

                for (var i = 0; i < j; i++)
                {
                    var t = w32[i];
                    w32[i] =
                        t << 24
                        | (t & 0xff00) << 8
                        | (t >> 8) & 0xff00
                        | t >> 24;
                }

                if (j < 32)
                {
                    var left = messageLen - dataPos;
                    if (left > 0)
                    {
                        switch (left)
                        {
                            case 3:
                                ((byte*)w32)[(dataPos & 127) + 3] = m[dataPos];
                                ((byte*)w32)[(dataPos & 127) + 2] = m[dataPos + 1];
                                ((byte*)w32)[(dataPos & 127) + 1] = m[dataPos + 2];
                                ((byte*)w32)[(dataPos & 127) + 0] = 0x80;
                                break;
                            case 2:
                                ((byte*)w32)[(dataPos & 127) + 3] = m[dataPos];
                                ((byte*)w32)[(dataPos & 127) + 2] = m[dataPos + 1];
                                ((byte*)w32)[(dataPos & 127) + 1] = 0x80;
                                ((byte*)w32)[(dataPos & 127) + 0] = 0;
                                break;
                            case 1:
                                ((byte*)w32)[(dataPos & 127) + 3] = m[dataPos];
                                ((byte*)w32)[(dataPos & 127) + 2] = 0x80;
                                ((byte*)w32)[(dataPos & 127) + 1] = 0;
                                ((byte*)w32)[(dataPos & 127) + 0] = 0;
                                break;
                            default: throw new NotImplementedException();
                        }

                        dataPos += sizeof(uint);
                        j++;
                    }
                    else if (left == 0)
                    {
                        ((byte*)w32)[(dataPos & 127) + 3] = 0x80;
                        ((byte*)w32)[(dataPos & 127) + 2] = 0;
                        ((byte*)w32)[(dataPos & 127) + 1] = 0;
                        ((byte*)w32)[(dataPos & 127) + 0] = 0;

                        dataPos += sizeof(uint);
                        j++;
                    }

                    for (; j < 32; j++)
                    {
                        var t = *(uint*)(&tail[dataPos]);
                        w32[(dataPos / sizeof(uint)) % 32] = t;
                        dataPos += sizeof(uint);
                    }
                }

                for (j = 0; j < 32; j += 2)
                {
                    var t = w32[j];
                    w32[j] = w32[j + 1];
                    w32[j + 1] = t;
                }

                ulong a = h0;
                ulong b = h1;
                ulong c = h2;
                ulong d = h3;
                ulong e = h4;
                ulong f = h5;
                ulong g = h6;
                ulong h = h7;

                for (j = 0; j < 16; j++)
                {
                    t1 = h + pK[j] + w64[j] + e1Ch(e, f, g);
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

                for (; j < 80; j++)
                {
                    var wNext =
                        s0(w64[j15 & 15])
                        + s1(w64[j2 & 15])
                        + w64[j16 & 15]
                        + w64[j7 & 15];

                    w64[j16 & 15] = wNext;

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
