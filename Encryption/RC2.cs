using System;
using System.Runtime.CompilerServices;

namespace NiL.Cryptography.Encryption;

// https://tools.ietf.org/html/rfc2268
public sealed class RC2 : IBlockCipher
{
    private static readonly byte[] PiTable =
    [
        0xd9,
        0x78,
        0xf9,
        0xc4,
        0x19,
        0xdd,
        0xb5,
        0xed,
        0x28,
        0xe9,
        0xfd,
        0x79,
        0x4a,
        0xa0,
        0xd8,
        0x9d,
        0xc6,
        0x7e,
        0x37,
        0x83,
        0x2b,
        0x76,
        0x53,
        0x8e,
        0x62,
        0x4c,
        0x64,
        0x88,
        0x44,
        0x8b,
        0xfb,
        0xa2,
        0x17,
        0x9a,
        0x59,
        0xf5,
        0x87,
        0xb3,
        0x4f,
        0x13,
        0x61,
        0x45,
        0x6d,
        0x8d,
        0x09,
        0x81,
        0x7d,
        0x32,
        0xbd,
        0x8f,
        0x40,
        0xeb,
        0x86,
        0xb7,
        0x7b,
        0x0b,
        0xf0,
        0x95,
        0x21,
        0x22,
        0x5c,
        0x6b,
        0x4e,
        0x82,
        0x54,
        0xd6,
        0x65,
        0x93,
        0xce,
        0x60,
        0xb2,
        0x1c,
        0x73,
        0x56,
        0xc0,
        0x14,
        0xa7,
        0x8c,
        0xf1,
        0xdc,
        0x12,
        0x75,
        0xca,
        0x1f,
        0x3b,
        0xbe,
        0xe4,
        0xd1,
        0x42,
        0x3d,
        0xd4,
        0x30,
        0xa3,
        0x3c,
        0xb6,
        0x26,
        0x6f,
        0xbf,
        0x0e,
        0xda,
        0x46,
        0x69,
        0x07,
        0x57,
        0x27,
        0xf2,
        0x1d,
        0x9b,
        0xbc,
        0x94,
        0x43,
        0x03,
        0xf8,
        0x11,
        0xc7,
        0xf6,
        0x90,
        0xef,
        0x3e,
        0xe7,
        0x06,
        0xc3,
        0xd5,
        0x2f,
        0xc8,
        0x66,
        0x1e,
        0xd7,
        0x08,
        0xe8,
        0xea,
        0xde,
        0x80,
        0x52,
        0xee,
        0xf7,
        0x84,
        0xaa,
        0x72,
        0xac,
        0x35,
        0x4d,
        0x6a,
        0x2a,
        0x96,
        0x1a,
        0xd2,
        0x71,
        0x5a,
        0x15,
        0x49,
        0x74,
        0x4b,
        0x9f,
        0xd0,
        0x5e,
        0x04,
        0x18,
        0xa4,
        0xec,
        0xc2,
        0xe0,
        0x41,
        0x6e,
        0x0f,
        0x51,
        0xcb,
        0xcc,
        0x24,
        0x91,
        0xaf,
        0x50,
        0xa1,
        0xf4,
        0x70,
        0x39,
        0x99,
        0x7c,
        0x3a,
        0x85,
        0x23,
        0xb8,
        0xb4,
        0x7a,
        0xfc,
        0x02,
        0x36,
        0x5b,
        0x25,
        0x55,
        0x97,
        0x31,
        0x2d,
        0x5d,
        0xfa,
        0x98,
        0xe3,
        0x8a,
        0x92,
        0xae,
        0x05,
        0xdf,
        0x29,
        0x10,
        0x67,
        0x6c,
        0xba,
        0xc9,
        0xd3,
        0x00,
        0xe6,
        0xcf,
        0xe1,
        0x9e,
        0xa8,
        0x2c,
        0x63,
        0x16,
        0x01,
        0x3f,
        0x58,
        0xe2,
        0x89,
        0xa9,
        0x0d,
        0x38,
        0x34,
        0x1b,
        0xab,
        0x33,
        0xff,
        0xb0,
        0xbb,
        0x48,
        0x0c,
        0x5f,
        0xb9,
        0xb1,
        0xcd,
        0x2e,
        0xc5,
        0xf3,
        0xdb,
        0x47,
        0xe5,
        0xa5,
        0x9c,
        0x77,
        0x0a,
        0xa6,
        0x20,
        0x68,
        0xfe,
        0x7f,
        0xc1,
        0xad,
    ];

    private int _effectiveKeyLen;
    private readonly byte[] _keySchedule;
    private byte[] _key;

    public RC2(byte[] key)
        : this(key, key.Length * 8)
    {
    }

    public RC2(byte[] key, int effectiveKeyLen)
    {
        _effectiveKeyLen = effectiveKeyLen;
        _keySchedule = new byte[128];
        Key = key;
    }

    public byte[] Key
    {
        get => _key;
        set
        {
            if (value == null)
                throw new ArgumentNullException();

            for (var i = 0; i < Math.Min(128, value.Length); i++)
                _keySchedule[i] = value[i];

            var t8 = _effectiveKeyLen + 7 >> 3;
            var tm = 0xff % (1 << 8 + _effectiveKeyLen - 8 * t8);
            expandKey(_keySchedule, t8, tm, value.Length);

            _key = value;
        }
    }
    public int InputBlockSize => 8;
    public int OutBlockSize => 8;

    public unsafe void Encrypt(in Span<byte> input, in Span<byte> output)
    {
        fixed (byte* l = _keySchedule)
        {
            var k = (ushort*)l;
            prologue(input, output);

            fixed (byte* op = output)
            {
                ushort* r = (ushort*)op;

                var j = 0;

                for (var i = 0; i < 5; i++)
                {
                    mix(r, k, 0, j++);
                    mix(r, k, 1, j++);
                    mix(r, k, 2, j++);
                    mix(r, k, 3, j++);
                }

                {
                    mash(r, k, 0);
                    mash(r, k, 1);
                    mash(r, k, 2);
                    mash(r, k, 3);
                }

                for (var i = 0; i < 6; i++)
                {
                    mix(r, k, 0, j++);
                    mix(r, k, 1, j++);
                    mix(r, k, 2, j++);
                    mix(r, k, 3, j++);
                }

                {
                    mash(r, k, 0);
                    mash(r, k, 1);
                    mash(r, k, 2);
                    mash(r, k, 3);
                }

                for (var i = 0; i < 5; i++)
                {
                    mix(r, k, 0, j++);
                    mix(r, k, 1, j++);
                    mix(r, k, 2, j++);
                    mix(r, k, 3, j++);
                }
            }
        }
    }

    public unsafe void Decrypt(in Span<byte> input, in Span<byte> output)
    {
        fixed (byte* l = _keySchedule)
        {
            var k = (ushort*)l;
            prologue(input, output);

            fixed (byte* op = output)
            {
                ushort* r = (ushort*)op;

                var j = 63;

                for (var i = 0; i < 5; i++)
                {
                    rmix(r, k, 3, j--);
                    rmix(r, k, 2, j--);
                    rmix(r, k, 1, j--);
                    rmix(r, k, 0, j--);
                }

                {
                    rmash(r, k, 3);
                    rmash(r, k, 2);
                    rmash(r, k, 1);
                    rmash(r, k, 0);
                }

                for (var i = 0; i < 6; i++)
                {
                    rmix(r, k, 3, j--);
                    rmix(r, k, 2, j--);
                    rmix(r, k, 1, j--);
                    rmix(r, k, 0, j--);
                }

                {
                    rmash(r, k, 3);
                    rmash(r, k, 2);
                    rmash(r, k, 1);
                    rmash(r, k, 0);
                }

                for (var i = 0; i < 5; i++)
                {
                    rmix(r, k, 3, j--);
                    rmix(r, k, 2, j--);
                    rmix(r, k, 1, j--);
                    rmix(r, k, 0, j--);
                }
            }
        }
    }

    private unsafe void prologue(Span<byte> input, in Span<byte> output)
    {
        if (input.Length != 8)
            throw new ArgumentException(nameof(input));

        if (output.Length != 8)
            throw new ArgumentException(nameof(input));

        // K - Key. ushort. Key expansion
        // L - Key as bytes. K[i] = L[2*i] + 256*L[2*i+1]
        // R - Data.
        // T - size of key. T1 - bits, T8 - bytes, T8 = (T1 + 7) / 8, TM = 255 mod 2**(8 + T1 - 8 * T8)
        // example: T1 = 64, T8 = 8, TM = 0xff

        for (var i = 0; i < input.Length; i++)
            output[i] = input[i];
    }

    private unsafe void expandKey(byte[] l, int t8, int tm, int len)
    {
        for (var i = len; i < 128; i++)
            l[i] = PiTable[l[i - 1] + l[i - len] & 0xff];

        l[128 - t8] = PiTable[l[128 - t8] & tm];

        for (var i = 128 - t8; i-- > 0;)
            l[i] = PiTable[l[i + 1] ^ l[i + t8]];
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe void mix(ushort* r, ushort* k, int i, int j)
    {
        r[i] = (ushort)(r[i] + k[j] + (r[i - 1 & 0x3] & r[i - 2 & 0x3]) + (~r[i - 1 & 0x3] & r[i - 3 & 0x3]));
        var s = i + 1;
        s += s >> 2;
        r[i] = (ushort)(r[i] << s | r[i] >> 16 - s);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe void rmix(ushort* r, ushort* k, int i, int j)
    {
        var s = i + 1;
        s += s >> 2;
        r[i] = (ushort)(r[i] >> s | r[i] << 16 - s);
        r[i] = (ushort)(r[i] - k[j] - (r[i - 1 & 0x3] & r[i - 2 & 0x3]) - (~r[i - 1 & 0x3] & r[i - 3 & 0x3]));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe void mash(ushort* r, ushort* k, int i)
    {
        r[i] = (ushort)(r[i] + k[r[i - 1 & 0x3] & 63]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private unsafe void rmash(ushort* r, ushort* k, int i)
    {
        r[i] = (ushort)(r[i] - k[r[i - 1 & 0x3] & 63]);
    }
}