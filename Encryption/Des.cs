using System;

namespace NiL.Cryptography.Encryption;

public sealed class Des : IBlockCipher
{
    private static readonly int[] IP =
    [
        58, 50, 42, 34, 26, 18, 10, 2,  60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,  64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17, 9,  1,  59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,  63, 55, 47, 39, 31, 23, 15, 7,
    ];

    private static readonly int[] IPr = new int[64];

    private static readonly int[] Cperm =
    [
        57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,
    ];

    private static readonly int[] Dperm =
    [
        63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4,
    ];

    private static readonly int[] CDperm =
    [
        57, 49, 41, 33, 25, 17, 9,  1,  58, 50, 42, 34, 26, 18,
        10, 2,  59, 51, 43, 35, 27, 19, 11, 3,  60, 52, 44, 36,

        63, 55, 47, 39, 31, 23, 15, 7,  62, 54, 46, 38, 30, 22,
        14, 6,  61, 53, 45, 37, 29, 21, 13, 5,  28, 20, 12, 4,
    ];

    private static readonly int[] Shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

    private static readonly int[] K =
    [
        14, 17, 11, 24, 1,  5,  3,  28, 15, 6,  21, 10, 23, 19, 12, 4,
        26, 8,  16, 7,  27, 20, 13, 2,  41, 52, 31, 37, 47, 55, 30, 40,
        51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
    ];

    private static readonly int[] E =
    [
        32, 1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9,  10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1,
    ];

    // var r = ""; for(var l = 0; l < 2; l++) for (var i = 0; i < 32; i++) r += (s[l * 32 + (i >> 1) + 16 * (i & 1)]) + ", ";
    private static readonly uint[][] S =
    [
        [
            14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8,
            1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7,
            8, 4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11,
            7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13
        ],
        [
            15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14,
            9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
            0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2,
            5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9
        ],
        [
            10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1,
            2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1, 13,
            1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4,
            1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12
        ],
        [
            7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1,
            4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9, 10, 3,
            6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1,
            4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14
        ],
        [
            2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8,
            5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6, 4, 11,
            2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9,
            15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3
        ],
        [
            12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0,
            6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8, 9, 4,
            14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0,
            14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13
        ],
        [
            4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3,
            14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6, 1, 6, 4,
            11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15,
            5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12
        ],
        [
            13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10,
            12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2, 7, 2,
            11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6,
            12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11
        ],
    ];

    private static readonly int[] ReversedSboxIndexes = new int[64];

    private static readonly int[] P =
    [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
        19, 13, 30, 6,
        22, 11, 4, 25,
    ];

    static Des()
    {
        for (var i = 0; i < IP.Length; i++)
        {
            IP[i]--;
            IPr[IP[i]] = i;
        }

        for (var i = 0; i < Cperm.Length; i++)
        {
            Cperm[i]--;
            Dperm[i]--;
        }

        for (var i = 0; i < CDperm.Length; i++)
        {
            CDperm[i]--;
        }

        for (var i = 0; i < K.Length; i++)
        {
            K[i]--;
        }

        for (var i = 0; i < S.Length; i++)
        {
            for (var j = 0; j < S[i].Length; j++)
            {
                S[i][j] = (uint)reverseBits(S[i][j], 4);
            }
        }

        for (var i = 0; i < E.Length; i++)
        {
            E[i]--;
        }

        for (var i = 0; i < P.Length; i++)
        {
            P[i]--;
        }

        for (var i = 0u; i < ReversedSboxIndexes.Length; i++)
        {
            ReversedSboxIndexes[i] = (int)reverseBits(i, 6);
        }
    }

    public int InputBlockSize => 8;

    public int OutBlockSize => 8;

    private byte[] _key;
    public byte[] Key
    {
        get => _key;
        set
        {
            if (value == null)
                throw new ArgumentNullException("key");

            if (value.Length != 8)
                throw new ArgumentOutOfRangeException();

            _key = value;
        }
    }

    public Des(byte[] key)
    {
        Key = key;
    }

    public void Decrypt(in Span<byte> input, in Span<byte> output)
    {
        crypt(input, output, false);
    }

    public unsafe void Encrypt(in Span<byte> input, in Span<byte> output)
    {
        crypt(input, output, true);
    }

    private unsafe void crypt(Span<byte> input, Span<byte> output, bool encrypt)
    {
        if (input.Length != 8)
            throw new ArgumentOutOfRangeException(nameof(input));

        if (output.Length != 8)
            throw new ArgumentOutOfRangeException(nameof(output));

        byte* textB = stackalloc byte[8];
        uint* text = (uint*)&textB[0];

        byte* kB = stackalloc byte[8];

        for (var i = 0; i < 8; i++)
        {
            textB[i] = input[7 - i];
            kB[i] = Key[7 - i];
        }

        *(ulong*)text = reverseBits(*(ulong*)text, 64);
        *(ulong*)kB = reverseBits(*(ulong*)kB, 64);

        var c = permutation(Cperm, *(ulong*)kB);
        var d = permutation(Dperm, *(ulong*)kB);

        *(ulong*)text = permutation(IP, *(ulong*)text);

        var t = 0ul;
        var tui = (uint*)&t;
        ulong k;

        if (!encrypt)
        {
            text[0] ^= text[1];
            text[1] ^= text[0];
            text[0] ^= text[1];
        }

        for (var i = 0; i < 16; i++)
        {
            if (encrypt)
            {
                var shift = Shifts[i];
                c = ((c >> shift) | (c << (28 - shift))) & 0xfffffff;
                d = ((d >> shift) | (d << (28 - shift))) & 0xfffffff;

            }

            k = c | (d << 28);
            k = permutation(K, k);

            if (encrypt)
            {
                tui[0] = text[1];
                tui[1] = text[0] ^ ff(text[1], k);
            }
            else
            {
                tui[1] = text[0];
                tui[0] = text[1] ^ ff(text[0], k);

                if (i < 15)
                {
                    var shift = Shifts[15 - i];
                    c = ((c << shift) | (c >> (28 - shift))) & 0xfffffff;
                    d = ((d << shift) | (d >> (28 - shift))) & 0xfffffff;
                }
            }

            *(ulong*)text = t;
        }

        if (encrypt)
        {
            text[0] ^= text[1];
            text[1] ^= text[0];
            text[0] ^= text[1];
        }

        *(ulong*)text = permutation(IPr, *(ulong*)text);

        *(ulong*)text = reverseBits(*(ulong*)text, 64);

        for (var i = 0; i < 8; i++)
            output[7 - i] = textB[i];
    }

    private static ulong reverseBits(ulong v, int n)
    {
        var res = 0ul;
        while (n-- > 0)
        {
            res <<= 1;
            res |= v & 1;
            v >>= 1;
        }

        return res;
    }

    private static unsafe uint ff(uint v, ulong key)
    {
        var e = permutation(E, v);
        e ^= key;
        var res = 0u;
        for (var i = 0; i < 8; i++)
        {
            var t = e & 63;
            res |= S[i][ReversedSboxIndexes[t]] << (i * 4);
            e >>= 6;
        }

        var r = permutation(P, res);

        res = (uint)r;

        return res;
    }

    private static ulong permutation(int[] permTable, ulong input)
    {
        var r = 0ul;
        for (var i = 0; i < permTable.Length; i++)
        {
            if ((input & (1ul << permTable[i])) != 0)
                r |= 1ul << i;

            //r |= (1ul << permTable[i]);
        }

        return r;
    }
}
