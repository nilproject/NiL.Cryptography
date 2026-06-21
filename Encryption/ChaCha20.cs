using System;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.Encryption;

public unsafe class ChaCha20 : IBlockCipher
{
    public required byte[] Key
    {
        get;
        set
        {
            if (value?.Length is not 32)
                throw new ArgumentOutOfRangeException(nameof(value), "the key must be of 32 bytes");

            field = value;
        }
    }

    public uint BlockCounter { get; set; }

    public required byte[] Nonce
    {
        get;
        set
        {
            if (value?.Length is not 12)
                throw new ArgumentOutOfRangeException(nameof(value), "the nonce must be of 12 bytes");

            field = value;
        }
    }

    public int InputBlockSize => 64;

    public int OutBlockSize => 64;

    private static uint rol(uint x, int shift) => (x << shift) | (x >> (32 - shift));

    public static (uint a, uint b, uint c, uint d) QuarterRound(uint a, uint b, uint c, uint d)
    {
        a += b; d ^= a; d = rol(d, 16);
        c += d; b ^= c; b = rol(b, 12);
        a += b; d ^= a; d = rol(d, 8);
        c += d; b ^= c; b = rol(b, 7);
        return (a, b, c, d);
    }

    public static void Round(uint* state)
    {
        /*
         * 1. QUARTERROUND ( 0, 4, 8,12)
         * 2. QUARTERROUND ( 1, 5, 9,13)
         * 3. QUARTERROUND ( 2, 6,10,14)
         * 4. QUARTERROUND ( 3, 7,11,15)
         * 5. QUARTERROUND ( 0, 5,10,15)
         * 6. QUARTERROUND ( 1, 6,11,12)
         * 7. QUARTERROUND ( 2, 7, 8,13)
         * 8. QUARTERROUND ( 3, 4, 9,14)
         */

        (state[0], state[4], state[8], state[12]) = QuarterRound(state[0], state[4], state[8], state[12]);
        (state[1], state[5], state[9], state[13]) = QuarterRound(state[1], state[5], state[9], state[13]);
        (state[2], state[6], state[10], state[14]) = QuarterRound(state[2], state[6], state[10], state[14]);
        (state[3], state[7], state[11], state[15]) = QuarterRound(state[3], state[7], state[11], state[15]);
        (state[0], state[5], state[10], state[15]) = QuarterRound(state[0], state[5], state[10], state[15]);
        (state[1], state[6], state[11], state[12]) = QuarterRound(state[1], state[6], state[11], state[12]);
        (state[2], state[7], state[8], state[13]) = QuarterRound(state[2], state[7], state[8], state[13]);
        (state[3], state[4], state[9], state[14]) = QuarterRound(state[3], state[4], state[9], state[14]);
    }

    public void Encrypt(in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        if (input.Length > output.Length)
            throw new ArgumentOutOfRangeException("output has no enough capacity");

        if (input.Length > 64)
            throw new ArgumentOutOfRangeException("input is too big");

        var state = stackalloc uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        var keyPlace = (byte*)&state[4];
        for (var i = 0; i < 32; i++)
            keyPlace[i] = Key[i];

        state[12] = BlockCounter++;

        var noncePlace = (byte*)&state[13];
        for (var i = 0; i < 12; i++)
            noncePlace[i] = Nonce[i];

        //var test = ArrayTools.FormatHexString(new(state, 64));

        var working_state = stackalloc uint[16];

        NumericsBase.Move(state, working_state, 16);

        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);
        Round(working_state);

        for (var i = 0; i < 16; i++)
            state[i] += working_state[i];

        for (var i = 0; i < input.Length; i++)
            output[i] = (byte)(input[i] ^ ((byte*)state)[i]);
    }

    public void Decrypt(in ReadOnlySpan<byte> input, in Span<byte> output)
        => Encrypt(input, output);
}
