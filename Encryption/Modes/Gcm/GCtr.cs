using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

internal unsafe class GCtr
{
    private readonly IBlockCipher _blockCipher;

    public GCtr(IBlockCipher blockCipher)
    {
        _blockCipher = blockCipher;
    }

    public void Invoke(in GcmFieldElement counter, in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        if (Sse2.IsSupported)
            gctrSse2(counter, input, output);
        else
            gctr(counter, input, output);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void gctr(in GcmFieldElement counter, in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        var blockSize = _blockCipher.OutBlockSize;
        var ciph = stackalloc byte[blockSize];
        var ciphs = new Span<byte>(ciph, blockSize);
        var xi = 0;

        var cbb = stackalloc byte[blockSize];
        var cbbs = new Span<byte>(cbb, blockSize);
        *(GcmFieldElement*)cbb = counter;

        fixed (byte* py = output)
        fixed (byte* px = input)
        {
            if (blockSize == 16)
            {
                for (var i = input.Length >> 4; i-- > 0;)
                {
                    _blockCipher.Encrypt(cbbs, ciphs);

                    *(ulong*)&py[xi] = *(ulong*)&ciph[0] ^ *(ulong*)&px[xi];
                    xi += 8;
                    *(ulong*)&py[xi] = *(ulong*)&ciph[8] ^ *(ulong*)&px[xi];
                    xi += 8;

                    for (var c = 16; c-- > 0 && ++cbb[c] == 0;) ;
                }

                if (xi < input.Length)
                {
                    _blockCipher.Encrypt(cbbs, ciphs);

                    for (var j = 0; xi < input.Length; xi++, j++)
                        output[xi] = (byte)(ciph[j] ^ input[xi]);

                    for (var j = 16; j-- > 0 && ++cbb[j] == 0;) ;
                }
            }
            else
            {
                var n = (input.Length + (blockSize - 1)) / blockSize;
                for (var i = 0; i < n; i++)
                {
                    _blockCipher.Encrypt(cbbs, ciphs);

                    for (var j = 0; j < blockSize && xi < input.Length; xi++, j++)
                        output[xi] = (byte)(ciph[j] ^ input[xi]);

                    for (var j = 16; j-- > 0 && ++cbb[j] == 0;) ;
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private void gctrSse2(in GcmFieldElement counter, in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        var blockSize = _blockCipher.OutBlockSize;

        var encodedCounterBytes = stackalloc byte[blockSize];
        var encodedCounterSpan = new Span<byte>(encodedCounterBytes, blockSize);

        var counterBytes = stackalloc byte[blockSize];
        var counterSpan = new Span<byte>(counterBytes, blockSize);
        *(GcmFieldElement*)counterBytes = counter;

        var dataIndex = 0;

        fixed (byte* pOutput = output)
        fixed (byte* pInput = input)
        {
            if (blockSize == 16)
            {
                for (var i = input.Length >> 4; i-- > 0;)
                {
                    _blockCipher.Encrypt(counterSpan, encodedCounterSpan);

                    *(Vector128<byte>*)&pOutput[dataIndex] = Sse2.Xor(*(Vector128<byte>*)encodedCounterBytes, *(Vector128<byte>*)&pInput[dataIndex]);
                    dataIndex += 16;

                    for (var c = 16; c-- > 0 && ++counterBytes[c] == 0;) ;
                }

                if (dataIndex < input.Length)
                {
                    _blockCipher.Encrypt(counterSpan, encodedCounterSpan);

                    for (var j = 0; dataIndex < input.Length; dataIndex++, j++)
                        output[dataIndex] = (byte)(encodedCounterBytes[j] ^ input[dataIndex]);

                    for (var j = 16; j-- > 0 && ++counterBytes[j] == 0;) ;
                }
            }
            else
            {
                var n = (input.Length + (blockSize - 1)) / blockSize;
                for (var i = 0; i < n; i++)
                {
                    _blockCipher.Encrypt(counterSpan, encodedCounterSpan);

                    for (var j = 0; j < blockSize && dataIndex < input.Length; dataIndex++, j++)
                        output[dataIndex] = (byte)(encodedCounterBytes[j] ^ input[dataIndex]);

                    for (var j = 16; j-- > 0 && ++counterBytes[j] == 0;) ;
                }
            }
        }
    }
}
