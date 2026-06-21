using System;
using System.Numerics;
using System.Runtime.Serialization;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.Encryption.Modes;

public class Poly1305(IBlockCipher blockCipher) : IAeadCipher
{
    public byte[] Key { get; set; }

    public int InputBlockSize => 1;

    public int OutBlockSize => 1;

    public void Encrypt(in ReadOnlySpan<byte> authData, in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output, in Span<byte> authTag)
    {
        crypt(true, authData, iv, input, output, authTag);
    }

    public void Decrypt(in ReadOnlySpan<byte> authData, in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> input, in Span<byte> output, in Span<byte> authTag)
    {
        crypt(false, authData, iv, input, output, authTag);
    }

    private unsafe void crypt(bool encrypt, ReadOnlySpan<byte> authData, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> input, in Span<byte> output, Span<byte> authTag)
    {
        if (authData.Length > 16)
            throw new ArgumentException(nameof(authData) + " is too large");

        if (input.Length > output.Length)
            throw new ArgumentException("input and output must be the equal size");

        var p = stackalloc uint[] { 0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 0x3, 0, 0, 0, 0, 0 };
        var r = stackalloc uint[10];
        var s = stackalloc uint[10];
        var n = stackalloc uint[10];

        for (var i = 0; i < authData.Length; i++)
        {
            ((byte*)n)[i] = authData[i];
        }

        if (blockCipher is ChaCha20 chaCha20)
        {
            if (iv.Length > 0)
            {
                for (var i = 0; i < iv.Length; i++)
                    chaCha20.Nonce[i] = iv[i];
            }

            chaCha20.BlockCounter = 0;

            Span<byte> state = stackalloc byte[32];
            chaCha20.Encrypt(state, state);

            for (var i = 0; i < 16; i++)
                ((byte*)r)[i] = state[i];

            for (var i = 0; i < 16; i++)
                ((byte*)s)[i] = state[i + 16];

            for (var pos = 0; pos < output.Length; pos += 64)
            {
                var cryptLen = Math.Min(input.Length - pos, 64);
                chaCha20.Encrypt(input.Slice(pos, cryptLen), output.Slice(pos, cryptLen));
            }
        }
        else
        {
            if (iv.Length > 0)
                throw new ArgumentException(nameof(iv) + " is not supported for ciphers other then ChaCha20");

            // NEED TO CHECK

            if (Key is not null)
            {
                for (var i = 0; i < 16; i++)
                    ((byte*)r)[i] = Key[i];

                for (var i = 0; i < 16; i++)
                    ((byte*)s)[i] = Key[i + 16];
            }

            int inputPos = 0, outputPos = 0;
            for (; inputPos + blockCipher.InputBlockSize <= input.Length && outputPos + blockCipher.OutBlockSize <= output.Length;
                inputPos += blockCipher.InputBlockSize, outputPos += blockCipher.OutBlockSize)
            {
                if (encrypt)
                {
                    blockCipher.Encrypt(input.Slice(inputPos), output.Slice(outputPos));
                }
                else
                {
                    blockCipher.Decrypt(input.Slice(inputPos), output.Slice(outputPos));
                }
            }

            if (inputPos < input.Length || Key is null)
            {
                Span<byte> inputBuffer = stackalloc byte[blockCipher.InputBlockSize];
                Span<byte> outputBuffer = stackalloc byte[blockCipher.OutBlockSize];

                while (inputPos < input.Length)
                {
                    inputBuffer[inputPos % blockCipher.InputBlockSize] = input[inputPos++];
                }

                if (encrypt)
                {
                    blockCipher.Encrypt(inputBuffer, outputBuffer);
                }
                else
                {
                    blockCipher.Decrypt(inputBuffer, outputBuffer);
                }

                if (Key is null)
                {
                    blockCipher.Encrypt(inputBuffer, outputBuffer);

                    for (var i = 0; i < 16; i++)
                        ((byte*)r)[i] = outputBuffer[i];

                    for (var i = 0; i < 16; i++)
                        ((byte*)s)[i] = outputBuffer[i + 16];
                }
            }
        }

        r[0] &= 0x0fff_ffffu;
        r[1] &= 0x0fff_fffcu;
        r[2] &= 0x0fff_fffcu;
        r[3] &= 0x0fff_fffcu;

        fixed (byte* macBuffer = encrypt ? output : input)
        {
            var bufferPos = 0;
            var accumulator = stackalloc uint[10];
            var temp = stackalloc uint[10];

            bufferPos = 0;

            ((byte*)n)[16] = 1;

            NumericsBase.Add(accumulator, n, temp, 10);
            NumericsBase.Mul(temp, r, accumulator, 10);
            NumericsBase.DivMod(accumulator, p, null, 10);

            while (bufferPos + 16 < output.Length)
            {
                ((ulong*)n)[0] = *(ulong*)&macBuffer[bufferPos];
                ((ulong*)n)[1] = *(ulong*)&macBuffer[bufferPos + 8];

                bufferPos += 16;

                NumericsBase.Add(accumulator, n, temp, 10);
                NumericsBase.Mul(temp, r, accumulator, 10);
                NumericsBase.DivMod(accumulator, p, null, 10);
            }

            ((ulong*)n)[0] = 0;
            ((ulong*)n)[1] = 0;

            while (bufferPos < output.Length)
            {
                ((byte*)n)[bufferPos & 15] = macBuffer[bufferPos++];
            }

            NumericsBase.Add(accumulator, n, temp, 10);
            NumericsBase.Mul(temp, r, accumulator, 10);
            NumericsBase.DivMod(accumulator, p, null, 10);

            n[0] = (uint)authData.Length;
            n[1] = 0;
            n[2] = (uint)output.Length;
            n[3] = 0;

            NumericsBase.Add(accumulator, n, temp, 10);
            NumericsBase.Mul(temp, r, accumulator, 10);
            NumericsBase.DivMod(accumulator, p, null, 10);

            NumericsBase.Add(s, accumulator, accumulator, 10);

            for (var i = 0; i < 16; i++)
            {
                authTag[i] = ((byte*)accumulator)[i];
            }
        }
    }
}
