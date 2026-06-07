using System;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace NiL.Cryptography.Encryption.Modes;

public sealed class CbcMode : IBlockCipher
{
    private readonly byte[] _iv;
    private static readonly bool isSse2Supported = Sse2.IsSupported;
    private static readonly bool isSimdSupported = AdvSimd.IsSupported;

    public CbcMode(IBlockCipher blockCipher)
        : this(blockCipher, new byte[blockCipher.InputBlockSize])
    {
    }

    public CbcMode(IBlockCipher blockCipher, byte[] iv)
    {
        BlockCipher = blockCipher ?? throw new ArgumentNullException(nameof(blockCipher));
        _iv = iv ?? throw new ArgumentNullException(nameof(iv));

        if (blockCipher.InputBlockSize != iv.Length)
            throw new ArgumentException();

        _iv = (byte[])iv.Clone();
    }

    public int InputBlockSize => BlockCipher.InputBlockSize;
    public int OutBlockSize => BlockCipher.OutBlockSize;
    public byte[] Key { get => BlockCipher.Key; }

    public IBlockCipher BlockCipher { get; }

    public byte[] IV => _iv;

    public void Encrypt(in Span<byte> input, in Span<byte> output)
    {
        if (output.Length < input.Length)
            throw new ArgumentOutOfRangeException();

        if (input.Length % BlockCipher.InputBlockSize != 0)
            throw new ArgumentException("Incorrect block size");

        var inputBlock = new byte[BlockCipher.InputBlockSize];

        var inputBlockSize = BlockCipher.InputBlockSize;
        var outputBlockSize = BlockCipher.OutBlockSize;

        unsafe
        {
            fixed (byte* ibp = inputBlock)
            fixed (byte* ivp = _iv)
            fixed (byte* inp = input)
            fixed (byte* oup = output)
            {
                var inputPtr = inp;
                var outputPtr = oup;
                var outputCnt = output.Length;

                var blockCipher = BlockCipher;

                for (int inputPos = 0, outPos = 0; inputPos < input.Length; inputPos += inputBlock.Length)
                {
                    if (inputBlockSize != 16 || (!isSse2Supported && !isSimdSupported))
                    {
                        var fillStart = Math.Min(inputBlockSize, input.Length - inputPos);
                        Array.Clear(inputBlock, fillStart, inputBlock.Length - fillStart);

                        for (var i = 0; i < inputBlockSize; i++)
                            inputBlock[i] = (byte)(inputPtr[i] ^ ivp[i]);
                    }
                    else if (isSse2Supported)
                    {
                        *(Vector128<byte>*)ibp = Sse2.Xor(*(Vector128<byte>*)inputPtr, *(Vector128<byte>*)ivp);
                    }
                    else
                    {
                        *(Vector128<byte>*)ibp = AdvSimd.Xor(*(Vector128<byte>*)inputPtr, *(Vector128<byte>*)ivp);
                    }

                    inputPtr += inputBlockSize;

                    blockCipher.Encrypt(inputBlock, new Span<byte>(outputPtr, outputBlockSize));

                    if (inputBlockSize != 16)
                    {
                        for (var i = 0; i < _iv.Length && outPos < outputCnt; i++, outPos++)
                            ivp[i] = outputPtr[i];
                    }
                    else
                    {
                        *(Vector128<byte>*)ivp = *(Vector128<byte>*)outputPtr;
                    }

                    outputPtr += outputBlockSize;
                }
            }
        }
    }

    // TODO: перенести оптимизации из шифрования
    public void Decrypt(in Span<byte> input, in Span<byte> output)
    {
        if (output.Length < input.Length)
            throw new ArgumentOutOfRangeException();

        var inputBlock = new byte[BlockCipher.InputBlockSize];
        var outBlock = new byte[BlockCipher.OutBlockSize];

        for (int inputPos = 0, outPos = 0; inputPos < input.Length;)
        {
            var fillStart = Math.Min(inputBlock.Length, input.Length - inputPos);
            //Array.Copy(input.Array, inputPos + input.Offset, inputBlock, 0, fillLen);
            Array.Clear(inputBlock, fillStart, inputBlock.Length - fillStart);

            for (var i = 0; i < inputBlock.Length; i++, inputPos++)
                inputBlock[i] = input[inputPos];

            BlockCipher.Decrypt(inputBlock, outBlock);

            for (var i = 0; i < outBlock.Length && outPos < output.Length; i++)
            {
                output[outPos++] = (byte)(outBlock[i] ^ _iv[i]);
                _iv[i] = inputBlock[i];
            }
        }
    }
}
