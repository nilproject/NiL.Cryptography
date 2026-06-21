using System;

namespace NiL.Cryptography.Encryption.Modes;

internal sealed class EcbMode : IBlockCipher
{
    public EcbMode(IBlockCipher blockCipher)
    {
        BlockCipher = blockCipher ?? throw new ArgumentNullException(nameof(blockCipher));
    }

    public int InputBlockSize => BlockCipher.InputBlockSize;
    public int OutBlockSize => BlockCipher.OutBlockSize;

    public IBlockCipher BlockCipher { get; }

    public byte[] Key { get => BlockCipher.Key; }

    public void Encrypt(in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        var inputBlock = new byte[BlockCipher.InputBlockSize];
        var outBlock = new byte[BlockCipher.OutBlockSize];

        for (int inputPos = 0, outPos = 0; inputPos < input.Length; inputPos++)
        {
            Array.Clear(inputBlock, 0, inputBlock.Length);
            //Array.Copy(input, inputPos, inputBlock, 0, Math.Min(inputBlock.Length, input.Length - inputPos));
            //inputPos += inputBlock.Length;
            for (var i = 0; i < inputBlock.Length && inputPos < input.Length; i++, inputPos++)
                inputBlock[i] = input[inputPos];

            BlockCipher.Encrypt(new ArraySegment<byte>(inputBlock), new ArraySegment<byte>(outBlock));

            for (var i = 0; i < outBlock.Length && outPos < output.Length; i++)
            {
                //output.Array[output.Offset + outPos++] = outBlock[i];
                output[outPos++] = outBlock[i];
            }
        }
    }

    public void Decrypt(in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        var inputBlock = new byte[BlockCipher.InputBlockSize];
        var outBlock = new byte[BlockCipher.OutBlockSize];

        for (int inputPos = 0, outPos = 0; inputPos < input.Length; inputPos++)
        {
            Array.Clear(inputBlock, 0, inputBlock.Length);
            //Array.Copy(input.Array, input.Offset + inputPos, inputBlock, 0, Math.Min(inputBlock.Length, input.Count - inputPos));
            //inputPos += inputBlock.Length;
            for (var i = 0; i < inputBlock.Length && inputPos < input.Length; i++, inputPos++)
                inputBlock[i] = input[inputPos];

            BlockCipher.Decrypt(new ArraySegment<byte>(inputBlock), new ArraySegment<byte>(outBlock));

            for (var i = 0; i < outBlock.Length && outPos < output.Length; i++)
            {
                //output.Array[output.Offset + outPos++] = outBlock[i];
                output[outPos++] = outBlock[i];
            }
        }
    }
}
