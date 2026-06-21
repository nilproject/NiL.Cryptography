using System;

namespace NiL.Cryptography.Encryption;

public sealed class TripleDes : IBlockCipher
{
    private Des _des0;
    private Des _des1;
    private Des _des2;

    public TripleDes(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException(nameof(key));

        Key = key;
    }

    public int InputBlockSize => 8;

    public int OutBlockSize => 8;
    public byte[] Key
    {
        get => _des0.Key;
        set
        {
            if (value.Length % 8 != 0 || value.Length == 0 || value.Length / 8 > 3)
                throw new ArgumentException();

            var roundKey = new byte[8];

            Array.Copy(value, 0, roundKey, 0, 8);
            _des0 = new Des((byte[])roundKey.Clone());

            Array.Copy(value, 8 % value.Length, roundKey, 0, 8);
            _des1 = new Des((byte[])roundKey.Clone());

            Array.Copy(value, 16 % value.Length, roundKey, 0, 8);
            _des2 = new Des(roundKey);
        }
    }

    public void Decrypt(in ReadOnlySpan<byte> input, in Span<byte> output)
    {

        if (input.Length != 8)
            throw new ArgumentException();
        if (output.Length != 8)
            throw new ArgumentException();

        _des2.Decrypt(input, output);
        _des1.Encrypt(output, output);
        _des0.Decrypt(output, output);
    }

    public void Encrypt(in ReadOnlySpan<byte> input, in Span<byte> output)
    {
        if (input.Length != 8)
            throw new ArgumentException();
        if (output.Length != 8)
            throw new ArgumentException();

        _des0.Encrypt(input, output);
        _des1.Decrypt(output, output);
        _des2.Encrypt(output, output);
    }
}
