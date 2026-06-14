using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

[StructLayout(LayoutKind.Explicit)]
public unsafe struct GcmFieldElement
{
    [FieldOffset(0)]
    private ulong _l0;

    [FieldOffset(8)]
    private ulong _l1;

    [FieldOffset(0)]
    public fixed ulong L[2];

    [FieldOffset(0)]
    public fixed uint I[4];

    [FieldOffset(0)]
    public fixed byte B[16];

    public GcmFieldElement(ulong low, ulong high) : this()
    {
        L[0] = low;
        L[1] = high;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public override string ToString()
    {
        var result = new string[32];
        for (var i = 32; i-- > 0;)
        {
            result[i] = (B[i >> 1] >> 4 * (i & 1) & 0xf).ToString("x1");
            if (i == 16)
                result[i] = "_" + result[i];
        }

        return string.Concat(result);
    }

    public static GcmFieldElement operator ^(GcmFieldElement left, GcmFieldElement right)
        => new GcmFieldElement(left.L[0] ^ right.L[0], left.L[1] ^ right.L[1]);
}

public sealed class GcmMode : IAeadCipher
{
    private readonly IBlockCipher _blockCipher;
    private readonly GHash _gHash;
    private readonly GCtr _gCtr;
    private IAesGcmHwBase _aesGcmHw;

    public int InputBlockSize => _blockCipher.InputBlockSize;
    public int OutBlockSize => _blockCipher.OutBlockSize;
    public byte[] Key
    {
        get => _blockCipher.Key;
    }

    public GcmMode(IBlockCipher blockCipher)
    {
        if (blockCipher.OutBlockSize != 16)
            throw new NotSupportedException("Block sizes other than 16 are not supported");

        _blockCipher = blockCipher;
        _gHash = new GHash(blockCipher);
        _gCtr = new GCtr(blockCipher);

        if (blockCipher is Aes aes)
        {
            if (Sse3.IsSupported && System.Runtime.Intrinsics.X86.Aes.IsSupported)
                _aesGcmHw = new AesGcmHwX86(_gHash, _gCtr, aes);
            else if (System.Runtime.Intrinsics.Arm.Aes.IsSupported)
                _aesGcmHw = new AesGcmHwArm(_gHash, _gCtr, aes);
        }
    }

    public void Decrypt(
        in ReadOnlySpan<byte> authData,
        in ReadOnlySpan<byte> iv,
        in ReadOnlySpan<byte> input,
        in Span<byte> output,
        in Span<byte> authTag)
    {
        crypt(false, authData, iv, input, output, authTag);
    }

    public void Encrypt(
        in ReadOnlySpan<byte> authData,
        in ReadOnlySpan<byte> iv,
        in ReadOnlySpan<byte> input,
        in Span<byte> output,
        in Span<byte> authTag)
    {
        crypt(true, authData, iv, input, output, authTag);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private unsafe void crypt(
        bool encrypt,
        in ReadOnlySpan<byte> authData,
        in ReadOnlySpan<byte> iv,
        in ReadOnlySpan<byte> input,
        in Span<byte> output,
        in Span<byte> authTag)
    {
        if (_aesGcmHw is not null)
        {
            _aesGcmHw.Crypt(encrypt, authData, iv, input, output, authTag);
            return;
        }

        if (output.Length != input.Length)
            throw new ArgumentOutOfRangeException();

        var gHash = _gHash.Invoke(authData, default);

        var dataToTag = encrypt ? output : input;

        var j = new GcmFieldElement();
        fixed (byte* n = iv)
        {
            j.L[0] = ((ulong*)n)[0];
            j.I[2] = ((uint*)n)[2];
        }

        j.B[15] = 2;

        _gCtr.Invoke(j, input, output);

        var lengthsBuffer = stackalloc long[2];
        lengthsBuffer[1] = authData.Length * 8;
        lengthsBuffer[0] = dataToTag.Length * 8;
        for (var i = 0; i < 8; i++)
        {
            var t = ((byte*)lengthsBuffer)[i];
            ((byte*)lengthsBuffer)[i] = ((byte*)lengthsBuffer)[15 - i];
            ((byte*)lengthsBuffer)[15 - i] = t;
        }

        gHash = _gHash.Invoke(dataToTag, gHash);
        gHash = _gHash.Invoke(new Span<byte>(lengthsBuffer, 16), gHash);

        var ps = new Span<byte>((byte*)&gHash, 16);

        j.I[3] = 1 << 24;

        _gCtr.Invoke(j, ps, ps);

        var c = Math.Min(authTag.Length, 16);
        for (var i = 0; i < c; i++)
            authTag[i] = ps[i];
    }

#if DEBUG
    //private readonly List<Vector128<byte>> _debug = new List<Vector128<byte>>();
#endif

}
