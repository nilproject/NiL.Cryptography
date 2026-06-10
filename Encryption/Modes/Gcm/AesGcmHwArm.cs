using System;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics;
using System.Diagnostics;
using AesNeon = System.Runtime.Intrinsics.Arm.Aes;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

internal unsafe class AesGcmHwArm : IAesGcmHwBase
{
    private delegate void EncryptAction(byte* input, byte* output);

    private readonly GHash _gHash;
    private readonly GCtr _gCtr;
    private readonly Aes _aes;

    public AesGcmHwArm(GHash gHash, GCtr gCtr, Aes aes)
    {
        _gHash = gHash;
        _gCtr = gCtr;
        _aes = aes;
    }

    public void Crypt(
        bool encrypt,
        in ReadOnlySpan<byte> authData,
        in ReadOnlySpan<byte> iv,
        in ReadOnlySpan<byte> input,
        in Span<byte> output,
        in Span<byte> authTag)
    {
        if (output.Length != input.Length)
            throw new ArgumentOutOfRangeException();

        var lengthsBuffer = stackalloc long[2];
        lengthsBuffer[1] = authData.Length * 8;
        lengthsBuffer[0] = input.Length * 8;
        for (var i = 0; i < 8; i++)
        {
            var t = ((byte*)lengthsBuffer)[i];
            ((byte*)lengthsBuffer)[i] = ((byte*)lengthsBuffer)[15 - i];
            ((byte*)lengthsBuffer)[15 - i] = t;
        }

        var gHash = _gHash.Invoke(authData, default);

        var j = new GcmFieldElement();
        fixed (byte* n = iv)
        {
            j.L[0] = ((ulong*)n)[0];
            j.I[2] = ((uint*)n)[2];
        }

        j.B[15] = 2;

        *(Vector128<byte>*)&gHash = encode(encrypt, (byte*)&j, input, output, gHash);

        gHash = _gHash.Invoke(new Span<byte>(lengthsBuffer, 16), gHash);

        var ps = new Span<byte>((byte*)&gHash, 16);

        j.I[3] = 1 << 24;

        _gCtr.Invoke(j, ps, ps);

        var c = Math.Min(authTag.Length, 16);
        for (var i = 0; i < c; i++)
            authTag[i] = ps[i];
    }

    private Vector128<byte> encode(bool encrypt, byte* counterBytes, in ReadOnlySpan<byte> input, Span<byte> output, GcmFieldElement gHash)
    {
        Vector128<byte> encodedCounterBytes = default;

        var vv = _gHash.H;
        var vv2 = vv;
        Vector64<ulong> e1ul2 = default;
        ((ulong*)&e1ul2)[0] = 0xe1ul << 2;

        var ghash = AdvSimd.ReverseElement8(*(Vector128<ulong>*)&gHash);

        fixed (byte* pOutput = output)
        fixed (byte* pInput = input)
        {
            {
                var mul = AesNeon.PolynomialMultiplyWideningLower(*(Vector64<ulong>*)&vv2, e1ul2);
                vv2.L[0] = vv2.L[1] ^ mul[0] << 55;
                vv2.L[1] = mul[1] << 55 | mul[0] >> 9;
            }

            _aes.EncryptArm(counterBytes, (byte*)&encodedCounterBytes);

            _ = ++counterBytes[15] == 0 &&
                ++counterBytes[14] == 0 &&
                ++counterBytes[13] == 0 &&
                ++counterBytes[12] == 0;

            var len = (input.Length & ~15);
            var tail = input.Length & 15;

            Vector128<byte> inputVector = default;
            Vector128<byte> outputVector = default;

            for (var i = 0; ; i += 16)
            {
                if (i >= len)
                {
                    if (tail == 0 || i > len)
                        break;

                    inputVector = *(Vector128<byte>*)&pInput[i];
                    outputVector = AdvSimd.Xor(inputVector, encodedCounterBytes);
                    var temp = *(GcmFieldElement*)&outputVector;
                    while (tail-- > 0)
                    {
                        pOutput[i] = temp.B[i & 15];
                        i++;
                    }

                    while ((i & 15) != 0)
                    {
                        temp.B[i & 15] = 0;
                        i++;
                    }

                    outputVector = *(Vector128<byte>*)&temp;
                }
                else
                {
                    inputVector = *(Vector128<byte>*)&pInput[i];
                    outputVector = AdvSimd.Xor(inputVector, encodedCounterBytes);
                    *(Vector128<byte>*)&pOutput[i] = outputVector;
                }

                _aes.EncryptArm(counterBytes, (byte*)&encodedCounterBytes);

                if (encrypt)
                    inputVector = outputVector;

                {
                    var shuffled = AdvSimd.Xor(ghash, AdvSimd.ReverseElement8(*(Vector128<ulong>*)&inputVector));
                    var temp2 = AdvSimd.LoadVector128((ulong*)&vv2);
                    var temp4 = AesNeon.PolynomialMultiplyWideningUpper(temp2, shuffled);
                    temp2 = AesNeon.PolynomialMultiplyWideningUpper(AdvSimd.ExtractVector128(temp2, temp2, 1), shuffled);

                    shuffled = AdvSimd.ExtractVector128(shuffled, shuffled, 1);

                    var temp = AdvSimd.LoadVector128((ulong*)&vv);
                    var temp3 = AesNeon.PolynomialMultiplyWideningUpper(temp, shuffled);
                    temp = AesNeon.PolynomialMultiplyWideningUpper(AdvSimd.ExtractVector128(temp, temp, 1), shuffled);

                    var product0 = AdvSimd.Xor(temp, temp2);
                    var product1 = AdvSimd.Xor(temp3, temp4);

                    var data = default(GcmFieldElement);
                    AdvSimd.Store((ulong*)&data, product0);
                    var low0 = data.L[0];

                    if (low0 > long.MaxValue)
                        product0 = AdvSimd.ShiftRightLogical(AdvSimd.ShiftLeftLogical(product0, 1), 1);

                    product0 = AesNeon.PolynomialMultiplyWideningLower(*(Vector64<ulong>*)&product0, e1ul2);

                    var high0 = data.L[1];

                    AdvSimd.Store((ulong*)&data, product0);
                    var high1 = (data.L[1] << 56) | (data.L[0] >> 8);
                    var low1 = data.L[0] << 56;

                    AdvSimd.Store((ulong*)&data, product1);
                    high0 ^= data.L[0];
                    var high2 = data.L[1];

                    ghash = Vector128.Create(
                            high1 ^ (high2 + high2) ^ (high0 >> 63),
                            low1 ^ (high0 + high0) ^ (low0 >> 63));
                }

                _ = ++counterBytes[15] == 0 &&
                    ++counterBytes[14] == 0 &&
                    ++counterBytes[13] == 0 &&
                    ++counterBytes[12] == 0;
            }

            ghash = AdvSimd.ReverseElement8(ghash);
            return *(Vector128<byte>*)&ghash;
        }
    }
}
