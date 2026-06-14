using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
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
        var test = new List<Vector128<ulong>>();

        var vv = _gHash.H;
        var vv2 = *(Vector128<ulong>*)&vv;
        Vector64<ulong> e1ul2 = default;
        ((ulong*)&e1ul2)[0] = 0xe1ul << 2;

        var ghash = AdvSimd.ReverseElement8(*(Vector128<ulong>*)&gHash);

        fixed (byte* pOutput = output)
        fixed (byte* pInput = input)
        {
            {
                var mul = AesNeon.PolynomialMultiplyWideningLower(*(Vector64<ulong>*)&vv2, e1ul2);
                vv2 = Vector128.Create(AdvSimd.Extract(vv2, 1) ^ mul[0] << 55, mul[1] << 55 | mul[0] >> 9);
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

                    if (encrypt)
                    {
                        while ((i & 15) != 0)
                        {
                            temp.B[i & 15] = 0;
                            i++;
                        }

                        inputVector = *(Vector128<byte>*)&temp;
                    }
                    else
                    {
                        *(Vector128<byte>*)&temp = inputVector;

                        while ((i & 15) != 0)
                        {
                            temp.B[i & 15] = 0;
                            i++;
                        }

                        inputVector = *(Vector128<byte>*)&temp;
                    }
                }
                else
                {
                    inputVector = *(Vector128<byte>*)&pInput[i];
                    outputVector = AdvSimd.Xor(inputVector, encodedCounterBytes);
                    *(Vector128<byte>*)&pOutput[i] = outputVector;

                    if (encrypt)
                        inputVector = outputVector;
                }

                _aes.EncryptArm(counterBytes, (byte*)&encodedCounterBytes);

                {
                    var shuffled = AdvSimd.Xor(ghash, AdvSimd.ReverseElement8(*(Vector128<ulong>*)&inputVector));
                    var temp4 = AesNeon.PolynomialMultiplyWideningUpper(vv2, shuffled);
                    var temp2 = AesNeon.PolynomialMultiplyWideningUpper(AdvSimd.ExtractVector128(vv2, vv2, 1), shuffled);

                    shuffled = AdvSimd.ExtractVector128(shuffled, shuffled, 1);

                    var temp = AdvSimd.LoadVector128((ulong*)&vv);
                    var temp3 = AesNeon.PolynomialMultiplyWideningUpper(temp, shuffled);
                    temp = AesNeon.PolynomialMultiplyWideningUpper(AdvSimd.ExtractVector128(temp, temp, 1), shuffled);

                    temp = AdvSimd.Xor(temp, temp2);
                    temp3 = AdvSimd.Xor(temp3, temp4);

                    var data = default(GcmFieldElement);
                    AdvSimd.Store((ulong*)&data, temp);
                    var low0 = data.L[0];
                    var high0 = data.L[1];

                    temp = AdvSimd.ShiftRightLogical(AdvSimd.ShiftLeftLogical(temp, 1), 1);
                    temp = AesNeon.PolynomialMultiplyWideningLower(*(Vector64<ulong>*)&temp, e1ul2);

                    AdvSimd.Store((ulong*)&data, temp);
                    var high1 = (data.L[1] << 56) | (data.L[0] >> 8);
                    var low1 = data.L[0] << 56;

                    AdvSimd.Store((ulong*)&data, temp3);
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
