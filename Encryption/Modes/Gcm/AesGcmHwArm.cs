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
        Vector128<long> e1ul2 = default;
        Vector128<long> mask = default;
        ((ulong*)&e1ul2)[0] = 0xe1ul << 2;

        //var ghash = AdvSimd.ReverseElement32(*(Vector128<long>*)&gHash);
        var ghash = *(Vector128<byte>*)&gHash;

        Vector128<byte> key = default;

        fixed (GcmFieldElement* zPreComputed0 = _gHash.ZPreComputed)
        fixed (byte* pOutput = output)
        fixed (byte* pInput = input)
        fixed (uint* keySchedule = _aes._keySchedule)
        {
            //{
            //    var mul = AesNeon.PolynomialMultiplyWideningLower(*(Vector64<long>*)&vv2, *(Vector64<long>*)&e1ul2);
            //    vv2.L[0] = vv2.L[1] ^ (ulong)mul[0] << 55;
            //    vv2.L[1] = (ulong)mul[1] << 55 | (ulong)mul[0] >> 9;
            //}

            var keySize = (_aes._keySchedule.Length - 44) / 8;

            _aes.EncryptArm(counterBytes, (byte*)&encodedCounterBytes);

            if (++counterBytes[15] == 0
                && ++counterBytes[14] == 0
                && ++counterBytes[13] == 0)
                counterBytes[12]++;

            //if (false)
            {
                var len = input.Length & ~15;
                for (var dataIndex = 0; dataIndex < len;)
                {
                    uint cnt = (uint)(counterBytes[15] | counterBytes[14] << 8 | counterBytes[13] << 16 | counterBytes[12] << 24);
                    var cntHigh = *(ushort*)&counterBytes[12];

                    while (dataIndex < len)
                    {
                        *(ulong*)&pOutput[dataIndex] = ((ulong*)counterBytes)[0];
                        *(ulong*)&pOutput[dataIndex + 8] = ((uint*)counterBytes)[2] | (ulong)((cnt << 24 | (cnt & 0xff00) << 8) ^ cntHigh) << 32;
                        cnt++;
                        dataIndex += 16;

                        if ((cnt & 0xffff) == 0)
                            break;
                    }

                    if ((cnt & 0xffff) == 0)
                    {
                        counterBytes[15] = 0;
                        counterBytes[14] = 0;
                        if (++counterBytes[13] == 0)
                            counterBytes[12]++;
                    }
                }

                var ks = keySchedule + keySize * 4 * 2;
                for (var k = -keySize * 2; k < 9; k += 2)
                {
                    var ks0 = *(Vector128<byte>*)&ks[4 * k];
                    var ks1 = *(Vector128<byte>*)&ks[4 * (k + 1)];
                    for (var i = 0; i < len; i += 16)
                    {
                        var temp = AesNeon.Encrypt(*(Vector128<byte>*)&pOutput[i], ks0);
                        temp = AesNeon.MixColumns(temp);
                        temp = AesNeon.Encrypt(temp, ks1);
                        if (k != 8) temp = AesNeon.MixColumns(temp);

                        *(Vector128<byte>*)&pOutput[i] = temp;
                    }
                }

                key = *(Vector128<byte>*)&ks[4 * 10];
            }

            for (int i = 0, len = input.Length; i < len; i += 16)
            {
                Vector128<byte> inputVector = default;
                Vector128<byte> outputVector = default;
                if (len - i < 16)
                {
                    var temp = *(Vector128<byte>*)&pInput[i];

                    var delta = 16 - (len - i);
                    while (delta-- > 0)
                        ((byte*)&temp)[15 - delta] = 0;

                    inputVector = temp;

                    outputVector = AdvSimd.Xor(encodedCounterBytes, inputVector);

                    temp = outputVector;

                    delta = 16 - (input.Length - i);
                    while (delta-- > 0)
                        ((byte*)&temp)[15 - delta] = 0;

                    outputVector = temp;

                    delta = input.Length - i;
                    while (delta-- > 0)
                        pOutput[i + delta] = ((byte*)&temp)[delta];
                }
                else
                {
                    inputVector = *(Vector128<byte>*)&pInput[i];
                    outputVector = AdvSimd.Xor(inputVector, encodedCounterBytes);

                    ref var data = ref *(Vector128<byte>*)&pOutput[i];
                    encodedCounterBytes = AdvSimd.Xor(data, key);

                    data = outputVector;
                }

                if (encrypt)
                    inputVector = outputVector;

                //if (_isCarryLessMulSupported)
                //{
                //    outputVector = *(Vector128<byte>*)&vv2;

                //    var shuffled = Sse2.Xor(ghash, Ssse3.Shuffle(inputVector, *(Vector128<byte>*)&mask));

                //    inputVector = *(Vector128<byte>*)&vv;

                //    var product0 = Sse2.Xor(
                //        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&inputVector, *(Vector128<ulong>*)&shuffled, 0x10),
                //        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&outputVector, *(Vector128<ulong>*)&shuffled, 0x00));

                //    var product1 = Sse2.Xor(
                //        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&inputVector, *(Vector128<ulong>*)&shuffled, 0x11),
                //        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&outputVector, *(Vector128<ulong>*)&shuffled, 0x01));

                //    var data = default(GcmFieldElement);
                //    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product0);
                //    var low = data.L[0];
                //    var high = data.L[1];

                //    product0 = Sse2.ShiftRightLogical(Sse2.ShiftLeftLogical(product0, 1), 1);
                //    product0 = Sse2.ShiftLeftLogical128BitLane(Pclmulqdq.CarrylessMultiply(product0, e1ul2, 0), 7);

                //    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product1);
                //    high ^= data.L[0];
                //    var high1 = data.L[1];

                //    *(Vector128<ulong>*)&ghash = Sse2.Xor(
                //        product0,
                //        Vector128.Create((high + high) ^ low >> 63, (high1 + high1) ^ high >> 63));
                //}
                //else
                {
                    var temp = AdvSimd.Xor(ghash, inputVector);
                    var zprec0 = (Vector128<byte>*)zPreComputed0;
                    var zprec1 = (Vector128<byte>*)(zPreComputed0 + 256);
                    ulong x0, x1;
                    Vector128<byte> t;
                    x0 = (*(GcmFieldElement*)&temp).L[0];
                    x1 = x0 & 0x0f0f0f0f0f0f0f0ful;
                    x0 &= 0xf0f0_f0f0_f0f0_f0f0ul;
                    x0 >>= 4;

                    x0 |= 0x7060_5040_3020_1000;
                    x1 |= 0x7060_5040_3020_1000;

                    t = AdvSimd.Xor(zprec0[(byte)x0], zprec1[(byte)x1]);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 8], zprec1[0xff & x1 >> 8]), t);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 16], zprec1[0xff & x1 >> 16]), t);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 24], zprec1[0xff & x1 >> 24]), t);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 32], zprec1[0xff & x1 >> 32]), t);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 40], zprec1[0xff & x1 >> 40]), t);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 48], zprec1[0xff & x1 >> 48]), t);
                    t = AdvSimd.Xor(AdvSimd.Xor(zprec0[0xff & x0 >> 56], zprec1[0xff & x1 >> 56]), t);

                    x0 = (*(GcmFieldElement*)&temp).L[1];
                    x1 = x0 & 0x0f0f0f0f0f0f0f0ful;
                    x0 &= 0xf0f0f0f0f0f0f0f0ul;
                    x0 >>= 4;
                    x0 |= 0xf0e0_d0c0_b0a0_9080;
                    x1 |= 0xf0e0_d0c0_b0a0_9080;

                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[(byte)x0], zprec1[(byte)x1]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 8], zprec1[0xff & x1 >> 8]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 16], zprec1[0xff & x1 >> 16]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 24], zprec1[0xff & x1 >> 24]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 32], zprec1[0xff & x1 >> 32]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 40], zprec1[0xff & x1 >> 40]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 48], zprec1[0xff & x1 >> 48]));
                    t = AdvSimd.Xor(t, AdvSimd.Xor(zprec0[0xff & x0 >> 56], zprec1[0xff & x1 >> 56]));
                    ghash = t;
                }
            }

            //_counters.Sort((x, y) => Math.Sign(x.count - y.count));

            //var ttest = _counters.Select(x => (x.mask.ToString("x2"), x.count / (float)_commonCounter)).ToList();

            //if (_isCarryLessMulSupported)
            //    return Ssse3.Shuffle(ghash, *(Vector128<byte>*)&mask);

            return ghash;
        }
    }
}
