using System;
using System.Diagnostics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using AesNi = System.Runtime.Intrinsics.X86.Aes;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

internal unsafe class AesGcmHwX86 : IAesGcmHwBase
{
    private readonly bool _isCarryLessMulSupported = Pclmulqdq.IsSupported;
    //private readonly bool _isCarryLessMulSupported = false;

    private delegate void EncryptAction(byte* input, byte* output);

    private readonly GHash _gHash;
    private readonly GCtr _gCtr;
    private readonly Aes _aes;

    public AesGcmHwX86(GHash gHash, GCtr gCtr, Aes aes)
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

    //private ulong _commonCounter = 0;
    //private List<(ulong mask, long count)> _counters = Enumerable
    //    .Range(0, 64 * 64 * 64)
    //    .Select(i =>
    //    {
    //        var bitIndex0 = i >> 12;
    //        var bitIndex1 = (i >> 6) & 63;
    //        var bitIndex2 = (i) & 63;
    //        var mask = (1UL << bitIndex0) | (1UL << bitIndex1) | (1UL << bitIndex2);
    //        return (mask, 0L);
    //    })
    //    .Distinct()
    //    .ToList();

    private Vector128<byte> encode(bool encrypt, byte* counterBytes, in ReadOnlySpan<byte> input, Span<byte> output, GcmFieldElement gHash)
    {
        Vector128<byte> encodedCounterBytes = default;

        var vv = _gHash.H;
        var vv2 = vv;
        Vector128<ulong> e1ul2 = default;
        Vector128<ulong> mask = default;
        ((ulong*)&e1ul2)[0] = 0xe1ul << 2;

        ((ulong*)&mask)[0] = 0x08_09_0a_0b_0c_0d_0e_0f;
        ((ulong*)&mask)[1] = 0x00_01_02_03_04_05_06_07;
        var ghash = _isCarryLessMulSupported ? Ssse3.Shuffle(*(Vector128<byte>*)&gHash, *(Vector128<byte>*)&mask) : *(Vector128<byte>*)&gHash;

        Vector128<byte> key = default;

        fixed (GcmFieldElement* zPreComputed0 = _gHash.ZPreComputed)
        fixed (byte* pOutput = output)
        fixed (byte* pInput = input)
        fixed (uint* keySchedule = _aes._keySchedule)
        {
            if (_isCarryLessMulSupported)
            {
                var mul = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&vv2, e1ul2, 0);
                vv2.L[0] = vv2.L[1] ^ mul[0] << 55;
                vv2.L[1] = mul[1] << 55 | mul[0] >> 9;
            }

            var keySize = (_aes._keySchedule.Length - 44) / 8;

            switch (keySize)
            {
                case 0: Aes.X86Encrypt10(counterBytes, (byte*)&encodedCounterBytes, (byte*)keySchedule); break;
                case 1: Aes.X86Encrypt12(counterBytes, (byte*)&encodedCounterBytes, (byte*)keySchedule); break;
                case 2: Aes.X86Encrypt14(counterBytes, (byte*)&encodedCounterBytes, (byte*)keySchedule); break;
            }

            _ = ++counterBytes[15] == 0 &&
                ++counterBytes[14] == 0 &&
                ++counterBytes[13] == 0 &&
                ++counterBytes[12] == 0;

            //if (false)
            {
                var len = input.Length & ~15;
                ((ulong*)counterBytes)[0] ^= *(ulong*)&keySchedule[0];
                ((uint*)counterBytes)[2] ^= keySchedule[2];
                for (var dataIndex = 0; dataIndex < len;)
                {
                    uint cnt = (uint)(counterBytes[15] | counterBytes[14] << 8 | counterBytes[13] << 16 | counterBytes[12] << 24);
                    var cntHigh = *(ushort*)&counterBytes[12] ^ keySchedule[3];

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
                        _ = ++counterBytes[15] == 0 &&
                            ++counterBytes[14] == 0 &&
                            ++counterBytes[13] == 0 &&
                            ++counterBytes[12] == 0;
                    }
                }

                ((ulong*)counterBytes)[0] ^= *(ulong*)&keySchedule[0];
                ((uint*)counterBytes)[2] ^= keySchedule[2];

                if (keySize == 1)
                {
                    var ks1 = *(Vector128<byte>*)&keySchedule[4 * 1];
                    var ks2 = *(Vector128<byte>*)&keySchedule[4 * 2];
                    var ks3 = *(Vector128<byte>*)&keySchedule[4 * 3];
                    var ks4 = *(Vector128<byte>*)&keySchedule[4 * 4];
                    var ks5 = *(Vector128<byte>*)&keySchedule[4 * 5];
                    var ks6 = *(Vector128<byte>*)&keySchedule[4 * 6];
                    var ks7 = *(Vector128<byte>*)&keySchedule[4 * 7];
                    var ks8 = *(Vector128<byte>*)&keySchedule[4 * 8];
                    var ks9 = *(Vector128<byte>*)&keySchedule[4 * 9];
                    var ks10 = *(Vector128<byte>*)&keySchedule[4 * 10];
                    var ks11 = *(Vector128<byte>*)&keySchedule[4 * 11];
                    for (var i = 0; i < len; i += 16)
                    {
                        var temp = AesNi.Encrypt(*(Vector128<byte>*)&pOutput[i], ks1);
                        Sse.Prefetch2(&pOutput[i + 1]);
                        temp = AesNi.Encrypt(temp, ks2);
                        temp = AesNi.Encrypt(temp, ks3);
                        temp = AesNi.Encrypt(temp, ks4);
                        temp = AesNi.Encrypt(temp, ks5);
                        temp = AesNi.Encrypt(temp, ks6);
                        temp = AesNi.Encrypt(temp, ks7);
                        temp = AesNi.Encrypt(temp, ks8);
                        temp = AesNi.Encrypt(temp, ks9);
                        temp = AesNi.Encrypt(temp, ks10);
                        Sse2.Store(&pOutput[i], temp);
                    }

                    key = *(Vector128<byte>*)&keySchedule[4 * 12];
                }
                else if (keySize == 2)
                {
                    var ks1 = *(Vector128<byte>*)&keySchedule[4 * 1];
                    var ks2 = *(Vector128<byte>*)&keySchedule[4 * 2];
                    var ks3 = *(Vector128<byte>*)&keySchedule[4 * 3];
                    var ks4 = *(Vector128<byte>*)&keySchedule[4 * 4];
                    var ks5 = *(Vector128<byte>*)&keySchedule[4 * 5];
                    var ks6 = *(Vector128<byte>*)&keySchedule[4 * 6];
                    var ks7 = *(Vector128<byte>*)&keySchedule[4 * 7];
                    var ks8 = *(Vector128<byte>*)&keySchedule[4 * 8];
                    var ks9 = *(Vector128<byte>*)&keySchedule[4 * 9];
                    var ks10 = *(Vector128<byte>*)&keySchedule[4 * 10];
                    var ks11 = *(Vector128<byte>*)&keySchedule[4 * 11];
                    var ks12 = *(Vector128<byte>*)&keySchedule[4 * 12];
                    var ks13 = *(Vector128<byte>*)&keySchedule[4 * 13];
                    for (var i = 0; i < len; i += 16)
                    {
                        var temp = AesNi.Encrypt(*(Vector128<byte>*)&pOutput[i], ks1);
                        Sse.Prefetch2(&pOutput[i + 1]);
                        temp = AesNi.Encrypt(temp, ks2);
                        temp = AesNi.Encrypt(temp, ks3);
                        temp = AesNi.Encrypt(temp, ks4);
                        temp = AesNi.Encrypt(temp, ks5);
                        temp = AesNi.Encrypt(temp, ks6);
                        temp = AesNi.Encrypt(temp, ks7);
                        temp = AesNi.Encrypt(temp, ks8);
                        temp = AesNi.Encrypt(temp, ks9);
                        temp = AesNi.Encrypt(temp, ks10);
                        temp = AesNi.Encrypt(temp, ks11);
                        temp = AesNi.Encrypt(temp, ks12);
                        temp = AesNi.Encrypt(temp, ks13);
                        Sse2.Store(&pOutput[i], temp);
                    }

                    key = *(Vector128<byte>*)&keySchedule[4 * 14];
                }
                else
                {
                    var ks1 = *(Vector128<byte>*)&keySchedule[4 * 1];
                    var ks2 = *(Vector128<byte>*)&keySchedule[4 * 2];
                    var ks3 = *(Vector128<byte>*)&keySchedule[4 * 3];
                    var ks4 = *(Vector128<byte>*)&keySchedule[4 * 4];
                    var ks5 = *(Vector128<byte>*)&keySchedule[4 * 5];
                    var ks6 = *(Vector128<byte>*)&keySchedule[4 * 6];
                    var ks7 = *(Vector128<byte>*)&keySchedule[4 * 7];
                    var ks8 = *(Vector128<byte>*)&keySchedule[4 * 8];
                    var ks9 = *(Vector128<byte>*)&keySchedule[4 * 9];
                    for (var i = 0; i < len; i += 16)
                    {
                        var temp = AesNi.Encrypt(*(Vector128<byte>*)&pOutput[i], ks1);
                        Sse.Prefetch2(&pOutput[i + 1]);
                        temp = AesNi.Encrypt(temp, ks2);
                        temp = AesNi.Encrypt(temp, ks3);
                        temp = AesNi.Encrypt(temp, ks4);
                        temp = AesNi.Encrypt(temp, ks5);
                        temp = AesNi.Encrypt(temp, ks6);
                        temp = AesNi.Encrypt(temp, ks7);
                        temp = AesNi.Encrypt(temp, ks8);
                        temp = AesNi.Encrypt(temp, ks9);
                        Sse2.Store(&pOutput[i], temp);
                    }

                    key = *(Vector128<byte>*)&keySchedule[4 * 10];
                }
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

                    outputVector = Sse2.Xor(encodedCounterBytes, inputVector);

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
                    outputVector = Sse2.Xor(inputVector, encodedCounterBytes);

                    ref var data = ref *(Vector128<byte>*)&pOutput[i];
                    encodedCounterBytes = AesNi.EncryptLast(data, key);
                    //encodedCounterBytes = data;

                    data = outputVector;
                }

                if (encrypt)
                    inputVector = outputVector;

                if (_isCarryLessMulSupported)
                {
                    outputVector = *(Vector128<byte>*)&vv2;

                    var shuffled = Sse2.Xor(ghash, Ssse3.Shuffle(inputVector, *(Vector128<byte>*)&mask));

                    inputVector = *(Vector128<byte>*)&vv;

                    var temp = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&inputVector, *(Vector128<ulong>*)&shuffled, 0x10);
                    var temp2 = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&outputVector, *(Vector128<ulong>*)&shuffled, 0x00);
                    var temp3 = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&inputVector, *(Vector128<ulong>*)&shuffled, 0x11);
                    var temp4 = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&outputVector, *(Vector128<ulong>*)&shuffled, 0x01);

                    var product0 = Sse2.Xor(temp, temp2);
                    var product1 = Sse2.Xor(temp3, temp4);

                    var data = default(GcmFieldElement);
                    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product0);
                    var low = data.L[0];
                    var high = data.L[1];

                    product0 = Sse2.ShiftLeftLogical(product0, 1);
                    product0 = Sse2.ShiftRightLogical(product0, 1);
                    temp = Pclmulqdq.CarrylessMultiply(product0, e1ul2, 0);
                    product0 = Sse2.ShiftLeftLogical128BitLane(temp, 7);

                    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product1);
                    high ^= data.L[0];
                    var high1 = data.L[1];

                    *(Vector128<ulong>*)&ghash = Sse2.Xor(
                        product0,
                        Vector128.Create((high + high) ^ low >> 63, (high1 + high1) ^ high >> 63));
                }
                else
                {
                    var temp = Sse2.Xor(ghash, inputVector);
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

                    t = Sse2.Xor(zprec0[(byte)x0], zprec1[(byte)x1]);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 8], zprec1[0xff & x1 >> 8]), t);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 16], zprec1[0xff & x1 >> 16]), t);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 24], zprec1[0xff & x1 >> 24]), t);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 32], zprec1[0xff & x1 >> 32]), t);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 40], zprec1[0xff & x1 >> 40]), t);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 48], zprec1[0xff & x1 >> 48]), t);
                    t = Sse2.Xor(Sse2.Xor(zprec0[0xff & x0 >> 56], zprec1[0xff & x1 >> 56]), t);

                    x0 = (*(GcmFieldElement*)&temp).L[1];
                    x1 = x0 & 0x0f0f0f0f0f0f0f0ful;
                    x0 &= 0xf0f0f0f0f0f0f0f0ul;
                    x0 >>= 4;
                    x0 |= 0xf0e0_d0c0_b0a0_9080;
                    x1 |= 0xf0e0_d0c0_b0a0_9080;

                    t = Sse2.Xor(t, Sse2.Xor(zprec0[(byte)x0], zprec1[(byte)x1]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 8], zprec1[0xff & x1 >> 8]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 16], zprec1[0xff & x1 >> 16]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 24], zprec1[0xff & x1 >> 24]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 32], zprec1[0xff & x1 >> 32]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 40], zprec1[0xff & x1 >> 40]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 48], zprec1[0xff & x1 >> 48]));
                    t = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 56], zprec1[0xff & x1 >> 56]));
                    ghash = t;
                }
            }

            //_counters.Sort((x, y) => Math.Sign(x.count - y.count));

            //var ttest = _counters.Select(x => (x.mask.ToString("x2"), x.count / (float)_commonCounter)).ToList();

            if (_isCarryLessMulSupported)
                return Ssse3.Shuffle(ghash, *(Vector128<byte>*)&mask);

            return ghash;
        }
    }
}
