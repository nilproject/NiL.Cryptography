using System;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using AesNi = System.Runtime.Intrinsics.X86.Aes;
using System.Diagnostics;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

internal unsafe class AesGcmHw
{
    private readonly bool _isCarryLessMulSupported = Pclmulqdq.IsSupported;
    //private readonly bool _isCarryLessMulSupported = false;

    private delegate void EncryptAction(byte* input, byte* output);

    private readonly GHash _gHash;
    private readonly GCtr _gCtr;
    private readonly Aes _aes;

    public AesGcmHw(GHash gHash, GCtr gCtr, Aes aes)
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
            {
                var mul = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&vv2, e1ul2, 0);
                vv2.L[0] = vv2.L[1] ^ mul[0] << 55;
                vv2.L[1] = mul[1] << 55 | mul[0] >> 9;
            }

            var keySize = (_aes._keySchedule.Length - 44) / 8;

            switch (keySize)
            {
                case 0: Aes.hwEncrypt10(counterBytes, (byte*)&encodedCounterBytes, (byte*)keySchedule); break;
                case 1: Aes.hwEncrypt12(counterBytes, (byte*)&encodedCounterBytes, (byte*)keySchedule); break;
                case 2: Aes.hwEncrypt14(counterBytes, (byte*)&encodedCounterBytes, (byte*)keySchedule); break;
            }

            if (++counterBytes[15] == 0
                && ++counterBytes[14] == 0
                && ++counterBytes[13] == 0)
                counterBytes[12]++;

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
                        counterBytes[15] = 0;
                        counterBytes[14] = 0;
                        if (++counterBytes[13] == 0)
                            counterBytes[12]++;
                    }
                }

                ((ulong*)counterBytes)[0] ^= *(ulong*)&keySchedule[0];
                ((uint*)counterBytes)[2] ^= keySchedule[2];

                for (var k = 1; k <= 9; k += 3)
                {
                    var ks0 = *(Vector128<byte>*)&keySchedule[4 * k];
                    var ks1 = *(Vector128<byte>*)&keySchedule[4 * (k + 1)];
                    var ks2 = *(Vector128<byte>*)&keySchedule[4 * (k + 2)];
                    for (var i = 0; i < len; i += 16)
                    {
                        *(Vector128<byte>*)&pOutput[i] = AesNi.Encrypt(AesNi.Encrypt(AesNi.Encrypt(*(Vector128<byte>*)&pOutput[i], ks0), ks1), ks2);
                    }
                }

                if (keySize == 1)
                {
                    var ks0 = *(Vector128<byte>*)&keySchedule[4 * 10];
                    var ks1 = *(Vector128<byte>*)&keySchedule[4 * 11];
                    for (var i = 0; i < len; i += 16)
                    {
                        var data = (Vector128<byte>*)&pOutput[i];
                        *data = AesNi.Encrypt(AesNi.Encrypt(*data, ks0), ks1);
                    }

                    key = *(Vector128<byte>*)&keySchedule[4 * 12];
                }
                else if (keySize == 2)
                {
                    var ks0 = *(Vector128<byte>*)&keySchedule[4 * 10];
                    var ks1 = *(Vector128<byte>*)&keySchedule[4 * 11];
                    var ks2 = *(Vector128<byte>*)&keySchedule[4 * 12];
                    var ks3 = *(Vector128<byte>*)&keySchedule[4 * 13];
                    for (var i = 0; i < len; i += 16)
                    {
                        var data = (Vector128<byte>*)&pOutput[i];
                        *data = AesNi.Encrypt(AesNi.Encrypt(AesNi.Encrypt(AesNi.Encrypt(*data, ks0), ks1), ks2), ks3);
                    }

                    key = *(Vector128<byte>*)&keySchedule[4 * 14];
                }
                else
                    key = *(Vector128<byte>*)&keySchedule[4 * 10];
            }

            var sw = Stopwatch.StartNew();

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

                    //var prevEncoded = encodedCounterBytes;
                    ref var data = ref *(Vector128<byte>*)&pOutput[i];
                    encodedCounterBytes = AesNi.EncryptLast(data, key);

                    //var test = Sse2.Xor(encodedCounterBytes, prevEncoded);

                    //var c0 = Popcnt.X64.PopCount(((ulong*)&test)[0]);
                    //var c1 = Popcnt.X64.PopCount(((ulong*)&test)[1]);

                    //var m = 0b_0000_0000_0000_1000_0000_0000_0000_0000_0000_1000_0000_0000_0000_0000_0000_0000ul;
                    //_counter0v += (((ulong*)&test)[0] & m) == m ? 1ul : 0;
                    //_counter1v += (((ulong*)&test)[1] & m) == m ? 1ul : 0;
                    //_counter0c++;

                    //for (var c = 0; c < _counters.Count; c++)
                    //    _counters[c] = (_counters[c].mask, _counters[c].count + ((_counters[c].mask & ((ulong*)&test)[0]) == _counters[c].mask ? 1L : 0));

                    //_commonCounter++;

                    data = outputVector;
                }

                if (encrypt)
                    inputVector = outputVector;

                if (_isCarryLessMulSupported)
                {
                    var shuffled = Sse2.Xor(ghash, Ssse3.Shuffle(inputVector, *(Vector128<byte>*)&mask));

                    inputVector = *(Vector128<byte>*)&vv;
                    outputVector = *(Vector128<byte>*)&vv2;

                    var product0 = Sse2.Xor(
                        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&inputVector, *(Vector128<ulong>*)&shuffled, 0x10),
                        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&outputVector, *(Vector128<ulong>*)&shuffled, 0x00));

                    var data = default(GcmFieldElement);
                    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product0);
                    var low = data.L[0];
                    var high = data.L[1];

                    var product1 = Sse2.Xor(
                        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&inputVector, *(Vector128<ulong>*)&shuffled, 0x11),
                        Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&outputVector, *(Vector128<ulong>*)&shuffled, 0x01));

                    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product1);

                    high ^= data.L[0];
                    var high1 = data.L[1];

                    product0 = Sse2.ShiftRightLogical(Sse2.Add(product0, product0), 1);
                    product0 = Sse2.ShiftLeftLogical128BitLane(Pclmulqdq.CarrylessMultiply(product0, e1ul2, 0), 7);
                    Sse2.Store((byte*)&data, *(Vector128<byte>*)&product0);

                    *(Vector128<ulong>*)&ghash = Vector128.Create(
                        (high + high) ^ low >> 63 ^ data.L[0],
                        (high1 + high1) ^ high >> 63 ^ data.L[1]);
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
                    ghash = Sse2.Xor(t, Sse2.Xor(zprec0[0xff & x0 >> 56], zprec1[0xff & x1 >> 56]));
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
