using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace NiL.Cryptography.Encryption.Modes.Gcm;

internal unsafe class GHash
{
    internal readonly GcmFieldElement[] ZPreComputed = new GcmFieldElement[16 * 16 + 16 * 16];
    //internal readonly GcmFieldElement[] ZPreComputed0 = new GcmFieldElement[16 * 16];
    //internal readonly GcmFieldElement[] ZPreComputed1 = new GcmFieldElement[16 * 16];
    internal readonly IBlockCipher BlockCipher;
    private GcmFieldElement _h;

    public GcmFieldElement H => _h;

    public GHash(IBlockCipher blockCipher)
    {
        BlockCipher = blockCipher;
        recalcH();
    }

    private static readonly bool isSse2Supported = Sse2.IsSupported;
    private static readonly bool isArmAesSupported = System.Runtime.Intrinsics.Arm.Aes.IsSupported;

    public GcmFieldElement Invoke(in ReadOnlySpan<byte> data, in GcmFieldElement y)
    {
        if (isSse2Supported)
            return ghashSse2(data, y);
        else if (isArmAesSupported)
            return ghashArm(data, y);
        else
            return ghash(data, y);
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private GcmFieldElement ghash(in ReadOnlySpan<byte> data, GcmFieldElement y)
    {
        var segmentIndex = 0;
        var len = data.Length & ~15;
        var xpos = 0u;
        ulong bbyte = 0;
        var tz = 0ul;
        var z0 = y.L[0];
        var z1 = y.L[1];

        if (len is 0 or 5)
        {
            _ = 1;
        }

        fixed (GcmFieldElement* zPreComputed0 = ZPreComputed)
        fixed (byte* pdata = data)
        {
            var zPreComputed1 = zPreComputed0 + 256;

            for (; ; )
            {
                if (segmentIndex / 16 == 655360)
                {
                    _ = 1;
                }

                if (segmentIndex < len)
                {
                    z0 ^= *(ulong*)&pdata[segmentIndex];
                    z1 ^= *(ulong*)&pdata[segmentIndex + 8];
                    segmentIndex += 16;
                }
                else
                {
                    y.L[0] = 0;
                    y.L[1] = 0;

                    if (segmentIndex == data.Length)
                        break;

                    xpos = 0;
                    while (segmentIndex < data.Length)
                        y.B[xpos++] = pdata[segmentIndex++];

                    z0 ^= y.L[0];
                    z1 ^= y.L[1];
                }

                tz = z1;
                bbyte = z0 >> 8;
                xpos = 1 << 4;

                {
                    var x = (uint)z0 & 0x0fu;
                    ref var zPreComp0 = ref zPreComputed0[((uint)z0 & 0xf0u) >> 4];
                    ref var zPreComp1 = ref zPreComputed1[x];
                    z0 = zPreComp0.L[0] ^ zPreComp1.L[0];
                    z1 = zPreComp0.L[1] ^ zPreComp1.L[1];
                }

                for (; ; )
                {
                    do
                    {
                        var x = (uint)bbyte & 0x0fu | xpos;
                        ref var zPreComp0 = ref zPreComputed0[((uint)bbyte & 0xf0u) >> 4 | xpos];
                        ref var zPreComp1 = ref zPreComputed1[x];
                        z0 ^= zPreComp0.L[0] ^ zPreComp1.L[0];
                        z1 ^= zPreComp0.L[1] ^ zPreComp1.L[1];

                        xpos += 1 << 4;
                        bbyte >>= 8;
                    }
                    while ((xpos & (8 << 4) - 1) != 0);

                    if (xpos == 16 << 4)
                        break;

                    bbyte = tz;
                }
            }
        }

        y.L[0] = z0;
        y.L[1] = z1;

        return y;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    private GcmFieldElement ghashSse2(in ReadOnlySpan<byte> data, GcmFieldElement y)
    {
        var xpos = 0u;
        var segmentIndex = 0;
        var zLow = 0ul;
        var zHigh = 0ul;
        var len = data.Length & ~15;
        var vy = (Vector128<byte>*)&y;
        var z = *vy;

        fixed (GcmFieldElement* zPreComputed0 = ZPreComputed)
        //fixed (GcmFieldElement* zPreComputed1 = ZPreComputed1)
        fixed (byte* pdata = data)
        {
            var zprec0 = (byte*)zPreComputed0;
            var zprec1 = (byte*)(zPreComputed0 + 256);

            while (segmentIndex != data.Length)
            {
                if (segmentIndex < len)
                {
                    *vy = *(Vector128<byte>*)&pdata[segmentIndex];
                    segmentIndex += 16;
                }
                else
                {
                    y.L[0] = 0;
                    y.L[1] = 0;

                    xpos = 0;
                    while (segmentIndex < data.Length)
                        y.B[xpos++] = pdata[segmentIndex++];
                }

                var temp = Sse2.Xor(z, *vy);
                zLow = (*(GcmFieldElement*)&temp).L[0];
                zHigh = (*(GcmFieldElement*)&temp).L[1];

                xpos = 1 << 4 + 4;

                var x0 = (uint)zLow & 0xf0u;
                var x1 = ((uint)zLow & 0x0fu) << 4;
                z = *(Vector128<byte>*)&zprec0[x0];
                z = Sse2.Xor(*(Vector128<byte>*)&zprec1[x1], z);
                zLow >>= 8;

                for (; ; )
                {
                    do
                    {
                        x0 = (byte)zLow & 0xf0u | xpos;
                        x1 = ((byte)zLow & 0x0fu) << 4 | xpos;
                        z = Sse2.Xor(*(Vector128<byte>*)&zprec0[x0], z);
                        z = Sse2.Xor(*(Vector128<byte>*)&zprec1[x1], z);
                        zLow >>= 8;
                        xpos += 1 << 4 + 4;
                    }
                    while ((xpos & (8 << 4 + 4) - 1) != 0);

                    if (xpos == 16 << 4 + 4)
                        break;

                    zLow = zHigh;
                }
            }
        }

        *vy = z;
        return y;
    }

    private GcmFieldElement ghashArm(ReadOnlySpan<byte> data, GcmFieldElement y)
    {
        var xpos = 0u;
        var segmentIndex = 0;
        var zLow = 0ul;
        var zHigh = 0ul;
        var len = data.Length & ~15;
        var vy = (Vector128<byte>*)&y;
        var z = *vy;

        fixed (GcmFieldElement* zPreComputed0 = ZPreComputed)
        //fixed (GcmFieldElement* zPreComputed1 = ZPreComputed1)
        fixed (byte* pdata = data)
        {
            var zprec0 = (byte*)zPreComputed0;
            var zprec1 = (byte*)(zPreComputed0 + 256);

            while (segmentIndex != data.Length)
            {
                if (segmentIndex < len)
                {
                    *vy = *(Vector128<byte>*)&pdata[segmentIndex];
                    segmentIndex += 16;
                }
                else
                {
                    y.L[0] = 0;
                    y.L[1] = 0;

                    xpos = 0;
                    while (segmentIndex < data.Length)
                        y.B[xpos++] = pdata[segmentIndex++];
                }

                var temp = AdvSimd.Xor(z, *vy);
                zLow = (*(GcmFieldElement*)&temp).L[0];
                zHigh = (*(GcmFieldElement*)&temp).L[1];

                xpos = 1 << 4 + 4;

                var x0 = (uint)zLow & 0xf0u;
                var x1 = ((uint)zLow & 0x0fu) << 4;
                z = *(Vector128<byte>*)&zprec0[x0];
                z = AdvSimd.Xor(*(Vector128<byte>*)&zprec1[x1], z);
                zLow >>= 8;

                for (; ; )
                {
                    do
                    {
                        x0 = (byte)zLow & 0xf0u | xpos;
                        x1 = ((byte)zLow & 0x0fu) << 4 | xpos;
                        z = AdvSimd.Xor(*(Vector128<byte>*)&zprec0[x0], z);
                        z = AdvSimd.Xor(*(Vector128<byte>*)&zprec1[x1], z);
                        zLow >>= 8;
                        xpos += 1 << 4 + 4;
                    }
                    while ((xpos & (8 << 4 + 4) - 1) != 0);

                    if (xpos == 16 << 4 + 4)
                        break;

                    zLow = zHigh;
                }
            }
        }

        *vy = z;
        return y;
    }

    private void recalcH()
    {
        fixed (GcmFieldElement* h = &_h)
        {
            var hspan = new Span<byte>((byte*)h, 16);
            BlockCipher.Encrypt(hspan, hspan);

            for (var i = 0; i < 8; i++)
            {
                var t = hspan[i];
                hspan[i] = hspan[15 - i];
                hspan[15 - i] = t;
            }
        }

        //{
        //    var localShifted = _h;
        //    var size = 32;
        //    var test0 = computeTz(
        //        size == 64 ? ulong.MaxValue : (1ul << size) - 1,
        //        ref localShifted,
        //        size);
        //}

        fixed (GcmFieldElement* zPreComputed0 = ZPreComputed)
        //fixed (GcmFieldElement* zPreComputed1 = ZPreComputed1)
        {
            var zPreComputed1 = zPreComputed0 + 256;

            var yShifted = _h;
            for (var i = 0; i < 32; i++)
            {
                var localShifted = yShifted;
                var t0 = yShifted;
                var y0 = t0.L[0];
                var y1 = t0.L[1];

                for (var b = 0ul; b < 16; b++)
                {
                    localShifted = yShifted;
                    var tz = computeTz(b, ref localShifted);
                    ((i & 1) == 0 ? zPreComputed0 : zPreComputed1)[(int)b | (i & ~1) << 3] = tz;
                }

                yShifted = localShifted;
            }
        }
    }
    private GcmFieldElement computeTz(ulong bbyte, ref GcmFieldElement v, int size = 4)
    {
#if false
        var originalBbyte = bbyte;
        var b = default(GcmFieldElement);
        b.L[0] = bbyte;
        var vv = v;
        var product0 = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&vv, *(Vector128<ulong>*)&b, 0);
        var gcmProduct = *(GcmFieldElement*)&product0;
        var product1 = Pclmulqdq.CarrylessMultiply(*(Vector128<ulong>*)&vv, *(Vector128<ulong>*)&b, 1);
        gcmProduct.L[1] ^= ((ulong*)&product1)[0];// >> (size - 1);
        gcmProduct.L[0] = (gcmProduct.L[0] >> (size - 1)) | (gcmProduct.L[1] << (64 - size + 1));
        gcmProduct.L[1] >>= size - 1;
        gcmProduct.L[1] ^= (((ulong*)&product1)[1] << (64 - size + 1));
#endif
        var tz = new GcmFieldElement();

        //var rxors = new List<int>();
        //var rapplies = new List<int[]>();

        for (var j = 0; j < size; j++)
        {
            if ((bbyte & 1ul << size - 1) != 0)
            {
                tz.L[0] ^= v.L[0];
                tz.L[1] ^= v.L[1];
                //rapplies.Add(rxors.ToArray());
            }
            //else
            //{
            //    rapplies.Add(Array.Empty<int>());
            //}

            bbyte <<= 1;

            var bit = v.L[0] & 1;

            v.L[0] = v.L[0] >> 1 | v.L[1] << 63;
            v.L[1] >>= 1;

            //for (var i = 0; i < rxors.Count; i++)
            //    rxors[i]--;

            if (bit != 0)
            {
                v.L[1] ^= 0xe1ul << 56;
                //rxors.Add(0);
            }
        }

        // reference
#if false
        var xor = Sse2.Xor(*(Vector128<ulong>*)&gcmProduct, *(Vector128<ulong>*)&tz);
#if false
        for (var i = 0; i < size; i++)
        {
            if ((originalBbyte & (1ul << i)) != 0)
            {
                for (var j = 0; j < (size - i - 1); j++)
                {
                    if ((vv.L[0] & (1ul << j)) != 0)
                    {
                        var s = 56 - size + i + j + 2;
                        if (s < 0)
                            Debugger.Break();
                        gcmProduct.L[1] ^= 0xe1ul << s;
                    }
                }
            }
        }
#else
        ((ulong*)&product0)[0] &= (1ul << (size - 1)) - 1;
        b.L[0] = 0xe1ul;
        b.L[1] = 0;
        product0 = Pclmulqdq.CarrylessMultiply(product0, *(Vector128<ulong>*)&b, 0);
        if (size >= 58)
        {
            ((ulong*)&product0)[1] = (((ulong*)&product0)[1] << (58 + 64 - size)) | (((ulong*)&product0)[0] >> (size - 58));
            ((ulong*)&product0)[0] <<= (58 + 64 - size);
        }
        else
        {
            ((ulong*)&product0)[1] = ((ulong*)&product0)[0] << (58 - size);
            ((ulong*)&product0)[0] = 0;
        }
        product1 = Sse2.Xor(product0, *(Vector128<ulong>*)&gcmProduct);
        gcmProduct = *(GcmFieldElement*)&product1;
#endif

        xor = Sse2.Xor(*(Vector128<ulong>*)&gcmProduct, *(Vector128<ulong>*)&tz);

        if (xor[0] != 0 || xor[1] != 0) 
            Debugger.Break();
#endif

        for (var k = 0; k < 8; k++)
        {
            var t = tz.B[k];
            tz.B[k] = tz.B[15 - k];
            tz.B[15 - k] = t;
        }

        return tz;
    }
}
