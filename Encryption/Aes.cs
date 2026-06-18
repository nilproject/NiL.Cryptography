using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using AesNeon = System.Runtime.Intrinsics.Arm.Aes;
using AesNi = System.Runtime.Intrinsics.X86.Aes;

namespace NiL.Cryptography.Encryption;

// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
public sealed class Aes : IBlockCipher
{
    public enum AccelerationMode
    {
        Software,
        X86_AesNi,
        Arm_Neon
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1, Size = 1)]
    public struct FieldElement
    {
        private static readonly byte[] _PrecomputedMul = new byte[256 * 256];

        static FieldElement()
        {
            for (var i = 0; i < 256; i++)
            {
                for (var j = 0; j < 256; j++)
                {
                    _PrecomputedMul[(i << 8) | j] = mul((byte)i, (byte)j).Value;
                }
            }
        }

        public readonly byte Value;

        public FieldElement(byte value)
        {
            Value = value;
        }

        public static FieldElement operator +(FieldElement a, FieldElement b)
        {
            return new FieldElement((byte)(a.Value ^ b.Value));
        }

        public static FieldElement operator -(FieldElement a, FieldElement b)
        {
            return new FieldElement((byte)(a.Value ^ b.Value));
        }

        public static FieldElement operator *(FieldElement a, FieldElement b)
        {
            //return mul(a.Value, b.Value);
            return new FieldElement(_PrecomputedMul[(a.Value << 8) | b.Value]);
        }

        public static FieldElement operator *(byte a, FieldElement b)
        {
            //return mul(a, b.Value);
            return new FieldElement(_PrecomputedMul[(a << 8) | b.Value]);
        }

        public static FieldElement operator *(FieldElement a, byte b)
        {
            //return mul(a.Value, b);
            return new FieldElement(_PrecomputedMul[(a.Value << 8) | b]);
        }

        private static FieldElement mul(byte a, byte b)
        {
            var v = 0;
            for (var i = 0; i < 8; i++)
            {
                if ((a & (1 << i)) != 0)
                    v ^= b << i;
            }

            const int modulo = 0x11b;
            while ((v & 0xff00) != 0)
            {
                var ub = v >> 8;
                var d = 0;
                d += ((0 - (ub >> 4)) >> 8) & 4;
                d += ((0 - (ub >> (d + 2))) >> 8) & 2;
                d += ((0 - (ub >> (d + 1))) >> 8) & 1;
                v ^= modulo << d;
            }

            return new FieldElement((byte)v);
        }

        private static readonly string[] _degreesOfX = ["x7", "x6", "x5", "x4", "x3", "x2", "x", "1"];
        public override string ToString()
        {
            var v = Value;
            return string.Join(" + ", _degreesOfX.Where((x, i) => ((v >> (7 - i)) & 1) != 0)) + " = 0x" + Value.ToString("x2");
        }
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct Polonomial
    {
        public FieldElement _0, _1, _2, _3;

        public Polonomial(byte v3, byte v2, byte v1, byte v0) : this()
        {
            _0 = new FieldElement(v0);
            _1 = new FieldElement(v1);
            _2 = new FieldElement(v2);
            _3 = new FieldElement(v3);
        }

        public static Polonomial operator *(Polonomial a, Polonomial b)
        {
            var result = new Polonomial
            {
                _0 = a._0 * b._0 + a._3 * b._1 + a._2 * b._2 + a._1 * b._3,
                _1 = a._1 * b._0 + a._0 * b._1 + a._3 * b._2 + a._2 * b._3,
                _2 = a._2 * b._0 + a._1 * b._1 + a._0 * b._2 + a._3 * b._3,
                _3 = a._3 * b._0 + a._2 * b._1 + a._1 * b._2 + a._0 * b._3
            };
            return result;
        }

        public override string ToString()
        {
            return "0x" + _3.Value.ToString("x2") + " + 0x" + _2.Value.ToString("x2") + " + 0x" + _1.Value.ToString("x2") + " + 0x" + _0.Value.ToString("x2");
        }
    }

    private static readonly byte[] Sbox =
    [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
    ];

    private static readonly byte[] InvSbox = new byte[Sbox.Length];

    private static readonly byte[] Rcon =
    [
        0,
        0x01,
        0x02,
        0x04,
        0x08,
        0x10,
        0x20,
        0x40,
        0x80,
        0x1b,
        0x36,
    ];

    private const int _Nb = 4;

    private static readonly bool _Sse3Supported = Sse3.IsSupported;

    public int InputBlockSize => 16;

    public int OutBlockSize => 16;

    public readonly AccelerationMode Mode;

    public byte[] Key
    {
        get
        {
            var result = new byte[_nk << 2];
            unsafe
            {
                fixed (uint* ksp = _keySchedule)
                {
                    var kspb = (byte*)ksp;
                    for (var i = 0; i < result.Length; i++)
                    {
                        result[i] = kspb[i];
                    }
                }
            }

            return result;
        }

        private set
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            if (value.Length != 16 && value.Length != 24 && value.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(value));

            _nk = value.Length >> 2;
            _nr = _nk + 6;

            _keySchedule = new uint[_Nb * (_nr + 1)];
            unsafe
            {
                fixed (uint* w = _keySchedule)
                {
                    for (var i = 0; i < value.Length; i++)
                        ((byte*)w)[i] = value[i];

                    keyExpansion(value, w, _nk, _nr);
                }
            }
        }
    }

    internal uint[] _keySchedule;
    private int _nk;
    private int _nr;

    private static readonly bool _NiSupported = AesNi.IsSupported;
    private static readonly bool _NeonSupported = AesNeon.IsSupported;

    public Aes(byte[] key, bool allowAesNi = true)
    {
        Mode = allowAesNi switch
        {
            true when _NiSupported => AccelerationMode.X86_AesNi,
            true when _NeonSupported => AccelerationMode.Arm_Neon,
            _ => AccelerationMode.Software,
        };
        Key = key ?? throw new ArgumentNullException(nameof(key));
    }

    static Aes()
    {
        for (var i = 0; i < 256; i++)
            InvSbox[Sbox[i]] = (byte)i;
    }

    public unsafe void Decrypt(in Span<byte> input, in Span<byte> output)
    {
        if (input.Length != 16)
            throw new ArgumentOutOfRangeException(nameof(input));

        if (output.Length != 16)
            throw new ArgumentOutOfRangeException(nameof(output));

        fixed (uint* ksp = _keySchedule)
        fixed (byte* inputPtr = input)
        fixed (byte* outputPtr = output)
        {
            var w = ksp;
            w += _Nb * _nr;

            switch (Mode)
            {
                case AccelerationMode.X86_AesNi:
                {
                    Vector128<byte> vectorState;

                    vectorState = Sse2.Xor(*(Vector128<byte>*)inputPtr, *(Vector128<byte>*)w);

                    w -= _Nb;

                    for (var i = _nr; i-- > 1; w -= _Nb)
                    {
                        vectorState = AesNi.DecryptLast(vectorState, *(Vector128<byte>*)w);
                        vectorState = AesNi.InverseMixColumns(vectorState);
                    }

                    *(Vector128<byte>*)outputPtr = AesNi.DecryptLast(vectorState, *(Vector128<byte>*)w);
                    break;
                }

                //case AccelerationMode.Arm_Neon:
                //{
                //    Vector128<byte> vectorState;

                //    if (AdvSimd.IsSupported)
                //    {
                //        vectorState = AdvSimd.Xor(*(Vector128<byte>*)inputPtr, *(Vector128<byte>*)w);
                //    }
                //    else
                //    {
                //        Vector128<byte> t = default;
                //        ((ulong*)&t)[0] = ((ulong*)inputPtr)[0] ^ ((ulong*)ksp)[0];
                //        ((ulong*)&t)[1] = ((ulong*)inputPtr)[1] ^ ((ulong*)ksp)[1];
                //        vectorState = t;
                //    }

                //    w -= _Nb;

                //    for (var i = _nr; i-- > 1; w -= _Nb)
                //        vectorState = AesNeon.InverseMixColumns(AesNeon.Decrypt(vectorState, *(Vector128<byte>*)w));

                //    *(Vector128<byte>*)outputPtr = AesNeon.Decrypt(vectorState, *(Vector128<byte>*)w);

                //    break;
                //}

                default:
                    softwareDecrypt(inputPtr, outputPtr, w);
                    break;
            }
        }
    }

    private unsafe void softwareDecrypt(byte* input, byte* output, uint* w)
    {
        var state = stackalloc byte[_Nb * 4];
        var stateInt = (uint*)state;

        ((ulong*)state)[0] = ((ulong*)input)[0] ^ ((ulong*)w)[0];
        ((ulong*)state)[1] = ((ulong*)input)[1] ^ ((ulong*)w)[1];

        w -= _Nb;
        for (var i = 1; i < _nr; i++, w -= _Nb)
        {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(stateInt, w);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(stateInt, w);


        ((ulong*)output)[0] = ((ulong*)state)[0];
        ((ulong*)output)[1] = ((ulong*)state)[1];
    }

    public unsafe void Encrypt(in Span<byte> input, in Span<byte> output)
    {
        if (input.Length != 16)
            throw new ArgumentOutOfRangeException(nameof(input));

        if (output.Length != 16)
            throw new ArgumentOutOfRangeException(nameof(output));

        fixed (byte* inputPtr = input)
        fixed (byte* outputPtr = output)
        {
            switch (Mode)
            {
                case AccelerationMode.X86_AesNi:
                    EncryptX86(inputPtr, outputPtr);
                    break;

                case AccelerationMode.Arm_Neon:
                    EncryptArm(inputPtr, outputPtr);
                    break;

                default:
                {
                    softwareEncrypt(inputPtr, outputPtr);
                    break;
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
    internal unsafe void EncryptArm(byte* inputPtr, byte* outputPtr)
    {
        var keyLen = _keySchedule.Length;
        fixed (uint* ksp = _keySchedule)
        {
            var vectorW = (byte*)ksp;
            var vectorState = AesNeon.MixColumns(AesNeon.Encrypt(*(Vector128<byte>*)inputPtr, *(Vector128<byte>*)vectorW));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 1]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 2]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 3]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 4]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 5]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 6]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 7]));
            vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 8]));
            vectorState = AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 9]);

            switch (keyLen)
            {
                case (14 + 1) * _Nb:

                    vectorState = AesNeon.MixColumns(vectorState);
                    vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 10]));
                    vectorState = AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 11]);
                    vectorW += 32;
                    goto case (12 + 1) * _Nb;

                case (12 + 1) * _Nb:

                    vectorState = AesNeon.MixColumns(vectorState);
                    vectorState = AesNeon.MixColumns(AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 10]));
                    vectorState = AesNeon.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 11]);
                    vectorW += 32;
                    goto case (10 + 1) * _Nb;

                case (10 + 1) * _Nb:
                    vectorState = AdvSimd.Xor(vectorState, *(Vector128<byte>*)&vectorW[16 * 10]);
                    *(Vector128<byte>*)outputPtr = vectorState;
                    break;
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    internal unsafe void EncryptX86(byte* inputPtr, byte* outputPtr)
    {
        fixed (uint* ksp = _keySchedule)
        {
            switch (_keySchedule.Length)
            {
                case (10 + 1) * _Nb: X86Encrypt10(inputPtr, outputPtr, (byte*)ksp); return;
                case (12 + 1) * _Nb: X86Encrypt12(inputPtr, outputPtr, (byte*)ksp); return;
                case (14 + 1) * _Nb: X86Encrypt14(inputPtr, outputPtr, (byte*)ksp); return;
            }
        }
    }
#if false
    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    internal static unsafe void X86Encrypt10(byte* inputPtr, byte* outputPtr, byte* vectorW)
    {
        var key = *(Vector128<byte>*)vectorW;
        var vectorState = Sse2.Xor(((Vector128<byte>*)inputPtr)[0], key);

        var delta = AesNi.KeygenAssist(key, 1);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 2);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 4);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 8);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 16);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 0x20);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 0x40);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 0x80);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 0x1b);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        vectorState = AesNi.Encrypt(vectorState, key);

        delta = AesNi.KeygenAssist(key, 0x36);
        *(Vector128<uint>*)&delta = Sse2.Shuffle(*(Vector128<uint>*)&delta, 0xff);
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));
        key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
        key = Sse2.Xor(key, delta);

        var final = AesNi.EncryptLast(vectorState, key);
        *(Vector128<byte>*)outputPtr = final;
    }
#else
    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    internal static unsafe void X86Encrypt10(byte* inputPtr, byte* outputPtr, byte* vectorW)
    {
        var vectorState = AesNi.Encrypt(
            Sse2.Xor(((Vector128<byte>*)inputPtr)[0], *(Vector128<byte>*)vectorW),
            *(Vector128<byte>*)&vectorW[16 * 1]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 2]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 3]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 4]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 5]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 6]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 7]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 8]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&vectorW[16 * 9]);
        var final = AesNi.EncryptLast(vectorState, *(Vector128<byte>*)&vectorW[16 * 10]);
        *(Vector128<byte>*)outputPtr = final;
    }
#endif

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    internal static unsafe void X86Encrypt12(byte* inputPtr, byte* outputPtr, byte* vectorW)
    {
        var w = vectorW;
        var vectorState = ((Vector128<byte>*)inputPtr)[0];
        vectorState = Sse2.Xor(vectorState, *(Vector128<byte>*)&w[16 * 0]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 1]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 2]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 3]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 4]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 5]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 6]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 7]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 8]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 9]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 10]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 11]);
        var final = AesNi.EncryptLast(vectorState, *(Vector128<byte>*)&w[16 * 12]);
        *(Vector128<byte>*)outputPtr = final;
    }

    [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.NoInlining)]
    internal static unsafe void X86Encrypt14(byte* inputPtr, byte* outputPtr, byte* vectorW)
    {
        var w = vectorW;
        var vectorState = ((Vector128<byte>*)inputPtr)[0];
        vectorState = Sse2.Xor(vectorState, *(Vector128<byte>*)&w[16 * 0]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 1]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 2]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 3]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 4]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 5]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 6]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 7]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 8]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 9]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 10]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 11]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 12]);
        vectorState = AesNi.Encrypt(vectorState, *(Vector128<byte>*)&w[16 * 13]);
        var final = AesNi.EncryptLast(vectorState, *(Vector128<byte>*)&w[16 * 14]);
        *(Vector128<byte>*)outputPtr = final;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static unsafe Vector128<byte> xor(void* left, void* right)
    {
        Vector128<byte> t = default;
        ((ulong*)&t)[0] = ((ulong*)left)[0] ^ ((ulong*)right)[0];
        ((ulong*)&t)[1] = ((ulong*)left)[1] ^ ((ulong*)right)[1];
        return t;
    }

    private unsafe void softwareEncrypt(byte* input, byte* output)
    {
        fixed (uint* ksp = _keySchedule)
        {
            var w = ksp;
            var state = stackalloc byte[_Nb * 4];

            *(Vector128<byte>*)state = xor(input, w);

            w += _Nb;

            for (var i = 1; i < _nr; i++, w += 4)
            {
                subBytes(state);
                shiftRows(state);
                mixColumns(state);
                addRoundKey((uint*)state, w);
            }

            subBytes(state);
            shiftRows(state);
            addRoundKey((uint*)state, w);

            ((ulong*)output)[0] = ((ulong*)state)[0];
            ((ulong*)output)[1] = ((ulong*)state)[1];
        }
    }

    private unsafe void subBytes(byte* state)
    {
        for (var i = 0; i < _Nb * 4; i++)
            state[i] = Sbox[state[i]];
    }

    private unsafe void invSubBytes(byte* state)
    {
        for (var i = 0; i < _Nb * 4; i++)
            state[i] = InvSbox[state[i]];
    }

    private unsafe void addRoundKey(uint* state, uint* w)
    {
        ((ulong*)state)[0] ^= ((ulong*)w)[0];
        ((ulong*)state)[1] ^= ((ulong*)w)[1];
    }

    private unsafe void shiftRows(byte* state)
    {
        var t = state[0 * 4 + 1];
        state[0 * 4 + 1] = state[1 * 4 + 1];
        state[1 * 4 + 1] = state[2 * 4 + 1];
        state[2 * 4 + 1] = state[3 * 4 + 1];
        state[3 * 4 + 1] = t;

        t = state[0 * 4 + 2];
        state[0 * 4 + 2] = state[2 * 4 + 2];
        state[2 * 4 + 2] = t;
        t = state[1 * 4 + 2];
        state[1 * 4 + 2] = state[3 * 4 + 2];
        state[3 * 4 + 2] = t;

        t = state[3 * 4 + 3];
        state[3 * 4 + 3] = state[2 * 4 + 3];
        state[2 * 4 + 3] = state[1 * 4 + 3];
        state[1 * 4 + 3] = state[0 * 4 + 3];
        state[0 * 4 + 3] = t;
    }

    private unsafe void invShiftRows(byte* state)
    {
        var t = state[0 * 4 + 3];
        state[0 * 4 + 3] = state[1 * 4 + 3];
        state[1 * 4 + 3] = state[2 * 4 + 3];
        state[2 * 4 + 3] = state[3 * 4 + 3];
        state[3 * 4 + 3] = t;

        t = state[0 * 4 + 2];
        state[0 * 4 + 2] = state[2 * 4 + 2];
        state[2 * 4 + 2] = t;
        t = state[1 * 4 + 2];
        state[1 * 4 + 2] = state[3 * 4 + 2];
        state[3 * 4 + 2] = t;

        t = state[3 * 4 + 1];
        state[3 * 4 + 1] = state[2 * 4 + 1];
        state[2 * 4 + 1] = state[1 * 4 + 1];
        state[1 * 4 + 1] = state[0 * 4 + 1];
        state[0 * 4 + 1] = t;
    }

    public unsafe void keyExpansion(byte[] key, uint* w, int nk, int nr)
    {
        var len = _Nb * (nr + 1);
        var rconIndex = 1;
        var temp0 = stackalloc uint[4];
        if (Mode == AccelerationMode.X86_AesNi && nr == 10)
        {
            for (var i = nk; i < len; i++)
            {
                var temp = w[i - 1];

                if (i % nk == 0)
                {
                    temp0[1] = temp;
                    *(Vector128<byte>*)temp0 = AesNi.KeygenAssist(*(Vector128<byte>*)temp0, Rcon[rconIndex++]);
                    temp = temp0[1];
                }
                else if (nk > 6 && i % nk == 4)
                {
                    temp0[1] = temp;
                    *(Vector128<byte>*)temp0 = AesNi.KeygenAssist(*(Vector128<byte>*)temp0, 0);
                    temp = temp0[0];
                }

                w[i] = w[i - nk] ^ temp;
            }
        }
        else
        {
            if (nk == 4)
            {
                computeRoundKey4(w + 00, temp0, 0x01);
                computeRoundKey4(w + 04, temp0, 0x02);
                computeRoundKey4(w + 08, temp0, 0x04);
                computeRoundKey4(w + 12, temp0, 0x08);
                computeRoundKey4(w + 16, temp0, 0x10);
                computeRoundKey4(w + 20, temp0, 0x20);
                computeRoundKey4(w + 24, temp0, 0x40);
                computeRoundKey4(w + 28, temp0, 0x80);
                computeRoundKey4(w + 32, temp0, 0x1b);
                computeRoundKey4(w + 36, temp0, 0x36);
            }
            else
            {
                for (var i = nk; i < len; i++)
                {
                    var temp = w[i - 1];
                    if (i % nk == 0)
                        temp = subWord(rotWord(temp)) ^ Rcon[rconIndex++];
                    else if (nk > 6 && i % nk == 4)
                        temp = subWord(temp);
                    w[i] = w[i - nk] ^ temp;
                }
            }
        }
    }

    private static unsafe void computeRoundKey4(uint* w, uint* temp0, byte rcon)
    {
        //w[4] ^= temp1[1]; //                                    w[0] ^ f(w[3])
        //w[5] ^= temp1[1]; // w[4] ^ w[1] =               w[0] ^ w[1] ^ f(w[3])
        //w[6] ^= temp1[1]; // w[5] ^ w[2] =        w[0] ^ w[1] ^ w[2] ^ f(w[3])
        //w[7] ^= temp1[1]; // w[6] ^ w[3] = w[0] ^ w[1] ^ w[2] ^ w[3] ^ f(w[3])

        var t = w[3];

        var temp = 0u;
        var pt = (byte*)&t;
        var pt2 = (byte*)&temp;
        fixed (byte* sbox = Sbox)
        {
            pt2[3] = sbox[pt[0]];
            pt2[0] = (byte)(sbox[pt[1]] ^ rcon);
            pt2[1] = sbox[pt[2]];
            pt2[2] = sbox[pt[3]];
        }

        *(Vector128<int>*)&w[4] = *(Vector128<int>*)&w[0];
        w[4] ^= temp;
        w[5] ^= w[4];
        w[6] ^= w[5];
        w[7] ^= w[6];
    }

    public static uint rotWord(uint x)
    {
        return (x >> 8) | (x << 24);
    }

    public static uint subWord(uint x)
    {
        return (uint)((Sbox[(byte)(x >> 24)] << 24) | (Sbox[(byte)(x >> 16)] << 16) | (Sbox[(byte)(x >> 8)] << 8) | Sbox[(byte)x]);
    }

    private unsafe void mixColumns(byte* state)
    {
        var a = new Polonomial(0x03, 0x01, 0x01, 0x02);
        var s = (Polonomial*)state;
        *s = a * *s;
        s++;
        *s = a * *s;
        s++;
        *s = a * *s;
        s++;
        *s = a * *s;
    }

    private unsafe void invMixColumns(byte* state)
    {
        var a = new Polonomial(0x0b, 0x0d, 0x09, 0x0e);
        var s = (Polonomial*)state;
        *s = a * *s;
        s++;
        *s = a * *s;
        s++;
        *s = a * *s;
        s++;
        *s = a * *s;
    }
}
