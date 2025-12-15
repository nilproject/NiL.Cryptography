using System;
using NiL.Cryptography.EllipticCryptography.MontgomeryForm;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography;

// http://www.secg.org/sec2-v2.pdf
// https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/ieee/00891000.pdf
public static unsafe class NamedCurveRegistry
{
    public static readonly CurveDefinition Secp256r1;
    public static readonly CurveDefinition X25519;

    public static CurveDefinition Get(NamedCurve curve)
    {
        switch (curve)
        {
            case NamedCurve.Secp256r1: return Secp256r1;
            case NamedCurve.X25519: return X25519;
            default: throw new NotImplementedException();
        }
    }

    static NamedCurveRegistry()
    {
        Secp256r1 = secp256r1();
        X25519 = x25519();
    }

    private static CurveDefinition secp256r1()
    {
        WeierstrassCurve<B512> curve = new WeierstrassCurve<B512>(
                p: BigUInt<B512>.ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"),
                a: BigUInt<B512>.ParseHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC"),
                b: BigUInt<B512>.ParseHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B"))
        {
            //ReduceFunc = secp256r1Reduce,
        };

        return CurveDefinition.Create(
            NamedCurve.Secp256r1,
            curve,
            basePoint: curve.CreatePoint(
                BigUInt<B512>.ParseHex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
                BigUInt<B512>.ParseHex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5")
            ),
            order: BigUInt<B512>.ParseHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"),
            2,
            true);
    }

    private static CurveDefinition x25519()
    {
        var p = BigUInt<B512>.ParseHex("07fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");
        var curve = new X25519Curve(p, 0x76d06, 1);

        var basePoint = new X25519CurvePoint(9, curve);
        var curveDef = CurveDefinition.Create(
            NamedCurve.X25519,
            curve,
            basePoint,
            BigUInt<B512>.ParseHex("01000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
            1,
            false);

        return curveDef;
    }

    private static void secp256r1Reduce(uint* x)
    {
        var i = 0;

        var needReduce = false;
        for (i = 8; !needReduce && i < 16; i++)
            needReduce |= x[i] != 0;

        if (!needReduce)
            return;

        var temp = stackalloc ulong[16];

        var x8f = x[8] * (ulong)uint.MaxValue;
        var x9f = x[9] * (ulong)uint.MaxValue;
        var x10f = x[10] * (ulong)uint.MaxValue;
        var x11f = x[11] * (ulong)uint.MaxValue;
        var x12f = x[12] * (ulong)uint.MaxValue;
        var x13f = x[13] * (ulong)uint.MaxValue;
        var x14f = x[14] * (ulong)uint.MaxValue;
        var x15f = x[15] * (ulong)uint.MaxValue;

        var x8e = x8f - x[8];
        var x9e = x9f - x[9];
        var x10e = x10f - x[10];
        var x11e = x11f - x[11];
        var x12e = x12f - x[12];
        var x13e = x13f - x[13];
        var x14e = x14f - x[14];
        var x15e = x15f - x[15];
    }
}
