using System;

namespace NiL.Cryptography.EllipticCryptography;

// https://tools.ietf.org/html/rfc4492#section-5.1.1
// https://tools.ietf.org/html/rfc8422#section-5.1.1
public enum NamedCurve : ushort
{
    Unnamed = 0,

    [Obsolete("rfc8422")]
    Sect163k1 = 1,
    [Obsolete("rfc8422")]
    Sect163r1 = 2,
    [Obsolete("rfc8422")]
    Sect163r2 = 3,
    [Obsolete("rfc8422")]
    Sect193r1 = 4,
    [Obsolete("rfc8422")]
    Sect193r2 = 5,
    [Obsolete("rfc8422")]
    Sect233k1 = 6,
    [Obsolete("rfc8422")]
    Sect233r1 = 7,
    [Obsolete("rfc8422")]
    Sect239k1 = 8,
    [Obsolete("rfc8422")]
    Sect283k1 = 9,
    [Obsolete("rfc8422")]
    Sect283r1 = 10,
    [Obsolete("rfc8422")]
    Sect409k1 = 11,
    [Obsolete("rfc8422")]
    Sect409r1 = 12,
    [Obsolete("rfc8422")]
    Sect571k1 = 13,
    [Obsolete("rfc8422")]
    Sect571r1 = 14,
    [Obsolete("rfc8422")]
    Secp160k1 = 15,
    [Obsolete("rfc8422")]
    Secp160r1 = 16,
    [Obsolete("rfc8422")]
    Secp160r2 = 17,
    [Obsolete("rfc8422")]
    Secp192k1 = 18,
    [Obsolete("rfc8422")]
    Secp192r1 = 19,
    [Obsolete("rfc8422")]
    Secp224k1 = 20,
    [Obsolete("rfc8422")]
    Secp224r1 = 21,
    [Obsolete("rfc8422")]
    Secp256k1 = 22,

    Secp256r1 = 23,
    Secp384r1 = 24,
    Secp521r1 = 25,
    X25519 = 29,
    X448 = 30,

    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,
}
