using System.Security.Cryptography;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Numerics;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Extensions.SignatureScheme;
using NiL.Tools;

namespace NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;

// https://tools.ietf.org/html/rfc6979
// https://www.cs.miami.edu/home/burt/learning/Csc609.142/ecdsa-cert.pdf
// https://tools.ietf.org/html/rfc4492#section-5.8
public sealed class WeierstrassEcdsa : ISignatureAlgorithm
{
    private readonly IBigUInt _key;
    private readonly CurveDefinition _curve;
    private readonly IHashFunction _hashFunction;
    private readonly RandomNumberGenerator _randomNumberGenerator;
    private readonly SignatureScheme _signatureSchemeId;

    public WeierstrassEcdsa(
        IBigUInt privateKey,
        CurveDefinition curve,
        IHashFunction hashFunction,
        RandomNumberGenerator randomNumberGenerator,
        SignatureScheme signatureSchemeId)
    {
        _key = privateKey;
        _curve = curve;
        _hashFunction = hashFunction;
        _randomNumberGenerator = randomNumberGenerator;
        _signatureSchemeId = signatureSchemeId;
    }

    public SignatureScheme Id => _signatureSchemeId;

    // https://tools.ietf.org/html/rfc6979#section-2.4
    public byte[] Sign(byte[] buffer)
    {
        var hash = _hashFunction.Compute(buffer);

        IBigUInt order = _curve.Order;
        IBigUInt h = IBigUInt.FromBytes(order.Size, hash, true);
        IBigUInt r = default;
        IBigUInt s;
        IBigUInt k;

        // https://tools.ietf.org/html/rfc6979#section-2.3.2
        var qlen = order.MostSignificantBitIndex();
        var blen = h.MostSignificantBitIndex();

        var shift = 0;
        if (qlen < blen)
            shift = blen - qlen;

        h >>= shift;
        h %= order;

        var buf = hash.Length == 32 ? hash : new byte[32];
        do
        {
            do
            {
                _randomNumberGenerator.GetBytes(buf);
                k = IBigUInt.FromBytes(order.Size, buf, true) % order;
                if (k.Equals(0))
                    continue;

                r = _curve.BasePointMultiplier.Multiply(k).Normalize().X;
            }
            while (r.Equals(0));

            var invK = k.ModInverse(order);

            s = (h + r * _key) % order * invK % order;
        }
        while (s.Equals(0));

        var rLen = r.MostSignificantBitIndex() + 1;
        if ((rLen & 7) == 0) // most signed bit, need one zero byte padding
            rLen++;
        rLen = (rLen + 7) / 8;

        var sLen = s.MostSignificantBitIndex() + 1;
        if ((sLen & 7) == 0)
            sLen++;
        sLen = (sLen + 7) / 8;

        var contentLen = 2 + rLen + 2 + sLen;
        var result = new BigEndianWriteBuffer(2 + contentLen, true);
        result.Uint8(16 | 32); // asn.1 sequence contructed
        result.Uint8((byte)contentLen); // length of content

        result.Uint8(2); // asn.1 int primitive
        result.Uint8((byte)rLen); // length of content
        r.ToBytes(result.Buffer, result.Position, rLen, true);
        result.Length += rLen;
        result.Position += rLen;

        result.Uint8(2); // asn.1 int primitive
        result.Uint8((byte)sLen); // length of content
        s.ToBytes(result.Buffer, result.Position, sLen, true);

        return result.Buffer;
    }
}
