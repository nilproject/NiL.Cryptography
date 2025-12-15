#nullable enable

using System;
using NiL.Cryptography.Hashing;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Tls13;

// https://datatracker.ietf.org/doc/html/rfc5869
public class HmacBasedKeyDerivationFunction
{
    private readonly Hmac _hmac;

    public Hmac Hmac => _hmac;

    public HmacBasedKeyDerivationFunction(Hmac hmac)
    {
        _hmac = hmac;
    }

    /// <summary>
    ///     HKDF-Extract(salt, IKM) -> PRK <br/>
    ///     <br/>
    ///     The output PRK is calculated as follows:<br/>
    ///     PRK = HMAC-Hash(salt, IKM)
    /// </summary>
    /// <param name="salt">optional salt value (a non-secret random value);
    /// if not provided, it is set to a string of HashLen zeros.</param>
    /// <param name="ikm">a pseudorandom key (of HashLen octets)</param>
    /// <returns>a pseudorandom key (of HashLen octets)</returns>
    public ReadOnlySpan<byte> HkdfExtract(byte[]? salt, byte[] ikm) => _hmac.Compute(ikm, salt ?? Array.Empty<byte>());

    /// <summary>
    ///     HKDF-Expand(PRK, info, L) -> OKM <br/>
    ///     <br/>
    ///     The output OKM is calculated as follows: <br/>
    ///     N = ceil(L/HashLen) <br/>
    ///     T = T(1) | T(2) | T(3) | ... | T(N) <br/>
    ///     OKM = first L octets of T
    /// </summary>
    /// <param name="prk">a pseudorandom key of at least HashLen octets<br/>(usually, the output from the extract step)</param>
    /// <param name="info">optional context and application specific information<br/>(can be a zero-length string)</param>
    /// <param name="length">length of output keying material in octets<br/>(&lt;= 255*HashLen)</param>
    /// <returns></returns>
    public ReadOnlySpan<byte> HkdfExpand(scoped in ReadOnlySpan<byte> prk, scoped in ReadOnlySpan<byte> info, int length)
    {
        if (length > 255 * _hmac.HashFunction.DigestSize) 
            throw new ArgumentOutOfRangeException(nameof(length));

        var output = new BigEndianWriteBuffer(length, true);
        var tBuffer = new BigEndianWriteBuffer();
        for (var i = 1; output.Length < length; i++)
        {
            tBuffer.Bytes(info);
            tBuffer.Uint8((byte)i);
            
            var mac = _hmac.Compute(tBuffer, prk);
            output.Bytes(mac, Math.Min(mac.Length, length - output.Length));

            tBuffer.ResetSize();
            tBuffer.Bytes(mac);
        }

        return output;
    }
}
