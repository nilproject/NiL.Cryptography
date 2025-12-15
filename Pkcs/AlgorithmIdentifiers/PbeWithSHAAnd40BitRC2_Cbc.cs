using System;
using NiL.Cryptography.Encryption;
using NiL.Cryptography.Encryption.Modes;
using NiL.Cryptography.Hashing;

namespace NiL.Cryptography.Pkcs.AlgorithmIdentifiers;

[PkcsObjectIdentifier("1.2.840.113549.1.12.1.6")]
internal sealed class PbeWithSHAAnd40BitRC2_Cbc : BaseCipherAlgorithm
{
    // надо вынести весь код в отдельные методы, а тут оставить только параметры для них и описание схемы кодирования
    public override void Decode(byte[] data, byte[] salt, int rounds, out byte[] output)
    {
        // PBKDF1, PBES1
        /*var prekey = new byte[Password.Length + 8];
        Array.Copy(Password, prekey, Password.Length);
        Array.Copy(salt, 0, prekey, Password.Length, 8);

        for (var i = 0; i < rounds; i++)
        {
            var digest = NiL.Cryptography.Hashing.Sha1.Compute(prekey);

            if (prekey.Length != digest.AsBytes.Length)
                prekey = new byte[digest.AsBytes.Length];

            for (var j = 0; j < digest.AsBytes.Length; j++)
                prekey[j] = digest.AsBytes[j];
        }

        var iv = new byte[8];
        Array.Copy(prekey, 5, iv, 0, 8);

        Array.Resize(ref prekey, 5);
        var key = prekey;

        var rc2 = new CbcMode(new Ciphers.RC2(64), iv);

        var o0 = new byte[data.Length];
        rc2.Decrypt(data, o0, key);

        output = o0;*/

        /*var dkLen = 16;
        var hLen = 20;
        var l = 1;*/

        // PBKDF2, PBES2
        /*var prekey = f(Password, salt, rounds, 1);

        var iv = new byte[8];
        Array.Copy(prekey, 5, iv, 0, 8);

        Array.Resize(ref prekey, 5);
        var key = prekey;

        var rc2 = new CbcMode(new Ciphers.RC2(40), iv);
        var o0 = new byte[data.Length];
        rc2.Decrypt(data, o0, key);

        output = o0;*/

        var key = Pkcs12KeyGen(salt, rounds, 5, KeyGenMode.Key, Sha1.Instance);
        var iv = Pkcs12KeyGen(salt, rounds, 8, KeyGenMode.IV, Sha1.Instance);

        var rc2 = new CbcMode(new RC2(key), iv);
        output = new byte[data.Length];
        rc2.Decrypt(data, output);

        var paddingLen = output[output.Length - 1];
        Array.Resize(ref output, output.Length - paddingLen);
    }

    private static byte[] f(byte[] password, byte[] salt, int c, int i)
    {
        var hmacSha1 = new Hmac(Sha1.Instance);

        Array.Resize(ref salt, salt.Length + 4);
        salt[salt.Length - 4] = (byte)((i >> 24) & 0xff);
        salt[salt.Length - 3] = (byte)((i >> 16) & 0xff);
        salt[salt.Length - 2] = (byte)((i >> 8) & 0xff);
        salt[salt.Length - 1] = (byte)(i & 0xff);

        var result = new byte[hmacSha1.HashFunction.DigestSize];

        var h = hmacSha1.Compute(salt, password);
        for (var j = 0; j < h.Length; j++)
            result[j] = h[j];

        while (--c > 0)
        {
            h = hmacSha1.Compute(h, password);
            for (var j = 0; j < h.Length; j++)
                result[j] ^= h[j];
        }

        return result;
    }

    public override void Encode(byte[] data, byte[] salt, int rounds, out byte[] output)
    {
        throw new NotImplementedException();
    }
}
