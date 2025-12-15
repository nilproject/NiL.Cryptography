using NiL.Cryptography.Asn1;
using NiL.Cryptography.Hashing;

namespace NiL.Cryptography.Pkcs.AlgorithmIdentifiers;

internal abstract class BaseCipherAlgorithm : BasePkcsAlgorithm
{
    protected byte[] Password { get; private set; }

    public abstract void Decode(byte[] data, byte[] salt, int rounds, out byte[] output);
    public abstract void Encode(byte[] data, byte[] salt, int rounds, out byte[] output);

    public override void Process(PkcsContaniner certificate, Asn1Element element, int startIndex)
    {
        Password = certificate._password;
    }

    protected enum KeyGenMode : byte
    {
        Key = 1,
        IV = 2,
        MacKey = 3
    }

    // https://tools.ietf.org/html/rfc7292#appendix-B
    protected byte[] Pkcs12KeyGen(byte[] salt, int rounds, int needBytes, KeyGenMode keyGenMode, IHashFunction hashFunction)
    {
        int u = hashFunction.DigestSize;
        int v = hashFunction.BlockSize;

        var slen = v * ((salt.Length + v - 1) / v);
        var plen = v * ((Password.Length + v - 1) / v);

        var dsp = new byte[v + slen + plen];

        for (var i = 0; i < v; i++)
            dsp[i] = (byte)keyGenMode;

        for (var i = 0; i < slen; i++)
            dsp[v + i] = salt[i % salt.Length];

        for (var i = 0; i < plen; i++)
            dsp[v + slen + i] = Password[i % Password.Length];

        var c = (needBytes + u - 1) / u;

        var res = new byte[needBytes];
        var ri = 0;

        for (var i = 0; i < c; i++)
        {
            var ai = hashFunction.Compute(dsp);
            for (var j = 1; j < rounds; j++)
                ai = hashFunction.Compute(ai);

            for (var j = 0; j < ai.Length && ri < res.Length; j++)
                res[ri++] = ai[j];

            for (var j = v << 1; j <= dsp.Length; j += v)
            {
                var o = 1;

                for (int k = j - 1, a = v - 1, n = 0; n < v; a--, k--, n++)
                {
                    o += dsp[k] + ai[a % u];
                    dsp[k] = (byte)o;
                    o >>= 8;
                }
            }
        }

        return res;
    }
}
