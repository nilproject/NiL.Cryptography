using System;
using NiL.Cryptography.Hashing;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Tls12;

public sealed class PseudoRandomFunction
{
    public IHashFunction HashFunction => _hmac.HashFunction;
    public KeysSizes KeysSizes { get; }

    private readonly Hmac _hmac;

    public PseudoRandomFunction(Hmac hmac, KeysSizes keysSizes)
    {
        KeysSizes = keysSizes;
        _hmac = hmac;
    }

    // https://tools.ietf.org/html/rfc5246#section-6.3
    public byte[] DeriveKey(byte[] secret, string label, Span<byte> seed, int count)
    {
        var resultBuffer = new BigEndianWriteBuffer(count, true);
        var seedBuffer = new BigEndianWriteBuffer(label.Length + seed.Length, true);
        var tempBuffer = new BigEndianWriteBuffer(_hmac.HashFunction.DigestSize + seedBuffer.Buffer.Length, true);

        for (var i = 0; i < label.Length; i++)
        {
            if (label[i] > 127)
                throw new ArgumentException(nameof(label));

            seedBuffer.Uint8((byte)label[i]);
        }

        seedBuffer.Bytes(seed);

        var a = seedBuffer.Buffer;
        while (resultBuffer.Position < count)
        {
            a = _hmac.Compute(a, secret);

            tempBuffer.ResetSize();
            tempBuffer.Bytes(a);
            tempBuffer.Bytes(seedBuffer.Buffer);
            resultBuffer.Bytes(_hmac.Compute(tempBuffer.Buffer, secret));
        }

        return resultBuffer.Buffer;
    }

    public KeysSet12 DeriveKeySet(byte[] preMasterSecret, byte[] serverRandom, byte[] clientRandom, bool isServerSide)
    {
        // https://tools.ietf.org/html/rfc5246#section-8.1
        var seedBuffer = new BigEndianWriteBuffer(serverRandom.Length + clientRandom.Length, true);
        seedBuffer.Bytes(clientRandom);
        seedBuffer.Bytes(serverRandom);
        var masterSecret = DeriveKey(preMasterSecret, "master secret", seedBuffer.Buffer, 48);

        //Console.WriteLine("Pre master: " + string.Concat(preMasterSecret.Select(x => x.ToString("X2"))));
        //Console.WriteLine("Master: " + string.Concat(masterSecret.Select(x => x.ToString("X2"))));

        // https://tools.ietf.org/html/rfc5246#section-6.3
        var keyMaterialSize = KeysSizes.WriteIV + KeysSizes.WriteKey + KeysSizes.WriteMacKey;
        keyMaterialSize += keyMaterialSize;

        seedBuffer.ResetSize();
        seedBuffer.Bytes(serverRandom);
        seedBuffer.Bytes(clientRandom);
        var keyBlock = DeriveKey(masterSecret, "key expansion", seedBuffer.Buffer, keyMaterialSize);

        var result = new KeysSet12(masterSecret, KeysSizes);
        var offset = 0;

        if (isServerSide)
        {
            extractKey(keyBlock, result.TheirWriteMacKey, ref offset);
            extractKey(keyBlock, result.OurWriteMacKey, ref offset);
            
            extractKey(keyBlock, result.TheirWriteKey, ref offset);
            extractKey(keyBlock, result.OurWriteKey, ref offset);

            extractKey(keyBlock, result.TheirWriteIV, ref offset);
            extractKey(keyBlock, result.OurWriteIV, ref offset);
        }
        else
        {
            extractKey(keyBlock, result.OurWriteMacKey, ref offset);
            extractKey(keyBlock, result.TheirWriteMacKey, ref offset);

            extractKey(keyBlock, result.OurWriteKey, ref offset);
            extractKey(keyBlock, result.TheirWriteKey, ref offset);

            extractKey(keyBlock, result.OurWriteIV, ref offset);
            extractKey(keyBlock, result.TheirWriteIV, ref offset);
        }
        return result;
    }

    private static void extractKey(byte[] keyBlock, byte[] target, ref int offset)
    {
        Array.Copy(keyBlock, offset, target, 0, target.Length);
        offset += target.Length;
    }
}
