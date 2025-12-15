using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Encryption.Modes;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Tls.Tls12;

namespace NiL.Cryptography.Tls.CipherSuites;

// https://tools.ietf.org/html/rfc5289#section-3.1
[CipherSuiteId(CipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)]
public sealed class EcdheEcdsaAes128CbcSha : CbcCipherSuite
{
    public EcdheEcdsaAes128CbcSha(EcdhKeyDerivation masterKeyDerivationAlgorithm, WeierstrassEcdsa ecdsa)
        : base(ecdsa, masterKeyDerivationAlgorithm)
    {
    }

    public override CipherSuiteId CipherSuiteId => CipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA;
    public override IHashFunction HashFunction => Sha1.Instance;

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(KeysSet12 keysSet, TlsVersion tlsVersion)
    {
        var outputCiph = new Encryption.Aes(keysSet.OurWriteKey);
        var inputCiph = new Encryption.Aes(keysSet.TheirWriteKey);
        return new EncryptDecryptProcessor(
            tlsVersion,
            keysSet,
            new CbcMode(outputCiph, new byte[outputCiph.InputBlockSize]),
            new CbcMode(inputCiph, new byte[outputCiph.InputBlockSize]),
            Hmac);
    }
}
