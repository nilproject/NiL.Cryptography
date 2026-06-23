using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Tls.Tls13;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_AES_256_GCM_SHA384)]
public class TlsAes256GcmSha384 : TlsAes128GcmSha256
{
    public TlsAes256GcmSha384(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) : base(keyDerivationAlgorithm, ecdsa)
    {
        var keySizes = KeysSizes;
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, keySizes.WriteKey, keySizes.WriteIV);
    }

    public override IHashFunction HashFunction => Sha384.Instance;

    public override KeysSizes KeysSizes => new(0, 32, 12);
}
