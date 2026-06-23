using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Hashing;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)]
public class EcdheEcdsaAes256GcmSha384 : EcdheEcdsaAes128GcmSha256
{
    public EcdheEcdsaAes256GcmSha384(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) 
        : base(keyDerivationAlgorithm, ecdsa)
    {
    }

    public override IHashFunction HashFunction => Sha384.Instance;

    public override KeysSizes KeysSizes => new(0, 32, 4);
}
