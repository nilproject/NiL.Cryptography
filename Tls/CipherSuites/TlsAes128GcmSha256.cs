using System;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Encryption.Modes.Gcm;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Tls.Tls13;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_AES_128_GCM_SHA256)]
public class TlsAes128GcmSha256 : Tls13CipherSuiteBase
{
    public TlsAes128GcmSha256(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) : base(keyDerivationAlgorithm, ecdsa)
    {
        var keySizes = KeysSizes;
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, keySizes.WriteKey, keySizes.WriteIV);
    }

    public override KeysSizes KeysSizes => new(0, 16, 12);

    public override IHashFunction HashFunction => Sha256.Instance;

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(TrafficKeyingMaterial ourKeyMaterial, TrafficKeyingMaterial theirKeyMaterial, TlsVersion tlsVersion)
    {
        if (tlsVersion is not TlsVersion.Tls13)
            throw new ArgumentException(nameof(tlsVersion));

        return new EncryptDecryptProcessor(
            tlsVersion,
            ourKeyMaterial,
            theirKeyMaterial,
            Hmac,
            new GcmMode(new Encryption.Aes(ourKeyMaterial.WriteKey)),
            new GcmMode(new Encryption.Aes(theirKeyMaterial.WriteKey)));
    }
}
