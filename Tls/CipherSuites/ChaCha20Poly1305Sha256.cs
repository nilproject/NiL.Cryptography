using System;
using NiL.Cryptography.Encryption;
using NiL.Cryptography.Encryption.Modes;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Tls13;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_CHACHA20_POLY1305_SHA256)]
public class ChaCha20Poly1305Sha256 : Tls13CipherSuiteBase
{
    public ChaCha20Poly1305Sha256(IPreMasterKeyDerivationAlgorithm derivationAlgorithm, ISignatureAlgorithm signatureAlgorithm)
        : base(derivationAlgorithm, signatureAlgorithm)
    {
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, 32, 12);
    }

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
            new Poly1305(new ChaCha20() { Key = ourKeyMaterial.WriteKey, Nonce = new byte[12] }),
            new Poly1305(new ChaCha20() { Key = theirKeyMaterial.WriteKey, Nonce = new byte[12] }));
    }
}
