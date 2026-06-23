using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.Encryption;
using NiL.Cryptography.Encryption.Modes;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Tls12;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)]
public class EcdheEcdsaChaCha20Poly1305Sha256 : Tls12CipherSuiteBase
{
    private readonly EcdhKeyDerivation _derivationAlgorithm;
    private readonly ISignatureAlgorithm _signatureAlgorithm;

    public EcdheEcdsaChaCha20Poly1305Sha256(EcdhKeyDerivation keyDerivationAlgorithm, ISignatureAlgorithm signatureAlgorithm)
    {
        _derivationAlgorithm = keyDerivationAlgorithm;
        _signatureAlgorithm = signatureAlgorithm;

        PseudoRandomFunction = new PseudoRandomFunction(Hmac, KeysSizes);
    }
    public override KeysSizes KeysSizes => new(0, 32, 12);
    public override IHashFunction HashFunction => Sha256.Instance;
    public override IPreMasterKeyDerivationAlgorithm KeyExchangeAlgorithm => _derivationAlgorithm;
    public override ISignatureAlgorithm SignatureAlgorithm => _signatureAlgorithm;
    public override PseudoRandomFunction PseudoRandomFunction { get; protected set; }

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls12];

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(KeysSet12 keysSet, TlsVersion tlsVersion)
    {
        return new EncryptDecryptProcessor(
            tlsVersion,
            keysSet,
            Hmac,
            new Poly1305(new ChaCha20 { Key = keysSet.OurWriteKey, Nonce = new byte[12] }),
            new Poly1305(new ChaCha20 { Key = keysSet.TheirWriteKey, Nonce = new byte[12] }),
            true);
    }
}
