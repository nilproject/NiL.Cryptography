using NiL.Cryptography.Hashing;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Tls12;
using NiL.Cryptography.Tls.Tls13;

namespace NiL.Cryptography.Tls;

public abstract class CipherSuiteBase
{
    protected CipherSuiteBase()
    {
        Hmac = new Hmac(HashFunction);
    }

    public abstract IHashFunction HashFunction { get; }
    public virtual Hmac Hmac { get; }
    public abstract CipherSuiteId CipherSuiteId { get; }
    public abstract IPreMasterKeyDerivationAlgorithm KeyExchangeAlgorithm { get; }
    public abstract ISignatureAlgorithm SignatureAlgorithm { get; }
    public virtual PseudoRandomFunction PseudoRandomFunction { get; protected set; }
    public virtual KeyScheduleDerivation KeyScheduleDerivation { get; protected set; }
    public abstract TlsVersion[] TlsVersions { get; }

    public abstract IEncryptDecryptProcessor CreateEncryptDecryptPair(KeysSet12 keysSet, TlsVersion tlsVersion);
}
