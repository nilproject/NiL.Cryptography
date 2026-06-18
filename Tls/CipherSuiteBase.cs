using System.Reflection;
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
        CipherSuiteId = this.GetType().GetCustomAttribute<CipherSuiteIdAttribute>().Id;
    }

    public abstract IHashFunction HashFunction { get; }
    public virtual Hmac Hmac { get; }
    public CipherSuiteId CipherSuiteId { get; private set; }
    public abstract IPreMasterKeyDerivationAlgorithm KeyExchangeAlgorithm { get; }
    public abstract ISignatureAlgorithm SignatureAlgorithm { get; }
    public virtual PseudoRandomFunction PseudoRandomFunction { get; protected set; }
    public virtual KeyScheduleDerivation KeyScheduleDerivation { get; protected set; }
    public abstract TlsVersion[] TlsVersions { get; }

    public virtual IEncryptDecryptProcessor CreateEncryptDecryptPair12(KeysSet12 keysSet, TlsVersion tlsVersion)
        => throw new System.NotSupportedException();

    public virtual IEncryptDecryptProcessor CreateEncryptDecryptPair(TrafficKeyingMaterial ourKeyMaterial, TrafficKeyingMaterial theirKeyMaterial, TlsVersion tlsVersion)
        => throw new System.NotSupportedException();
}
