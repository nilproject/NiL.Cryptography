namespace NiL.Cryptography.Tls;

public enum CertificateType : byte
{
    X509 = 0,
    OpenPGP_RESERVED = 1,
    RawPublicKey = 2,
}
