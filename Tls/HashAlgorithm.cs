namespace NiL.Cryptography.Tls;

public enum HashAlgorithm : byte
{
    None = 0,
    Md5 = 1,
    Sha1 = 2,
    Sha224 = 3,
    Sha256 = 4,
    Sha384 = 5,
    Sha512 = 6,
    Ed25519 = 7,
    Ed448 = 8,
}
