namespace NiL.Cryptography.Signature;

public enum SignatureAlgorithmId : byte
{
    Anonymous = 0,
    Rsa = 1,
    Dsa = 2,
    Ecdsa = 3,
    Ed25519 = 7,
    Ed448 = 8,
}
