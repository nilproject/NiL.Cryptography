namespace NiL.Cryptography.Pkcs.Attributes;

[PkcsObjectIdentifier("1.2.840.113549.1.9.21")]
public sealed class LocalKeyIdPkcsAttribute : BasePkcsAttribute
{
    public byte[] KeyId => ((Values[0] as PkcsList).Items[0] as PkcsOctetString).Data;
}
