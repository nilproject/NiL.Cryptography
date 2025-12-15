namespace NiL.Cryptography.Tls;

public sealed class EphemeralKeysSet
{
    public byte[] PrivateKey { get; set; }
    public byte[] PublicKey { get; set; }
    public byte[] PreMasterKey { get; internal set; }
}
