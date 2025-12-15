namespace NiL.Cryptography.Tls;

public sealed class KeysSet12
{
    public readonly byte[] MasterSecret;
    public readonly byte[] TheirWriteMacKey;
    public readonly byte[] OurWriteMacKey;
    public readonly byte[] TheirWriteKey;
    public readonly byte[] OurWriteKey;
    public readonly byte[] TheirWriteIV;
    public readonly byte[] OurWriteIV;

    public KeysSet12(byte[] masterSecret, KeysSizes keysSizes)
    {
        MasterSecret = masterSecret;
        TheirWriteMacKey = new byte[keysSizes.WriteMacKey];
        OurWriteMacKey = new byte[keysSizes.WriteMacKey];
        TheirWriteKey = new byte[keysSizes.WriteKey];
        OurWriteKey = new byte[keysSizes.WriteKey];
        TheirWriteIV = new byte[keysSizes.WriteIV];
        OurWriteIV = new byte[keysSizes.WriteIV];
    }
}
