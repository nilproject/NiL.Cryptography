namespace NiL.Cryptography.Tls;

public readonly struct KeysSizes
{
    public readonly int WriteMacKey;
    public readonly int WriteKey;
    public readonly int WriteIV;

    public KeysSizes(int writeMacKey, int writeKey, int writeIV)
    {
        WriteMacKey = writeMacKey;
        WriteKey = writeKey;
        WriteIV = writeIV;
    }
}
