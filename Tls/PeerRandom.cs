namespace NiL.Cryptography.Tls;

public struct PeerRandom
{
    public byte[] Opaque;

    public PeerRandom(byte[] opaque)
    {
        Opaque = opaque;
    }
}
