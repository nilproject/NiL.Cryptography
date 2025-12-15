namespace NiL.Cryptography.Tls;

public struct TlsPlaintext
{
    public TlsContentType ContentType;
    public TlsVersion ProtocolVersion;
    public ushort Length;
    public byte[] Opaque;
}
