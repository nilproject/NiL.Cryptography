namespace NiL.Cryptography.Tls;

public enum TlsContentType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
}
