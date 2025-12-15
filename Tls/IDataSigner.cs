namespace NiL.Cryptography.Tls;

public interface IDataSigner
{
    byte[] Sign(byte[] data);
}
