using System.Text;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class SecureRemotePasswordExtensions : ITlsExtension<SecureRemotePasswordExtensions>
{
    public SecureRemotePasswordExtensions(string data)
    {
        Data = data;
    }

    public string Data { get; }

    public static ExtensionType ExtensionType => ExtensionType.SecureRemotePassword;

    public static SecureRemotePasswordExtensions ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        var dataLen = reader.UInt8();
        var data = reader.Bytes(dataLen);
        var str = Encoding.UTF8.GetString(data);
        return new SecureRemotePasswordExtensions(str);
    }
}
