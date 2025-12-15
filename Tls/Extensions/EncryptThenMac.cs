using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class EncryptThenMacExtension : ITlsExtension<EncryptThenMacExtension>
{
    public static ExtensionType ExtensionType => ExtensionType.EncryptThenMac;

    public static EncryptThenMacExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        return new EncryptThenMacExtension();
    }
}
