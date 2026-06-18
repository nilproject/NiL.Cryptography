using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class ExtendedMasterSecret : ITlsExtension<ExtendedMasterSecret>
{
    public static ExtensionType ExtensionType => ExtensionType.ExtendedMasterSecret;

    public static ExtendedMasterSecret ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        return new ExtendedMasterSecret();
    }

    public static void Write(BigEndianWriteBuffer buffer)
    {
        buffer.Uint16((ushort)ExtensionType.ExtendedMasterSecret);
        buffer.Uint16(0);
    }
}
