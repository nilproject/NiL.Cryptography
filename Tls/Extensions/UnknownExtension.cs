using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class UnknownTlsExtension : ITlsExtension<UnknownTlsExtension>
{
    public UnknownTlsExtension(ExtensionType extensionType, ushort size)
    {
        ExtensionTypeId = extensionType;
        Size = size;
    }

    public ExtensionType ExtensionTypeId { get; }

    public static ExtensionType ExtensionType => ExtensionType.Unknown;

    public ushort Size { get; }

    public static UnknownTlsExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        reader.Position -= 2;
        var extensionType = (ExtensionType)reader.UInt16();
        var size = reader.UInt16();
        reader.Skip(size);
        return new UnknownTlsExtension(extensionType, size);
    }

    public override string ToString()
    {
        return nameof(UnknownTlsExtension) + " with type " + ExtensionTypeId;
    }
}
