using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class PaddingExtension : ITlsExtension<PaddingExtension>
{
    public PaddingExtension(ushort size)
    {
        Size = size;
    }

    public static ExtensionType ExtensionType => ExtensionType.Padding;

    public ushort Size { get; }

    public static PaddingExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        var size = reader.UInt16();
        reader.Skip(size);
        return new PaddingExtension(size);
    }
}
