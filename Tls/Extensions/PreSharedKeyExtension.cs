using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

/*public sealed class PreSharedKeyExtension : ITlsExtension<PreSharedKeyExtension>
{
    public PreSharedKeyExtension()
    {
    }

    public static ExtensionType ExtensionType => ExtensionType.PreSharedKey;

    public PskKeyExchangeMode[] Modes { get; }

    public static PreSharedKeyExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();

        if (extensionContext is ExtensionContext.ClientHello)
        {
            // todo
        }
    }
}*/